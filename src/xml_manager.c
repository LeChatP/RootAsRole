/*
 * <xml_manager.c>
 *
 * This file contains the definitions of xml management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __STDC_LIB_EXT1__
#define __STDC_LIB_EXT1__
#endif
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include "xml_manager.h"
#include "command.h"
#include "capabilities.h"

#include <libxml/xpath.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <linux/limits.h>
#include <syslog.h>
#include <stdlib.h>
#include <regex.h>
#include <fnmatch.h>
#include <sys/capability.h>

#ifndef ARG_MAX
#define ARG_MAX 131072
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef REGERROR_BUF_SIZE
#define REGERROR_BUF_SIZE 1024
#endif

#ifndef USER_MAX
#define USER_MAX 1024
#endif

xmlXPathObjectPtr result = NULL;

/**************************************
 * PARTIAL ORDER COMPARISON FUNCTIONS *
 **************************************/

typedef unsigned long long score_t;

/**
 * @brief find actors element of a role
*/
xmlNodePtr find_actors(xmlNodePtr role)
{
	xmlNodePtr actors = role->children;
	while (actors != NULL) {
		if (xmlStrcmp(actors->name, (const xmlChar *)"actors") == 0) {
			return actors;
		}
		actors = actors->next;
	}
	return NULL;
}

/**
 * @brief actor is matching the user criteria
*/
int actor_match_user(xmlNodePtr actor, char *user)
{
	if (!xmlStrcmp(actor->name, (const xmlChar *)"user") &&
	    xmlHasProp(actor, (const xmlChar *)"name")) {
		xmlChar *name = xmlGetProp(actor, (const xmlChar *)"name");
		if (name != NULL) {
			if (!strcmp((char *)name, user)) {
				return 1;
			}
		}
	}
	return 0;
}

int actors_match_user(xmlNodePtr actors, char *user)
{
	xmlNodePtr actor = actors->children;
	while (actor != NULL) {
		if (actor_match_user(actor, user)) {
			return 1;
		}
		actor = actor->next;
	}
	return 0;
}

/**
 * @brief counts the number of group names that match the given groups
 * @param names the comma-separated list of group names
 * @param groups the array of group names to match against
 * @param nb_groups the number of group names in the groups array
 * @param all the number of group names in the names string
 * @return the number of group names that match, 0 if one does not match at all
 */
int count_matching_groups(char *names, char **groups, int nb_groups, int *all)
{
	char *names_str = strdup(names);
	char *token = strtok(names_str, ",");
	int found = 0;
	*all = 0;
	while (token != NULL) {
		for (int j = 0; j < nb_groups; j++) {
			if (!strcmp(token, groups[j])) {
				found += 1;
				break;
			}
		}
		token = strtok(NULL, ",");
		*all += 1;
	}
	free(names_str);
	return found == *all ? found : 0;
}

/**
 * @brief actor is matching the group criteria
 * @return n matching groups
*/
int actor_match_group(xmlNodePtr actor, char **groups, int nb_groups)
{
	if (!xmlStrcmp(actor->name, (const xmlChar *)"group") &&
	    xmlHasProp(actor, (const xmlChar *)"names")) {
		xmlChar *names = xmlGetProp(actor, (const xmlChar *)"names");
		if (names != NULL) {
			char *names_str = (char *)names;
			int all = 0;
			return count_matching_groups(names_str, groups,
						     nb_groups, &all);
		}
	}
	return 0;
}

int actors_match_max_group(xmlNodePtr actors, char **groups, int nb_groups)
{
	xmlNodePtr actor = actors->children;
	int max = 0;
	while (actor != NULL) {
		int n = actor_match_group(actor, groups, nb_groups);
		if (n > max) {
			max = n;
		}
		actor = actor->next;
	}
	return max;
}

int scorecmp(score_t score_A, score_t score_B)
{
	if (score_A > score_B)
		return 1;
	else if (score_A < score_B)
		return -1;
	else
		return 0;
}

int twoscorecmp(score_t user_min_A, score_t cmd_min_A, score_t user_min_B,
		score_t cmd_min_B)
{
	if (user_min_A > user_min_B)
		return 1;
	else if (user_min_A < user_min_B)
		return -1;
	else if (cmd_min_A > cmd_min_B)
		return 1;
	else if (cmd_min_A < cmd_min_B)
		return -1;
	else
		return 0;
}

int threescorecmp(score_t caps_min_A, score_t setuid_min_A,
		  score_t security_min_A, score_t caps_min_B,
		  score_t setuid_min_B, score_t security_min_B)
{
	if (caps_min_A > caps_min_B)
		return 1;
	else if (caps_min_A < caps_min_B)
		return -1;
	else if (setuid_min_A > setuid_min_B)
		return 1;
	else if (setuid_min_A < setuid_min_B)
		return -1;
	else if (security_min_A > security_min_B)
		return 1;
	else if (security_min_A < security_min_B)
		return -1;
	else
		return 0;
}

/**
 * @brief actor is matching the user criteria
 * @param user the user to match
 * @param actors the actors node to match against
 * @return the score of the match (between 1 and MAX), 0 if no match
*/
score_t actors_match(user_t *user, xmlNodePtr actors)
{
	score_t score = 0;
	if (!xmlStrcmp(actors->name, (const xmlChar *)"actors")) {
		if (actors_match_user(actors, user->name)) {
			score = 1;
		} else {
			score_t max = -1;
			score_t n = max -
				    actors_match_max_group(actors, user->groups,
							   user->nb_groups);
			if (n == 0) {
				printf("Unkown error\n");
				return 0;
			} else if (n != max && n > score) {
				score = n;
			}
		}
	}
	return score;
}

#define NO_MATCH 0
#define PATH_STRICT 1
#define PATH_ARG_STRICT 2
#define PATH_STRICT_ARG_WILDCARD 3
#define PATH_WILDCARD 4
#define PATH_WILDCARD_ARG_STRICT 5
#define PATH_ARG_WILDCARD 6
#define PATH_FULL_WILDCARD 7
#define PATH_FULL_WILDCARD_ARG_STRICT 8
#define PATH_FULL_WILDCARD_ARG_WILDCARD 9
#define PATH_ARG_FULL_WILDCARD 10

int path_matches(char *full_path, cmd_t *command)
{
	int path_matches = NO_MATCH;
	if (!strncmp(command->command, full_path, PATH_MAX)) {
		path_matches = PATH_STRICT;
	} else if (!strcmp(full_path, "*")) {
		path_matches = PATH_FULL_WILDCARD;
	} else {
		//check wildcard on path
		if (!fnmatch(full_path, command->command,
			     FNM_PATHNAME | FNM_NOESCAPE | FNM_PERIOD)) {
			path_matches = PATH_WILDCARD;
		}
	}
	return path_matches;
}

int regex_matches(char *args, cmd_t *command, xmlNodePtr command_element,
		  score_t *retval)
{
	args[0] = '^';
	int args_len = strnlen(args, ARG_MAX);
	if (args_len + 1 > ARG_MAX) {
		error(0, 0,
		      "Configuration file malformed, contact administrator or see the logs\n");
		syslog(LOG_ERR, "Regex in line %d is too long\n",
		       command_element->line);
		return 0;
	}
	args[args_len] = '$';
	args_len++;
	args[args_len] = '\0';

	//check regex on args
	regex_t regex;
	int reti = regcomp(&regex, args, REG_EXTENDED);
	if (reti) {
		error(0, 0,
		      "Configuration file malformed, contact administrator or see the logs\n");

		char error_msg[REGERROR_BUF_SIZE];
		*error_msg = (char)'\0';
		regerror(reti, &regex, error_msg, REGERROR_BUF_SIZE);
		syslog(LOG_ERR, "Regex in line %d is malformed : %s\n",
		       command_element->line, error_msg);
		return 0;
	}
	char joined[ARG_MAX];
	int joined_len = 0;
	join_argv(command->argc, command->argv, joined, ARG_MAX, &joined_len);
	reti = regexec(&regex, joined, 0, NULL, 0);
	joined[0] = '\0';
	regfree(&regex);
	if (!reti) {
		switch (*retval) {
		case PATH_STRICT:
			*retval = may_be_regex(args + 1, args_len - 2) ?
					  PATH_STRICT_ARG_WILDCARD :
					  PATH_ARG_STRICT;
			break;
		case PATH_WILDCARD:
			*retval = may_be_regex(args + 1, args_len - 2) ?
					  PATH_ARG_WILDCARD :
					  PATH_WILDCARD_ARG_STRICT;
			break;
		case PATH_FULL_WILDCARD:
			*retval = may_be_regex(args + 1, args_len - 2) ?
					  PATH_FULL_WILDCARD_ARG_WILDCARD :
					  PATH_FULL_WILDCARD_ARG_STRICT;
			break;
		}

		return 1;
	}
	return 0;
}

int check_path_matches(cmd_t *command, xmlNodePtr command_element,
		       char *content, score_t *retval)
{
	char full_path[PATH_MAX];
	char args[ARG_MAX];

	if (!get_abspath_from_cmdline((char *)content, full_path, PATH_MAX,
				      args + 1, ARG_MAX - 2)) {
		return 0;
	}
	if (!strcmp(content, "**")) {
		*retval = PATH_ARG_FULL_WILDCARD;
		return 1;
	}
	*retval = path_matches(full_path, command);
	if (*retval && args[1] != '\0') {
		//path matches and args are not empty
		int ret = regex_matches(args, command, command_element, retval);
		if (!ret) {
			*retval = NO_MATCH;
		}
	} else if (args[1] == '\0' && command->argc > 1) {
		*retval = NO_MATCH;
	}
	return *retval != NO_MATCH;
}

/**
 * @brief check if the user input command match the command xml element
 * @param input_command the user input command
 * @param command_element the <command> xml element
 * @return non-zero if the command match, 0 otherwise
*/
score_t command_match(cmd_t *command, xmlNodePtr command_element)
{
	score_t retval = NO_MATCH;
	if (!xmlStrcmp(command_element->name, (const xmlChar *)"command")) {
		xmlChar *content = xmlNodeGetContent(command_element);
		size_t content_len = xmlStrlen(content);
		if (content != NULL && content_len > 0) {
			if (!check_path_matches(command, command_element,
						(char *)content, &retval)) {
				retval = NO_MATCH;
			}
		}
		xmlFree(content);
	}

	return retval;
}

int contains_root(xmlChar *comma_string)
{
	char *dup = strdup((char *)comma_string);
	char *element = strtok((char *)dup, ",");
	while (element != NULL &&
	       (!strcasecmp(element, "root") || !strcmp(element, "0"))) {
		element = strtok(NULL, ",");
	}
	free(dup);
	return element == NULL ? 0 : 1;
}

#define NO_CAPS 1
#define CAPS_NO_ADMIN 2
#define CAPS_ADMIN 3
#define CAPS_ALL 4

#define NO_SETUID_NO_SETGID 1
#define SETGID 2
#define SETUID 3
#define SETUID_SETGID 4
#define SETGID_ROOT 5
#define SETUID_NOTROOT_SETGID_ROOT 6
#define SETUID_ROOT 7
#define SETUID_ROOT_SETGID 8
#define SETUID_SETGID_ROOT 9

score_t get_caps_min(const xmlNodePtr task_element)
{
	score_t caps_min = NO_CAPS;
	if (xmlHasProp(task_element, (const xmlChar *)"capabilities")) {
		xmlChar *capabilities = xmlGetProp(
			task_element, (const xmlChar *)"capabilities");
		if (capabilities != NULL && xmlStrlen(capabilities) > 0) {
			if (xmlStrcasestr(capabilities,
					  (const xmlChar *)"ALL") != NULL) {
				caps_min = CAPS_ALL;
			} else if (xmlStrcasestr(capabilities,
						 (const xmlChar *)"ADMIN") !=
				   NULL) {
				caps_min = CAPS_ADMIN;
			} else {
				caps_min = CAPS_NO_ADMIN;
			}
		}
	}
	return caps_min;
}

score_t setuser_min(const xmlNodePtr task_element, const settings_t *settings)
{
	score_t setuid_min = NO_SETUID_NO_SETGID;
	xmlChar *setuid = xmlGetProp(task_element, (const xmlChar *)"setuser");
	if (setuid != NULL && xmlStrlen(setuid) > 0) {
		if (!settings->no_root &&
		    xmlStrcmp(setuid, (const xmlChar *)"root") == 0) {
			setuid_min = SETUID_ROOT;
		} else {
			setuid_min = SETUID;
		}
	}
	xmlFree(setuid);
	return setuid_min;
}

score_t setgid_min(const xmlNodePtr task_element, const settings_t *settings,
		   score_t setuid_min)
{
	score_t setgid_min = NO_SETUID_NO_SETGID;
	xmlChar *setgid =
		xmlGetProp(task_element, (const xmlChar *)"setgroups");
	if (setgid != NULL && xmlStrlen(setgid) > 0) {
		switch (setuid_min) {
		case SETUID_ROOT:
			if (!settings->no_root && contains_root(setgid)) {
				setgid_min = SETUID_SETGID_ROOT;
			} else {
				setgid_min = SETUID_ROOT_SETGID;
			}
			break;
		case SETUID:
			if (!settings->no_root && contains_root(setgid)) {
				setgid_min = SETUID_NOTROOT_SETGID_ROOT;
			} else {
				setgid_min = SETUID_SETGID;
			}
			break;
		default: // no_setuid
			if (!settings->no_root && contains_root(setgid)) {
				setgid_min = SETGID_ROOT;
			} else {
				setgid_min = SETGID;
			}
			break;
		}
	}
	xmlFree(setgid);
	return setgid_min;
}

score_t get_setuid_min(const xmlNodePtr task_element,
		       const settings_t *settings)
{
	score_t setuid_min = NO_SETUID_NO_SETGID;
	if (xmlHasProp(task_element, (const xmlChar *)"setuser")) {
		setuid_min = setuser_min(task_element, settings);
	}
	if (xmlHasProp(task_element, (const xmlChar *)"setgroups")) {
		setuid_min = setgid_min(task_element, settings, setuid_min);
	}
	return setuid_min;
}

/**
 * @brief check if the command matches the task element
 * @param cmd the command to check
 * @param task_element the task element to check
 * @param cmd_min the minimum command level that matched
 * @param caps_min the capabilities level of the task
 * @return 1 if any match, or 0 if no match
*/
int task_match(cmd_t *cmd, const xmlNodePtr task_element, settings_t *settings,
	       score_t *cmd_min, score_t *caps_min, score_t *setuid_min)
{
	*setuid_min = *caps_min = *cmd_min = -1;
	if (!xmlStrcmp(task_element->name, (const xmlChar *)"task")) {
		get_options_from_config(task_element, settings);
		xmlNodePtr command_element = task_element->children;

		while (command_element != NULL) {
			score_t match = command_match(cmd, command_element);
			if (match) {
				*cmd_min = match < *cmd_min ? match : *cmd_min;
			}

			command_element = command_element->next;
		}
		if (*cmd_min > 0) {
			*caps_min = get_caps_min(task_element);
			*setuid_min = get_setuid_min(task_element, settings);
		}
	}
	return *cmd_min < (score_t)-1 ? 1 : 0;
}

#define NO_ROOT_WITH_BOUNDING 1
#define ENABLE_ROOT 2
#define DISABLE_BOUNDING 3
#define ENABLE_ROOT_DISABLE_BOUNDING 4

int set_task_min(cmd_t *cmd, const xmlNodePtr role_sub_element,
		 xmlNodePtr *task_min, settings_t *settings, score_t *cmd_min,
		 score_t *caps_min, score_t *setuid_min, score_t *security_min)
{
	int ret = -1;
	score_t task_cmd = -1, task_caps = -1, task_setuid = -1;
	if (task_match(cmd, role_sub_element, settings, &task_cmd, &task_caps,
		       &task_setuid)) {
		int cmp = threescorecmp(task_cmd, task_caps, task_setuid,
					*cmd_min, *caps_min, *setuid_min);
		if (cmp < 0) {
			*cmd_min = task_cmd;
			*caps_min = task_caps;
			*setuid_min = task_setuid;
			*task_min = role_sub_element;
			if (!settings->no_root && !settings->bounding)
				*security_min = ENABLE_ROOT_DISABLE_BOUNDING;
			else if (!settings->no_root)
				*security_min = ENABLE_ROOT;
			else if (!settings->bounding)
				*security_min = DISABLE_BOUNDING;
			else
				*security_min = NO_ROOT_WITH_BOUNDING;
			ret = 1;
		} else if (*cmd_min != (score_t)-1 && cmp == 0) {
			xmlChar *role_name = xmlGetProp(
				role_sub_element, (const xmlChar *)"name");
			syslog(LOG_WARNING, "Duplicate task in role %s",
			       role_name);
			xmlFree(role_name);
			ret = 0;
		}
	}
	return ret;
}

int role_match(const xmlNodePtr role_element, user_t *user, cmd_t *cmd,
	       xmlNodePtr *task_min, settings_t *settings, score_t *user_min,
	       score_t *cmd_min, score_t *caps_min, score_t *setuid_min,
	       score_t *security_min)
{
	if (!xmlStrcmp(role_element->name, (const xmlChar *)"role")) {
		xmlNode *role_sub_element = role_element->children;
		*user_min = *cmd_min = *caps_min = *setuid_min = *security_min =
			-1;
		xmlNodePtr actors_block = find_actors(role_element);
		int matches = 0;
		if (actors_block != NULL) {
			*user_min = actors_match(user, actors_block);
			while (role_sub_element != NULL) {
				int ret =
					set_task_min(cmd, role_sub_element,
						     task_min, settings,
						     cmd_min, caps_min,
						     setuid_min, security_min);
				if (ret == 1)
					matches = 1;
				role_sub_element = role_sub_element->next;
			}
		}
		if (matches)
			return 1;
	}
	return 0;
}

void min_partial_order_role(xmlNodePtr role_element, user_t *user, cmd_t *cmd,
			    score_t *user_min, score_t *cmd_min,
			    score_t *caps_min, score_t *setuid_min,
			    score_t *security_min, xmlNodePtr *matched_role,
			    xmlNodePtr *matched_task,
			    settings_t *matched_settings, int *n_roles)
{
	xmlNodePtr tmp_task_element = NULL;
	settings_t tmp_settings;
	set_default_options(&tmp_settings);
	score_t tmp_user_min = -1, tmp_cmd_min = -1, tmp_caps_min = -1,
		tmp_setuid_min = -1, tmp_security_min = -1;
	if (role_match(role_element, user, cmd, &tmp_task_element, &tmp_settings,
		       &tmp_user_min, &tmp_cmd_min, &tmp_caps_min,
		       &tmp_setuid_min, &tmp_security_min)) {
		int precision = twoscorecmp(tmp_user_min, tmp_cmd_min,
					    *user_min, *cmd_min);
		int leastprivilege = threescorecmp(tmp_caps_min, tmp_setuid_min,
						   tmp_security_min, *caps_min,
						   *setuid_min, *security_min);
		if (precision < 0 || (precision == 0 && leastprivilege < 0)) {
			*user_min = tmp_user_min;
			*cmd_min = tmp_cmd_min;
			*caps_min = tmp_caps_min;
			*setuid_min = tmp_setuid_min;
			*security_min = tmp_security_min;
			*matched_role = role_element;
			*matched_task = tmp_task_element;
			options_assign(matched_settings, &tmp_settings);
			*n_roles = 1;
		} else if (precision == 0 && leastprivilege == 0) {
			(*n_roles)++;
		}
	}
}

/**
 * @brief get the most precise and least privileged role for a command
 * @param user the user to match
 * @param cmd the command to match
 * @param roles_element the roles that can be matched
 * @param matched_role the matched role
 * @param matched_task the matched task
 * @param matched_settings the associated settings to the matched task
 * @return n roles found
 * 
*/
int find_partial_order_role(xmlNodeSetPtr roles_element, user_t *user,
			    cmd_t *cmd, xmlNodePtr *matched_role,
			    xmlNodePtr *matched_task, settings_t *matched_settings)
{
	score_t user_min = -1, cmd_min = -1, caps_min = -1, setuid_min = -1,
		security_min = -1;
	int n_roles = 0;
	for (int i = 0; i < roles_element->nodeNr; i++) {
		xmlNodePtr role_element = roles_element->nodeTab[i];
		min_partial_order_role(role_element, user, cmd, &user_min,
				       &cmd_min, &caps_min, &setuid_min,
				       &security_min, matched_role,
				       matched_task, matched_settings,
				       &n_roles);
	}
	return n_roles;
}

/*******************************************
 ***            FIND ROLES               ***
********************************************/

/**
 * @brief sanitize string with concat xpath function
 * @param str the string to sanitize
 * @return the sanitized string, or NULL on error, to free at end of usage
*/
char *sanitize_quotes_xpath(const char *p_str, size_t p_strlen)
{
	char *split = "',\"'\",'";
	char *str = (char *)p_str;
	size_t tot = p_strlen * 8 + 1;
	char *tmp = malloc(tot);
	if (tmp == NULL) {
		return NULL;
	}
	tmp[0] = '\0';
	char *saveptr = NULL;
	char *tok = strtok_r(str, "'", &saveptr);
	size_t tok_len = tok - str;
	tmp = strncat(tmp, tok, tok_len);
	tok = strtok_r(NULL, "'", &saveptr);
	while (tok != NULL) {
		tok_len = tok - str - tok_len;
		tmp = strncat(tmp, split, 8);
		tmp = strncat(tmp, tok, tok_len);
		tok = strtok_r(NULL, "'", &saveptr);
	}
	char *ret = malloc(tot + 11);
	if (ret == NULL) {
		free(tmp);
		return NULL;
	}
	if (strchr(str, '\'') != NULL)
		snprintf(ret, tot + 11, "concat('%s')", tmp);
	else
		snprintf(ret, tot + 2, "'%s'", str);
	printf("ret: %s\n", ret);
	free(tmp);
	return ret;
}

/**
 * @brief return the xpath expression to find a role by name
 * @param role the role name
 * @return the xpath expression, or NULL on error, to free at end of usage
*/
xmlChar *expr_search_role_by_name(char *role)
{
	int err;
	int size = 0;
	xmlChar *expression = NULL;

	size = 20 + (int)strlen(role);

	expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
	if (!expression) {
		fputs("Error malloc\n", stderr);
		goto ret_err;
	}

	err = xmlStrPrintf(expression, size, "//role[@name='%s'][1]", role);
	if (err == -1) {
		fputs("Error xmlStrPrintf()\n", stderr);
		free(expression);
		return NULL;
	}

ret_err:
	return expression;
}

/**
 * @brief return the xpath expression to find a role by command
 * @param command the command name
 * @return the xpath expression, or NULL on error, to free at end of usage
*/
int __expr_user_or_groups(xmlChar **expr, char *user, char **groups,
			  int nb_groups)
{
	char *expr_format = "actors/user[@name='%s'] or actors/group[%s]";
	int size = 40 + (int)strnlen(user, USER_MAX);
	xmlChar *groups_str = (xmlChar *)xmlMalloc(
		(nb_groups * (27 + USER_MAX)) * sizeof(xmlChar));
	if (!groups_str) {
		fputs("Error malloc\n", stderr);
		return -1;
	}
	xmlChar *str_ptr = groups_str;
	for (int i = 0; i < nb_groups; i++) {
		int contains_size = (int)strnlen(groups[i], USER_MAX) + 21;
		int err = -1;
		if (i == 0) {
			err = xmlStrPrintf(str_ptr, contains_size,
					   "contains(@names, '%s')", groups[i]);
		} else {
			contains_size = contains_size + 4;
			err = xmlStrPrintf(str_ptr, contains_size,
					   " or contains(@names, '%s')",
					   groups[i]);
		}
		if (err == -1) {
			fputs("Error xmlStrPrintf()\n", stderr);
			free(groups_str);
			return err;
		}
		str_ptr += contains_size - 1;
		size += contains_size;
	}
	*expr = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
	int ret = xmlStrPrintf(*expr, size, expr_format, user, groups_str);
	free(groups_str);
	return ret + 1;
}

/**
 * @brief return the xpath expression to find a role by username or group combined with a command
 * @param user the username
 * @param groups the groups
 * @param nb_groups the number of groups
 * @param command the command name
 * @return the xpath expression, or NULL on error, to free at end of usage
*/
xmlChar *expr_search_role_by_usergroup_command(user_t *user, cmd_t *command)
{
	int err;
	int size = 0;
	xmlChar *expression = NULL;
	xmlChar *user_groups_char = NULL;
	char str_cmd[PATH_MAX + ARG_MAX + 1];
	*str_cmd = '\0';
	int cmd_len = 0;
	int res = join_cmd(command, str_cmd, PATH_MAX + ARG_MAX + 1, &cmd_len);
	if (res == -1) {
		return NULL;
	}
	printf("str_cmd: %s\n", str_cmd);
	char *sanitized_str =
		sanitize_quotes_xpath(str_cmd, PATH_MAX + ARG_MAX + 1);
	if (sanitized_str == NULL) {
		return NULL;
	}
	printf("sanitized_str: %s\n", sanitized_str);
	int user_groups_size = __expr_user_or_groups(
		&user_groups_char, user->name, user->groups, user->nb_groups);
	if (user_groups_size == -1) {
		free(sanitized_str);
		return NULL;
	}
	size = 136 + PATH_MAX + ARG_MAX + 1 + user_groups_size;

	expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
	if (!expression) {
		fputs("Error malloc\n", stderr);
		goto ret_err;
	}

	// //role[(actors/user[@name='lechatp'] or actors/group[contains(@names,'lechatp') or contains(@names,'group1')]) and (task/command[text()='%s'] or task[string-length(translate(text(),'.+*?^$()[]{}|\\\\','')) < string-length(text())])]
	err = xmlStrPrintf(
		expression, size,
		"//role[(%s) and (task/command[text()=%s] or task/command[string-length(translate(text(),'.+*?^$()[]{}|\\\\','')) < string-length(text())])]",
		user_groups_char, sanitized_str);
	if (err == -1) {
		fputs("Error xmlStrPrintf()\n", stderr);
		xmlFree(expression);
	}

ret_err:
	free(sanitized_str);
	xmlFree(user_groups_char);
	return expression;
}

/**
 * @brief return the xpath result of a expression
 * @param expression the xpath expression
 * @param doc the xml document
 * @param node the xml node where to start the search
 * @return the xpath result, or NULL on error, free "result" global variable at end of usage
*/
xmlNodeSetPtr find_with_xpath(xmlChar *expression, xmlDocPtr doc,
			      xmlNodePtr node)
{
	xmlXPathContextPtr context = NULL;
	xmlNodeSetPtr nodeset = NULL;

	context = xmlXPathNewContext(doc);
	if (node != NULL) {
		context->node = node;
	}
	if (context == NULL) {
		fputs("Error in xmlXPathNewContext\n", stderr);
		goto ret_err;
	}
	if (result != NULL) {
		xmlXPathFreeObject(result);
	}
	result = xmlXPathEvalExpression(expression, context);
	if (result == NULL) {
		fputs("Error in xmlXPathEvalExpression\n", stderr);
		printf("expression: %s\n", expression);
		goto ret_err;
	}

	if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
		goto ret_err;
	}

	nodeset = result->nodesetval;

ret_err:
	if (context != NULL) {
		xmlXPathFreeContext(context);
	}
	return nodeset;
}

/**
 * @brief remove roles if group combination is not matching the executor
 * @param set the xpath result
 * @param groups the groups
 * @param nb_groups the number of groups
 * @return the xpath result, or NULL on error, free "result" global variable at end of usage
*/
xmlNodeSetPtr filter_wrong_groups_roles(xmlNodeSetPtr set, char **groups,
					int nb_groups)
{
	for (int i = 0; i < set->nodeNr; i++) {
		xmlNodePtr node = set->nodeTab[i];
		xmlNodePtr group = find_actors(node);
		while (group != NULL) {
			if (xmlStrcmp(group->name, (const xmlChar *)"group") ==
			    0) {
				xmlChar *names = xmlGetProp(
					group, (const xmlChar *)"names");
				if (names != NULL) {
					int all = 0;
					int found = count_matching_groups(
						(char *)names, groups,
						nb_groups, &all);
					if (found == 0 || found != all) {
						xmlUnlinkNode(node);
						xmlFreeNode(node);
						if (i < set->nodeNr - 1) {
							set->nodeTab[i] =
								set->nodeTab[i +
									     1];
						} else {
							set->nodeTab[i] = NULL;
						}
						set->nodeNr--;
						break;
					}
				}
			}
			group = group->next;
		}
	}
	return set;
}

xmlNodeSetPtr filter_wrong_commands_roles(xmlNodeSetPtr set, cmd_t *command)
{
	for (int i = 0; i < set->nodeNr; i++) {
		xmlNodePtr node = set->nodeTab[i];
		xmlNodePtr task = node->children;
		while (task != NULL) {
			if (!xmlStrcmp(task->name, (const xmlChar *)"task")) {
				xmlNodePtr command_node = task->children;
				score_t found = NO_MATCH;
				while (command_node != NULL) {
					if (!xmlStrcmp(command_node->name,
						       (const xmlChar
								*)"command")) {
						found = command_match(
							command, command_node);
						if (found != NO_MATCH) {
							break;
						}
					}
					command_node = command_node->next;
				}
				if (found == NO_MATCH) {
					xmlUnlinkNode(node);
					xmlFreeNode(node);
					if (i < set->nodeNr - 1) {
						set->nodeTab[i] =
							set->nodeTab[i + 1];
					} else {
						set->nodeTab[i] = NULL;
					}
					set->nodeNr--;
					break;
				}
			}
			task = task->next;
		}
	}
	return set;
}

/**
 * @brief find all roles matching the user or groups and command
 * @param doc the xml document
 * @param user the username
 * @param groups the groups
 * @param nb_groups the number of groups
 * @param command the command name
 * @return every roles that match the user or groups and command (regex or not)
*/
xmlNodeSetPtr find_role_by_usergroup_command(xmlDocPtr doc, user_t *user,
					     cmd_t *cmd)
{
	xmlChar *expression = NULL;
	xmlNodeSetPtr nodeset = NULL;
	expression = expr_search_role_by_usergroup_command(user, cmd);
	if (!expression) {
		fputs("Error expr_search_role_by_usergroup_command()\n",
		      stderr);
		goto ret_err;
	}
	nodeset = find_with_xpath(expression, doc, NULL);
	if (!nodeset) {
		fputs("Error find_with_xpath()\n", stderr);
		goto ret_err;
	}
	nodeset = filter_wrong_groups_roles(nodeset, user->groups,
					    user->nb_groups);
	if (!nodeset) {
		fputs("Error filter_wrong_groups_roles()\n", stderr);
		goto ret_err;
	}
	nodeset = filter_wrong_commands_roles(nodeset, cmd);
	if (!nodeset) {
		fputs("Error filter_wrong_commands_roles()\n", stderr);
		goto ret_err;
	}
ret_err:
	xmlFree(expression);
	return nodeset;
}

/**
 * @brief create expression to find all task containing the given command in a role
 * @param command command to search
 * @return expression like .//task[command/text() = 'thecommand')]
*/
xmlChar *expr_search_command_block_from_role(char *command, size_t command_len)
{
	xmlChar *expr = NULL;
	char *sanitized_command = sanitize_quotes_xpath(command, command_len);
	if (sanitized_command == NULL) {
		return NULL;
	}
	char *command_block = ".//task[command/text() = %s]";
	int len = 27 + command_len + 1;
	expr = (xmlChar *)malloc(len);
	if (expr == NULL) {
		return NULL;
	}
	xmlStrPrintf(expr, len, command_block, sanitized_command);
	free(sanitized_command);
	return expr;
}

/**
 * @brief find task blocks which are empty on the role with xpath
 * @param role_node the role node
 * @return the task node, or NULL on error or if no empty task block
*/
xmlNodeSetPtr find_wildcard_task_block_from_role(xmlNodePtr role_node)
{
	xmlChar *expression = (xmlChar *)"./task[contains(command, '*')]";
	if (!expression) {
		fputs("Error expr_search_command_block_from_role()\n", stderr);
		return NULL;
	}
	xmlNodeSetPtr nodeset =
		find_with_xpath(expression, role_node->doc, role_node);
	if (nodeset == NULL || nodeset->nodeNr == 0) {
		return NULL;
	}
	return nodeset;
}

/**
 * @brief find the role node matching the parameters, filter 
*/
int get_settings(xmlNodePtr role_node, xmlNodePtr task_node,
		 settings_t *options)
{
	int res = 1;
	options->role = (char *)xmlStrdup(
		xmlGetProp(role_node, (const xmlChar *)"name"));
	if (xmlHasProp(task_node, (const xmlChar *)"setuser")) {
		xmlChar *prop =
			xmlGetProp(task_node, (const xmlChar *)"setuser");
		options->setuid = (char *)xmlStrdup(prop);
		xmlFree(prop);
	} else {
		options->setuid = NULL;
	}
	if (xmlHasProp(task_node, (const xmlChar *)"setgroups")) {
		xmlChar *prop =
			xmlGetProp(task_node, (const xmlChar *)"setgroups");
		options->setgid = (char *)xmlStrdup(prop);
		xmlFree(prop);
	} else {
		options->setgid = NULL;
	}
	if (xmlHasProp(task_node, (const xmlChar *)"capabilities")) {
		xmlChar *capabilities =
			xmlGetProp(task_node, (const xmlChar *)"capabilities");
		if (xmlStrcasecmp(capabilities, (const xmlChar *)"all") == 0) {
			*capabilities = '\0';
			xmlChar *s_capabilities =
				xmlMalloc(xmlStrlen(capabilities) + 5);
			xmlStrPrintf(s_capabilities,
				     xmlStrlen(capabilities) + 3, "%s=i",
				     capabilities);
			xmlFree(capabilities);
			capabilities = s_capabilities;
		} else if (xmlStrlen(capabilities) != 0) {
			xmlChar *s_capabilities =
				xmlMalloc(xmlStrlen(capabilities) + 5);
			xmlStrPrintf(s_capabilities,
				     xmlStrlen(capabilities) + 3, "%s=i",
				     capabilities);
			xmlFree(capabilities);
			capabilities = s_capabilities;
		}
		

		cap_t eff = cap_from_text((char *)capabilities);
		cap_iab_fill(options->iab, CAP_IAB_AMB, eff, CAP_INHERITABLE);
		get_options_from_config(task_node, options);
		if (options->bounding) {
			cap_iab_fill(options->iab, CAP_IAB_BOUND, eff,
				     CAP_INHERITABLE);
		}
		drop_iab_from_current_bounding(&options->iab);
		cap_free(eff);
		xmlFree(capabilities);
	} else {
		cap_t eff = cap_get_proc();
		if (options->bounding) {
			cap_iab_fill(options->iab, CAP_IAB_BOUND, eff,
				     CAP_PERMITTED);
			drop_iab_from_current_bounding(&options->iab);
		}
	}
	if (!res)
		fprintf(stderr,
			"There is a problem with the configuration file, contact administrator or read logs\n");

	xmlXPathFreeObject(result);
	return res;
}

int find_role_by_name(xmlNodeSetPtr set, char *role_name, xmlNodePtr *role_node)
{
	int res = 0;
	for (int i = 0; i < set->nodeNr; i++) {
		xmlNodePtr t_node = set->nodeTab[i];
		xmlChar *name = xmlGetProp(t_node, (const xmlChar *)"name");

		if (xmlStrcasecmp(name, (const xmlChar *)role_name) == 0) {
			*role_node = t_node;
			res = 1;
			xmlFree(name);
		}
		xmlFree(name);
	}
	return res;
}

/**
 * @brief retrieve all execution settings from xml document matching user, groups and command 
 * @param doc the document
 * @param user the user
 * @param nb_groups the number of groups
 * @param groups the groups
 * @param command the command
 * @return execution setting in global variables, 1 on success, or 0 on error
*/
int get_settings_from_doc_by_role(char *role, xmlDocPtr doc, user_t *user,
				  cmd_t *cmd, settings_t *settings)
{
	int res = 0;
	xmlNodeSetPtr set = find_role_by_usergroup_command(doc, user, cmd);
	if (set == NULL) {
		return res;
	}
	xmlNodePtr role_node = NULL;
	int tresult = find_role_by_name(set, role, &role_node);
	if (!tresult) {
		xmlXPathFreeNodeSet(set);
		return res;
	}
	xmlNodePtr task_node = NULL;

	return get_settings(role_node, task_node, settings);
}

/**
 * @brief load xml file and validate it
 * @param xml_file the xml file
 * @return the document, or NULL on error
*/
xmlDocPtr load_xml(char *xml_file)
{
	xmlParserCtxtPtr ctxt;
	xmlDocPtr doc;

	ctxt = xmlNewParserCtxt();
	if (!ctxt) {
		fputs("Failed to allocate parser context\n", stderr);
		return NULL;
	}
	dac_read_effective(1);
	doc = xmlCtxtReadFile(ctxt, xml_file, NULL,
			      XML_PARSE_DTDVALID | XML_PARSE_NOBLANKS);
	dac_read_effective(0);
	if (!doc) {
		fprintf(stderr, "Failed to parse %s\n", XML_FILE);
		goto ret_err;
	}
	if (!ctxt->valid) {
		fprintf(stderr, "Failed to validate %s\n", XML_FILE);
		xmlFreeDoc(doc);
		goto ret_err;
	}

	xmlFreeParserCtxt(ctxt);

	return doc;

ret_err:
	xmlFreeParserCtxt(ctxt);
	return NULL;
}

/**
 * @brief retrieve all execution settings from xml document matching user, groups and command 
 * @param doc the document
 * @param user the user
 * @param nb_groups the number of groups
 * @param groups the groups
 * @param command the command
 * @return execution setting in global variables, 1 on success, or 0 on error
*/
int get_settings_from_doc_by_partial_order(xmlDocPtr doc, user_t *user,
					   cmd_t *cmd, settings_t *options)
{
	int res = 0;
	xmlNodeSetPtr set = find_role_by_usergroup_command(doc, user, cmd);
	if (set == NULL) {
		return res;
	}
	xmlNodePtr role_node = NULL;
	xmlNodePtr task_node = NULL;

	int nb_colliding = find_partial_order_role(set, user, cmd, &role_node,
						   &task_node, options);
	if (nb_colliding == 0) {
		return res;
	} else if (nb_colliding == 1) {
		return get_settings(role_node, task_node, options);
	} else {
		error(0, 0,
		      "Multiple roles matchs this command, please specify a role.");
		return res;
	}
}

/**
 * @brief load the xml file and retrieve capabilities matching the criterions
 * @param user the user
 * @param nb_groups the number of groups
 * @param groups the groups
 * @param command the command
 * @param p_iab the capabilities
 * @param p_options the options
 * @return 1 on success, or 0 on error
 * @note the capabilities and options are stored in global variables
*/
int get_settings_from_config(user_t *user, cmd_t *command,
			     settings_t *p_options)
{
	xmlDocPtr doc;
	doc = load_xml(XML_FILE);
	if (!doc)
		return 0;
	int res = get_settings_from_doc_by_partial_order(doc, user, command,
							 p_options);
	
	xmlFreeDoc(doc);
	return res;
}

int get_settings_from_config_role(char *role, user_t *user, cmd_t *cmd, settings_t *p_options)
{
	xmlDocPtr doc;
	doc = load_xml(XML_FILE);
	if (!doc)
		return 0;
	int res =
		get_settings_from_doc_by_role(role, doc, user, cmd, p_options);
	xmlFreeDoc(doc);
	return res;
}

/**
 * @brief retrieve the role node from the document matching the role name
 * @param doc the document
 * @param role the role name
 * @return the role node, or NULL on error or if no role found
*/
xmlNodePtr get_role_node(xmlDocPtr doc, char *role)
{
	xmlNodePtr node = xmlDocGetRootElement(doc);
	xmlChar *expression = expr_search_role_by_name(role);
	if (!expression) {
		fputs("Error expr_search_role()\n", stderr);
		return NULL;
	}
	xmlNodeSetPtr nodeset = find_with_xpath(expression, doc, node);
	if (nodeset == NULL || nodeset->nodeNr == 0) {
		return NULL;
	}
	xmlFree(expression);
	return nodeset->nodeTab[0];
}

/**
 * @brief xpath expression if user has access to the role
 * @param role the role name
 * @param user the user
 * @param nb_groups the number of groups
 * @param groups the groups
 * @return the expression, or NULL on error
*/
xmlChar *expr_has_access(char *role, char *user, int nb_groups, char **groups)
{
	int err = -1;
	int size = 0;
	xmlChar *expression = NULL;
	xmlChar *user_groups_char = NULL;
	int user_groups_size = __expr_user_or_groups(&user_groups_char, user,
						     groups, nb_groups);
	size = strlen(role) + 24 + user_groups_size;

	expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
	if (!expression) {
		fputs("Error malloc\n", stderr);
		goto ret_err;
	}

	err = xmlStrPrintf(expression, size, "//role[@name='%s' and (%s)]",
			   role, user_groups_char);
	if (err == -1) {
		fputs("Error xmlStrPrintf()\n", stderr);
		xmlFree(expression);
	}

ret_err:
	xmlFree(user_groups_char);
	return expression;
}
/**
 * @brief obtain role if user has access to the role
 * @param doc the document
 * @param role the role name
 * @param user the user
 * @param nb_groups the number of groups
 * @param groups the groups
 * @return the role node, or NULL on error or if user has no access
 * @note unused
*/
xmlNodePtr get_role_if_access(xmlDocPtr doc, char *role, char *user,
			      int nb_groups, char **groups)
{
	xmlChar *expression = expr_has_access(role, user, nb_groups, groups);
	if (!expression) {
		fputs("Error expr_search_role()\n", stderr);
		return NULL;
	}
	xmlNodeSetPtr nodeset = find_with_xpath(expression, doc, NULL);
	if (nodeset == NULL || nodeset->nodeNr == 0) {
		return NULL;
	}
	return nodeset->nodeTab[0];
}

/************************************************************************
 ***                        PRINT FUNCTIONS                           ***
*************************************************************************/

/**
 * @brief duplicate a node set
 * @param cur the node set
 * @return the duplicated node set, or NULL on error, to be freed with xmlFreeNodeSet()
*/
xmlNodeSetPtr xmlNodeSetDup(xmlNodeSetPtr cur)
{
	xmlNodeSetPtr ret = malloc(sizeof(xmlNodeSet));
	int i;
	ret->nodeNr = cur->nodeNr;
	ret->nodeMax = cur->nodeMax;
	ret->nodeTab = malloc(sizeof(xmlNodePtr) * cur->nodeNr);
	for (i = 0; i < cur->nodeNr; i++) {
		ret->nodeTab[i] = cur->nodeTab[i];
	}
	return ret;
}

/**
 * @brief expression to search all roles matching the user
 * @param user the user
 * @param nb_groups the number of groups
 * @param groups the groups
 * @return the expression, or NULL on error
*/
xmlChar *expr_search_access_roles(user_t *user)
{
	int err;
	int size = 0;
	xmlChar *expression = NULL;
	xmlChar *user_groups_char = NULL;
	int user_groups_size = __expr_user_or_groups(
		&user_groups_char, user->name, user->groups, user->nb_groups);
	size = 24 + user_groups_size;

	expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
	if (!expression) {
		fputs("Error malloc\n", stderr);
		goto ret_err;
	}

	// //role[user[@name='lechatp'] or group[contains(@names,'lechatp') or contains(@names,'group1')]]
	err = xmlStrPrintf(expression, size, "//role[%s]", user_groups_char);
	if (err == -1) {
		fputs("Error xmlStrPrintf()\n", stderr);
	}

ret_err:
	xmlFree(user_groups_char);
	return expression;
}

/**
 * @brief obtain all roles matching the user
 * @param doc the document
 * @param user the user
 * @param nb_groups the number of groups
 * @param groups the groups
 * @return the node set, or NULL on error, to be freed with xmlFreeNodeSet()
*/
xmlNodeSetPtr get_right_roles(xmlDocPtr doc, user_t *user)
{
	xmlNodeSetPtr filtered = NULL;
	xmlChar *expression = expr_search_access_roles(user);
	if (!expression) {
		fputs("Error expr_search_role()\n", stderr);
		goto free_error;
	}
	xmlNodeSetPtr nodeset = find_with_xpath(expression, doc, NULL);
	if (nodeset == NULL || nodeset->nodeNr == 0) {
		goto free_error;
	}
	filtered = filter_wrong_groups_roles(nodeset, user->groups,
					     user->nb_groups);
	if (filtered == NULL) {
		goto free_error;
	}
free_error:
	if (expression != NULL)
		xmlFree(expression);
	return filtered;
}

/**
 * @brief expression to get all elements matching their name (user, group, task)
 * @param element the element name
 * @return the expression, or NULL on error
*/
xmlChar *expr_search_element_in_role(char *element)
{
	int err;
	int size = 0;
	xmlChar *expression = NULL;
	size = strlen(element) + 4;

	expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
	if (!expression) {
		fputs("Error malloc\n", stderr);
		goto ret_err;
	}

	// //task
	err = xmlStrPrintf(expression, size, ".//%s", element);
	if (err == -1) {
		fputs("Error xmlStrPrintf()\n", stderr);
		xmlFree(expression);
	}

ret_err:
	return expression;
}

/**
 * @brief search all elements matching their name (user, group, task) in a role
 * @param role the role node
 * @param element the element name
 * @return the node set, or NULL on error, to be freed with xmlFreeNodeSet()
*/
xmlNodeSetPtr search_element_in_role(xmlNodePtr role, char *element)
{
	xmlNodeSetPtr nodeset = NULL;
	xmlChar *expression = expr_search_element_in_role(element);
	if (!expression) {
		fputs("Error expr_search_element_in_role()\n", stderr);
		goto ret_err;
	}
	nodeset = find_with_xpath(expression, role->doc, role);
	if (nodeset == NULL || nodeset->nodeNr == 0) {
		nodeset = NULL;
		goto ret_err;
	}
ret_err:
	if (expression != NULL)
		xmlFree(expression);
	return nodeset;
}

/**
 * @brief print all task in the node set
 * @param nodeset the node set containing the task
 * @param restricted if the verbose need to be restricted
 * @return 0 on success, -1 on error
*/
void print_task(xmlNodeSetPtr nodeset, int restricted)
{
	char *vertical = "│  ";
	char *element = "├─ ";
	char *end = "└─ ";
	char *space = "   ";

	for (int i = 0; i < nodeset->nodeNr; i++) {
		xmlNodePtr node = nodeset->nodeTab[i];
		if (!restricted) {
			if (xmlHasProp(node, (const xmlChar *)"capabilities")) {
				printf("%stask with capabilities: %s\n",
				       i + 1 < nodeset->nodeNr ? element : end,
				       xmlGetProp(
					       node,
					       (const xmlChar *)"capabilities"));
			} else {
				printf("%stask without capabilities:\n",
				       i + 1 < nodeset->nodeNr ? element : end);
			}
		} else if (i == 0) {
			printf("%stask:\n", end);
		}

		if (node->children)
			for (xmlNodePtr command = node->children; command;
			     command = command->next) {
				printf("%s%s%s\n",
				       restricted || i + 1 >= nodeset->nodeNr ?
					       space :
					       vertical,
				       i + 1 < nodeset->nodeNr ? element : end,
				       command->children->content);
			}
		else {
			printf("%s%sAny command\n",
			       restricted || i + 1 >= nodeset->nodeNr ?
				       space :
				       vertical,
			       i + 1 < nodeset->nodeNr ? element : end);
		}
	}
}

/**
 * @brief print role
 * @param role the role node
*/
void print_xml_role(xmlNodePtr role)
{
	char *vertical = "│  ";
	char *element = "├─ ";
	char *end = "└─ ";
	char *space = "   ";
	xmlChar *name = xmlGetProp(role, (const xmlChar *)"name");
	printf("Role \"%s\"\n", name);
	xmlFree(name);
	xmlAttrPtr priority = xmlHasProp(role, (const xmlChar *)"priority");
	xmlAttrPtr bounding = xmlHasProp(role, (const xmlChar *)"bounding");
	xmlAttrPtr noroot = xmlHasProp(role, (const xmlChar *)"root");
	xmlAttrPtr keepenv = xmlHasProp(role, (const xmlChar *)"keep-env");

	if (priority || bounding || noroot || keepenv) {
		printf("%sProperties:\n", role->children ? element : end);
		if (priority) {
			printf("%s%sPriority %s", vertical,
			       bounding || noroot || keepenv ? element : end,
			       priority->children->content);
		}
	}
	xmlNodeSetPtr users =
		xmlNodeSetDup(search_element_in_role(role, "user"));
	xmlNodeSetPtr groups =
		xmlNodeSetDup(search_element_in_role(role, "group"));
	xmlNodeSetPtr task = search_element_in_role(role, "task");
	if (users->nodeNr + groups->nodeNr > 0) {
		char *side = task->nodeNr ? element : space;
		printf("%sActors:\n", task->nodeNr ? element : end);
		for (int i = 0; i < users->nodeNr; i++) {
			xmlNodePtr user = users->nodeTab[i];
			xmlChar *username =
				xmlGetProp(user, (const xmlChar *)"name");
			printf("%s%s%s\n", side,
			       i + 1 < (users->nodeNr + groups->nodeNr) ?
				       element :
				       end,
			       username);
			xmlFree(username);
		}
		for (int i = 0; i < groups->nodeNr; i++) {
			xmlNodePtr group = groups->nodeTab[i];
			xmlChar *groupname =
				xmlGetProp(group, (const xmlChar *)"names");
			printf("%s%s%s\n", side,
			       i + 1 < groups->nodeNr ? element : end,
			       groupname);
			xmlFree(groupname);
		}
	}
	print_task(task, 0);
	xmlXPathFreeObject(result);
	xmlXPathFreeNodeSet(users);
	xmlXPathFreeNodeSet(groups);
}

/**
 * @brief print a role
 * @param role the role name
*/
void print_full_role(char *role)
{
	xmlDocPtr doc;

	doc = load_xml(XML_FILE);
	if (doc) {
		xmlNodePtr role_node = get_role_node(doc, role);
		if (role_node) {
			print_xml_role(role_node);
		} else {
			printf("Role \"%s\" not found\n", role);
		}
	} else {
		printf("Error loading XML file\n");
	}
	xmlFreeDoc(doc);
}

/**
 * @brief print all roles
*/
void print_full_roles()
{
	xmlDocPtr doc;

	doc = load_xml(XML_FILE);
	if (doc)
		for (xmlNodePtr role = doc->children->children; role;
		     role = role->next) {
			print_xml_role(role);
		}
	else {
		printf("Error loading XML file\n");
	}
	xmlFreeDoc(doc);
}

/**
 * @brief print roles (including their task) that user can use
 * @param user the user name
 * @param nb_groups the number of groups
 * @param groups the groups
 * @param restricted if 1, print only roles and task, if 0, print all properties
*/
void print_rights(user_t *posix_user, int restricted)
{
	xmlDocPtr doc;

	doc = load_xml(XML_FILE);
	if (doc) {
		xmlNodeSetPtr roles = get_right_roles(doc, posix_user);
		xmlNodeSetPtr tmp = xmlNodeSetDup(roles);
		if (roles) {
			for (int i = 0; i < tmp->nodeNr; i++) {
				xmlNodePtr role = tmp->nodeTab[i];
				if (restricted) {
					xmlNodeSetPtr task =
						search_element_in_role(role,
								       "task");
					xmlChar *rolename = xmlGetProp(
						role, (const xmlChar *)"name");
					printf("Role \"%s\"\n", rolename);
					xmlFree(rolename);
					print_task(task, RESTRICTED);
					xmlXPathFreeNodeSet(task);
				} else {
					print_xml_role(role);
				}
			}
		} else {
			printf("Permission denied\n");
		}
		xmlXPathFreeNodeSet(tmp);
	} else {
		printf("Error loading XML file\n");
	}
	xmlFreeDoc(doc);
}

/**
 * @brief Check if user has rights to print role
 * @param role Role to check
 * @param user User to check
 * @param nb_groups Number of groups of user
 * @param groups Groups of user
 * @return >0 if user has rights, 0 otherwise
*/
int check_rights(xmlNodePtr role, user_t *user)
{
	xmlNodeSetPtr users = search_element_in_role(role, "user");
	xmlNodeSetPtr groups_node = NULL;
	int found = 0;
	for (int i = 0; i < users->nodeNr; i++) {
		xmlNodePtr user_node = users->nodeTab[i];
		xmlChar *username =
			xmlGetProp(user_node, (const xmlChar *)"name");
		if (!xmlStrcmp((xmlChar *)user->name, username)) {
			found = 1;
			xmlFree(username);
			goto result;
		}
		xmlFree(username);
	}
	groups_node = search_element_in_role(role, "group");
	for (int i = 0; i < groups_node->nodeNr; i++) {
		xmlNodePtr group_node = groups_node->nodeTab[i];
		xmlChar *group =
			xmlGetProp(group_node, (const xmlChar *)"names");
		int j = 0;
		for (; j < user->nb_groups; j++) {
			if (!xmlStrcmp(group, (xmlChar *)user->groups[j])) {
				found++;
			}
		}
		xmlFree(group);
		if (found == j) {
			goto result;
		}
		found = 0;
	}
result:
	return found;
}

/**
 * @brief print a role if user has rights
 * @param role the role name
 * @param user the user name
 * @param nb_groups the number of groups
 * @param groups the groups
 * @param restricted if 1, print only roles and task, if 0, print all properties
*/
void print_rights_role(char *role, user_t *user, int restricted)
{
	xmlDocPtr doc;

	doc = load_xml(XML_FILE);
	if (doc) {
		xmlNodePtr role_node = get_role_node(doc, role);
		if (role_node && check_rights(role_node, user)) {
			if (restricted) {
				xmlNodeSetPtr task = search_element_in_role(
					role_node, "task");
				xmlChar *rolename = xmlGetProp(
					role_node, (const xmlChar *)"name");
				printf("Role \"%s\"\n", rolename);
				xmlFree(rolename);
				print_task(task, RESTRICTED);
			} else {
				print_xml_role(role_node);
			}
		} else {
			printf("Permission denied\n");
		}
		xmlXPathFreeObject(result);
	} else {
		printf("Error loading XML file\n");
	}
	xmlFreeDoc(doc);
}

/* 
 * 
 * Copyright Ahmad Samer Wazan <ahmad-samer.wazan@irit.fr>, 2022
 * Copyright Eddie Billoir <eddie.billoir@irit.fr>, 2022
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.  */
