#include "params.h"
#define __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1

#include <stdlib.h>
#include <linux/limits.h>
#include <string.h>
#include <syslog.h>


static user_t *user = &(user_t){.name=NULL, .nb_groups = 0, .groups = NULL};

static cmd_t *command = &(cmd_t){NULL, 0, NULL};

static char *role = NULL;

static char *d_keep_vars[] = { "HOME",
			"USER",
			"LOGNAME",
			"COLORS",
			"DISPLAY",
			"HOSTNAME",
			"KRB5CCNAME",
			"LS_COLORS",
			"PS1",
			"PS2",
			"XAUTHORY",
			"XAUTHORIZATION",
			"XDG_CURRENT_DESKTOP" };
static char *d_check_vars[] = { "COLORTERM", "LANG", "LANGUAGE", "LC_*",
			 "LINGUAS",   "TERM", "TZ" };
static char d_path[] =
	"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin";

static settings_t options = { .env_keep = d_keep_vars,
			      .env_check = d_check_vars,
			      .path = d_path,
			      .setuid = NULL,
			      .setgid = NULL,
			      .disable_root = 1,
			      .apply_bounding = 1,
				  .iab = NULL };

/**
 * @brief Set the POSIX user variables
 * @param name The input user name
 * @param nb_groups The input user nb_groups
 * @param groups The input user groups
 * @return static user_t on success, NULL on error
*/
user_t *params_user_posix_set(char *name, int nb_groups, char **groups){
    user->nb_groups = nb_groups;
    user->groups = groups;
    user->name = name;
    return user;
}

user_t *params_user_get(){
    return user;
}

/**
 * @brief Set the command variables
 * @param command The input command absolute path
 * @param argc The input command argc
 * @param argv The input command argv
 * @param cmd The output command object
 * @return static cmd_t on success, NULL on error
*/
cmd_t *params_command_set(char *p_command, int argc, char **argv){
    command->command = p_command;
    command->argc = argc;
    command->argv = argv;
    return command;
}

cmd_t *params_command_get(){
    return command;
}

char *params_set_role(char *p_role){
    role = p_role;
    return role;
}

char *params_get_role(){
    return role;
}

/*******************************************
 ***            FIND OPTIONS             ***
********************************************/

settings_t *default_options_get(){
    return &options;
}

void set_default_options(settings_t *settings){
	if (settings == NULL){
		return;
	}
	settings->env_keep = d_keep_vars;
	settings->env_check = d_check_vars;
	settings->path = d_path;
	settings->setuid = NULL;
	settings->setgid = NULL;
	settings->disable_root = 1;
	settings->apply_bounding = 1;
	settings->role = NULL;
	settings->iab = cap_iab_init();
}

void options_assign(settings_t *dst, settings_t *src) {
	if (src == NULL || dst == NULL) {
		return;
	}
	if (src->env_keep != NULL) {
		dst->env_keep = src->env_keep;
	}
	if (src->env_check != NULL) {
		dst->env_check = src->env_check;
	}
	if (src->path != NULL) {
		dst->path = src->path;
	}
	if (src->setuid != NULL) {
		dst->setuid = src->setuid;
	}
	if (src->setgid != NULL) {
		dst->setgid = src->setgid;
	}
	dst->disable_root = src->disable_root;
	dst->apply_bounding = src->apply_bounding;
	if (src->role != NULL) {
		dst->role = src->role;
	}
	if (src->iab != NULL) {
		dst->iab = src->iab;
	}
}

static char** split_string(xmlChar *str, char *delimiter){
    if (str == NULL){
        return NULL;
    }
    char **array = NULL;
    int i = 0;
    char *token = strtok((char *)str, delimiter);
    while(token != NULL){
        char **re_array = realloc(array, sizeof(char*) * (i + 2));
        if (re_array == NULL){
            goto error;
        }
        array = re_array;
        array[i] = token;
        array[i + 1] = NULL;
        i++;
        token = strtok(NULL, delimiter);
    }
    return (char **) array;

    error:
    if (array != NULL){
        free(array);
    }
    return NULL;
}

/**
 * @brief check if an option is enforced
 * @param option the option to check
 * @return 1 if the option is enforced, 0 otherwise
*/
int option_enforced(xmlNodePtr option)
{
	if (!xmlHasProp(option, (const xmlChar *)"enforce"))
		return 1;
	int res = 0;
	xmlChar *prop = xmlGetProp(option, (const xmlChar *)"enforce");
	if (!xmlStrcmp(prop, (const xmlChar *)"true"))
		res = 1;
	xmlFree(prop);
	return res;
}

/**
 * @brief set the options from the options xml node
 * @param options_node the xml node containing the options
 * @return the options structure in the global variable options
*/
void set_options_from_node(xmlNodePtr options_node, settings_t *options)
{
	for (xmlNodePtr node = options_node->children; node;
	     node = node->next) {
		if (node->type == XML_ELEMENT_NODE) {
			if (!xmlStrcmp(node->name,
				       (const xmlChar *)"allow-root")) {
						options->disable_root = !option_enforced(node);
			} else if (!xmlStrcmp(
					   node->name,
					   (const xmlChar *)"allow-bounding")) {
				options->apply_bounding = !option_enforced(node);
			} else if (!xmlStrcmp(node->name,
					      (const xmlChar *)"path")) {
				options->path = (char *)xmlNodeGetContent(node);
			} else if (!xmlStrcmp(node->name,
					      (const xmlChar *)"env-keep")) {
				options->env_keep = split_string(
					xmlNodeGetContent(node),",");
			} else if (!xmlStrcmp(node->name,
					      (const xmlChar *)"env-check")) {
				options->env_check = split_string(
					xmlNodeGetContent(node),",");
			}
		}
	}
}

/**
 * @brief find the options node in the xml tree and set the options
 * @param p_node the node to start the search
 * @return the options structure in the global variable options
*/
void find_and_set_options_in_node(xmlNodePtr p_node, settings_t *options)
{
	for (xmlNodePtr node = p_node->children; node; node = node->next) {
		if (!xmlStrncmp(node->name, (const xmlChar *)"options", 7)) {
			set_options_from_node(node, options);
		}
	}
}

/**
 * @brief retrieve the options from the task node
 * @param task_node the edging node where options could be found
 * @return the options structure
 * @note This function is checking from the most specific to the most general and applies defaults if nothing is found
*/
void get_options_from_config(xmlNodePtr task_node, settings_t *options)
{
	find_and_set_options_in_node(task_node, options);
	if (task_node->parent == NULL)
		return;
	find_and_set_options_in_node(task_node->parent, options);
	if (task_node->doc == NULL || task_node->doc->children == NULL || task_node->doc->children->next == NULL)
		return;
	find_and_set_options_in_node(task_node->doc->children->next, options);
}

/**
 * @brief free the options structure
 * @param options the options structure to free
*/
void free_options(settings_t *options)
{
	//free(options->role);
	//free(options->iab);
	options->apply_bounding = 0;
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