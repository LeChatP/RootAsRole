#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __STDC_LIB_EXT1__
#define __STDC_LIB_EXT1__
#endif
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <criterion/criterion.h>
#include <criterion/new/assert.h>

#include "xml_manager.c"

Test(command_match, test_all_cases)
{
	char *command_xml = "<commands>\
        <command>/bin/ls</command>\
        <command>/bin/ls -a</command>\
        <command>*</command>\
        <command>**</command>\
        <command>* -a</command>\
        <command>* -(a|l)</command>\
        <command>/bin/l* -l</command>\
        <command>/bin/ls -*(l|a)</command>\
        <command>/bin/l*</command>\
        <command>/bin/l* -(l|a)*</command>\
    </commands>";
	xmlDocPtr doc = xmlParseMemory(command_xml, strlen(command_xml));
	xmlNodePtr root = xmlDocGetRootElement(doc);

	char *s_bin_ls = "/bin/ls";
	char *s_opt_l[2] = { "ls", "-l" };
	cmd_t *bin_ls_opt_l = &(struct s_cmd){
		.command = s_bin_ls,
		.argv = s_opt_l,
		.argc = 2,
	};

	char *s_opt_a[2] = { "ls", "-a" };
	cmd_t *bin_ls_opt_a = &(struct s_cmd){
		.command = s_bin_ls,
		.argv = s_opt_a,
		.argc = 2,
	};

	char *s_opt_a_l[3] = { "ls", "-a", "-l" };
	cmd_t *bin_ls_opt_a_l = &(struct s_cmd){
		.command = s_bin_ls,
		.argv = s_opt_a_l,
		.argc = 3,
	};

	char *s_opt_null[1] = { "ls" };
	cmd_t *bin_ls = &(struct s_cmd){
		.command = s_bin_ls,
		.argv = s_opt_null,
		.argc = 1,
	};

	char *s_opt_al[2] = { "ls", "-al" };
	cmd_t *bin_ls_opt_al = &(struct s_cmd){
		.command = s_bin_ls,
		.argv = s_opt_al,
		.argc = 2,
	};

	char *s_opt_la[2] = { "ls", "-la" };
	cmd_t *bin_ls_opt_la = &(struct s_cmd){
		.command = s_bin_ls,
		.argv = s_opt_la,
		.argc = 2,
	};

	char *argv_test6[2] = { "ls", "--l" };
	cmd_t *bin_ls_lopt_l = &(struct s_cmd){
		.command = s_bin_ls,
		.argv = argv_test6,
		.argc = 2,
	};

	char *s_opt_ls_space_a_null[1] = { "ls a" };
	char *s_bin_ls_space = "/bin/ls a";
	cmd_t *bin_ls_space = &(struct s_cmd){
		.command = s_bin_ls_space,
		.argv = s_opt_ls_space_a_null,
		.argc = 1,
	};

	char *s_opt_lsa_null[1] = { "ls a" };
	char *s_bin_lsa = "/bin/lsa";
	cmd_t *bin_lsa = &(struct s_cmd){
		.command = s_bin_lsa,
		.argv = s_opt_lsa_null,
		.argc = 1,
	};

	cmd_t *bin_lsa_opt_a = &(struct s_cmd){
		.command = s_bin_lsa,
		.argv = s_opt_a,
		.argc = 2,
	};
	/**
    char *s_bin_l = "/bin/l";
    cmd_t *bin_l = &(struct s_cmd) {
        .command = s_bin_l,
        .argv = s_opt_null,
        .argc = 0,
    };

    cmd_t *null_cmd = &(struct s_cmd) {
        .command = NULL,
        .argv = s_opt_null,
        .argc = 0,
    };

    cmd_t *bin_ls_a_opt_a = &(struct s_cmd) {
        .command = s_bin_ls_space,
        .argv = s_opt_a,
        .argc = 1,
    };*/
	char *s_opt_ls_minusa[1] = { "ls -a" };
	char *s_bin_ls_minusa = "/bin/ls -a";
	cmd_t *bin_ls_minusa = &(struct s_cmd){
		.command = s_bin_ls_minusa,
		.argv = s_opt_ls_minusa,
		.argc = 1,
	};

	int tests[11] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };

	// Test case : command match
	xmlNodePtr command = root->children->next;
	int result =
		command_match(bin_ls_opt_a, command); // /bin/ls -a vs /bin/ls
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls -a == /bin/ls, expected false");
	tests[result] = result;
	result = command_match(bin_ls, command); // /bin/ls vs /bin/ls
	cr_assert_eq(
		result, PATH_STRICT,
		"Error: command_match() /bin/ls == /bin/ls, expected true");
	tests[result] = result;

	result = command_match(bin_ls_space, command); // /bin/ls a vs /bin/ls
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls a == /bin/ls, expected false");

	// Test case : command match with argument
	command = command->next->next;
	result = command_match(bin_ls_opt_a,
			       command); // /bin/ls -a vs /bin/ls -a
	cr_assert_eq(
		result, PATH_ARG_STRICT,
		"Error: command_match() /bin/ls -a == /bin/ls -a, expected %d, got %d",
		PATH_ARG_STRICT, result);
	tests[result] = result;
	result = command_match(bin_ls_opt_a_l,
			       command); // /bin/ls -a -l vs /bin/ls -a
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls -a -l == /bin/ls -a, expected false");
	result = command_match(bin_ls_minusa,
			       command); // /bin/ls\ -a vs /bin/ls -a
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls\\ -a == /bin/ls -a, expected false");

	// Test case : command match with wildcard
	command = command->next->next;
	result = command_match(bin_ls, command); // /bin/ls vs *
	cr_assert_eq(result, PATH_FULL_WILDCARD,
		     "Error: command_match() /bin/ls == *, expected %d, got %d",
		     PATH_FULL_WILDCARD, result);
	tests[result] = result;
	result = command_match(bin_ls_opt_a_l, command); // /bin/ls -a -l vs *
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls -a -l == *, expected %d, got %d",
		NO_MATCH, result);
	result = command_match(bin_ls_minusa, command); // /bin/ls\ -a vs *
	cr_assert_eq(
		result, PATH_FULL_WILDCARD,
		"Error: command_match() /bin/ls\\ -a == *, expected %d, got %d",
		PATH_FULL_WILDCARD, result);

	// Test case : command full wildcard
	command = command->next->next;
	result = command_match(bin_ls, command); // /bin/ls vs **
	cr_assert_eq(
		result, PATH_ARG_FULL_WILDCARD,
		"Error: command_match() /bin/ls == **, expected %d, got %d",
		PATH_ARG_FULL_WILDCARD, result);
	tests[result] = result;
	result = command_match(bin_ls_opt_a_l, command); // /bin/ls -a -l vs **
	cr_assert_eq(
		result, PATH_ARG_FULL_WILDCARD,
		"Error: command_match() /bin/ls -a -l == **, expected %d, got %d",
		PATH_ARG_FULL_WILDCARD, result);
	result = command_match(bin_ls_minusa, command); // /bin/ls\ -a vs **
	cr_assert_eq(
		result, PATH_ARG_FULL_WILDCARD,
		"Error: command_match() /bin/ls\\ -a == **, expected %d, got %d",
		PATH_ARG_FULL_WILDCARD, result);

	// Test case : command match with wildcard and argument
	command = command->next->next;
	result = command_match(bin_ls_opt_a, command); // /bin/ls -a vs * -a
	cr_assert_eq(
		result, PATH_FULL_WILDCARD_ARG_STRICT,
		"Error: command_match() /bin/ls -a == * -a, expected %d, got %d",
		PATH_FULL_WILDCARD_ARG_STRICT, result);
	tests[result] = result;
	result = command_match(bin_ls, command); // /bin/ls vs * -a
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls == * -a, expected %d, got %d",
		NO_MATCH, result);
	result =
		command_match(bin_ls_opt_a_l, command); // /bin/ls -a -l vs * -a
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls -a -l == * -a, expected %d, got %d",
		NO_MATCH, result);

	// Test case : command match with wildcard and regex argument
	command = command->next->next;
	result = command_match(bin_ls_opt_a, command); // /bin/ls -a vs * -(a|l)
	cr_assert_eq(
		result, PATH_FULL_WILDCARD_ARG_WILDCARD,
		"Error: command_match() /bin/ls -a == * -(a|l), expected %d, got %d",
		PATH_FULL_WILDCARD_ARG_WILDCARD, result);
	tests[result] = result;
	result = command_match(bin_ls, command); // /bin/ls vs * -(a|l)
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls == * -(a|l), expected %d, got %d",
		NO_MATCH, result);
	result = command_match(bin_ls_opt_a_l,
			       command); // /bin/ls -a -l vs * -(a|l)
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls -a -l == * -(a|l), expected %d, got %d",
		NO_MATCH, result);

	// Test case : command match with wildcard but  strict argument
	command = command->next->next;
	result = command_match(bin_ls_opt_l,
			       command); // /bin/ls -l vs /bin/l* -l
	cr_assert_eq(
		result, PATH_WILDCARD_ARG_STRICT,
		"Error: command_match() /bin/ls -l == /bin/l* -l, expected %d, got %d",
		PATH_WILDCARD_ARG_STRICT, result);
	tests[result] = result;
	result = command_match(bin_ls_opt_a,
			       command); // /bin/ls -a vs /bin/l* -l
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls -a == /bin/l* -l, expected %d, got %d",
		NO_MATCH, result);

	// Test case : command match without wildcard but regex argument
	command = command->next->next;
	result = command_match(bin_ls_opt_l,
			       command); // /bin/ls -l vs /bin/ls -*(a|l)
	cr_assert_eq(
		result, PATH_STRICT_ARG_WILDCARD,
		"Error: command_match() /bin/ls -l == /bin/ls -*(a|l), expected %d, got %d",
		PATH_STRICT_ARG_WILDCARD, result);
	tests[result] = result;
	result = command_match(bin_ls_opt_a,
			       command); // /bin/ls -a vs /bin/ls -*(a|l)
	cr_assert_eq(
		result, PATH_STRICT_ARG_WILDCARD,
		"Error: command_match() /bin/ls -a == /bin/ls -*(a|l), expected %d, got %d",
		PATH_STRICT_ARG_WILDCARD, result);
	result = command_match(bin_ls_opt_la,
			       command); // /bin/ls -la vs /bin/ls -*(a|l)
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls -la == /bin/ls -*(a|l), expected %d, got %d",
		NO_MATCH, result);
	result = command_match(bin_ls_opt_al,
			       command); // /bin/ls -al vs /bin/ls -*(a|l)
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls -al == /bin/ls -*(a|l), expected %d, got %d",
		NO_MATCH, result);
	result = command_match(bin_ls_lopt_l,
			       command); // /bin/ls --l vs /bin/ls -*(a|l)
	cr_assert_eq(
		result, PATH_STRICT_ARG_WILDCARD,
		"Error: command_match() /bin/ls --l == /bin/ls -*(a|l), expected %d, got %d",
		PATH_STRICT_ARG_WILDCARD, result);

	// Test case : command match with wildcard but no arguments
	command = command->next->next;
	result = command_match(bin_ls, command); // /bin/ls vs /bin/l*
	cr_assert_eq(
		result, PATH_WILDCARD,
		"Error: command_match() /bin/ls == /bin/l*, expected %d, got %d",
		PATH_WILDCARD, result);
	tests[result] = result;
	result = command_match(bin_ls_opt_l, command); // /bin/ls -l vs /bin/l*
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/ls -l == /bin/l*, expected %d, got %d",
		NO_MATCH, result);
	result = command_match(bin_lsa, command); // /bin/lsa vs /bin/l*
	cr_assert_eq(
		result, PATH_WILDCARD,
		"Error: command_match() /bin/lsa == /bin/l*, expected %d, got %d",
		PATH_WILDCARD, result);
	result =
		command_match(bin_lsa_opt_a, command); // /bin/lsa -a vs /bin/l*
	cr_assert_eq(
		result, NO_MATCH,
		"Error: command_match() /bin/lsa -a == /bin/l*, expected %d, got %d",
		NO_MATCH, result);

	// Test case : command match with wildcard and regex argument
	command = command->next->next;
	result = command_match(bin_ls_opt_l,
			       command); // /bin/ls -l vs /bin/l* -(l|a)*
	cr_assert_eq(
		result, PATH_ARG_WILDCARD,
		"Error: command_match() /bin/ls -l == /bin/l* -(l|a)*, expected %d, got %d",
		PATH_ARG_WILDCARD, result);
	tests[result] = result;
	result = command_match(bin_ls_opt_a,
			       command); // /bin/ls -a vs /bin/l* -(l|a)*
	cr_assert_eq(
		result, PATH_ARG_WILDCARD,
		"Error: command_match() /bin/ls -a == /bin/l* -(l|a)*, expected %d, got %d",
		PATH_ARG_WILDCARD, result);
	result = command_match(bin_ls_opt_la,
			       command); // /bin/ls -la vs /bin/l* -(l|a)*
	cr_assert_eq(
		result, PATH_ARG_WILDCARD,
		"Error: command_match() /bin/ls -la == /bin/l* -(l|a)*, expected %d, got %d",
		PATH_ARG_WILDCARD, result);
	result = command_match(bin_lsa_opt_a,
			       command); // /bin/lsa -a vs /bin/l* -(l|a)*
	cr_assert_eq(
		result, PATH_ARG_WILDCARD,
		"Error: command_match() /bin/lsa -a == /bin/l* -(l|a)*, expected %d, got %d",
		PATH_ARG_WILDCARD, result);

	//Test 0,1,2,3,4,5,6,7,8,9,10
	int expected[11] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
	cr_assert_arr_eq(tests, expected, 11,
			 "Error: command_match() failed to match all tests");
	xmlFreeDoc(doc);
}

// Define the test suite
Test(count_matching_groups, test_matching_groups)
{
	char *names = "group1,group2,group3";
	char *groups[] = { "group1", "group2", "group3" };
	int nb_groups = 3;
	unsigned int all;
	unsigned int result = count_matching_groups(names, groups, nb_groups, &all);
	cr_assert_eq(result, 3, "Expected 3 matching groups, but got %d",
		     result);
	cr_assert_eq(all, 3, "Expected 3 total groups, but got %d", all);
}

Test(count_matching_groups, test_non_matching_groups)
{
	char *names = "group1,group2,group3";
	char *groups[] = { "group1", "group2", "group4" };
	int nb_groups = 3;
	unsigned int all;
	unsigned int result = count_matching_groups(names, groups, nb_groups, &all);
	cr_assert_eq(result, 0, "Expected 0 matching groups, but got %d",
		     result);
	cr_assert_eq(all, 3, "Expected 3 total groups, but got %d", all);
}

Test(count_matching_groups, test_partial_matching_groups)
{
	char *names = "group1,group2,group3";
	char *groups[] = { "group1", "group2", "group3",
			   "group4", "group6", "group5" };
	int nb_groups = 6;
	unsigned int all;
	unsigned int result = count_matching_groups(names, groups, nb_groups, &all);
	cr_assert_eq(result, 3, "Expected 3 matching group, but got %d",
		     result);
	cr_assert_eq(all, 3, "Expected 3 total groups, but got %d", all);
}

Test(expr_user_or_groups, test1)
{
	// Test with valid user and group
	char *user = "john";
	char *groups[] = { "developers", "designers" };
	int nb_groups = 2;
	xmlChar *expr;
	int result = __expr_user_or_groups(&expr, user, groups, nb_groups);
	cr_assert_eq(result, 107, "Expected 107, but got %d", result);
	cr_assert_str_eq(
		(char *)expr,
		"actors/user[@name='john'] or actors/group[contains(@names, 'developers') or contains(@names, 'designers')]",
		"Expression does not match expected value\n%s", expr);
	xmlFree(expr);
}

Test(expr_user_or_groups, test2)
{
	// Test with invalid user and group
	char *user = "jane";
	char *groups[] = { "managers", "admins", "developers", "designers" };
	int nb_groups = 4;
	xmlChar *expr;
	int result = __expr_user_or_groups(&expr, user, groups, nb_groups);
	cr_assert_eq(result, 169, "Expected 169, but got %d", result);
	cr_assert_str_eq(
		(char *)expr,
		"actors/user[@name='jane'] or actors/group[contains(@names, 'managers') or contains(@names, 'admins') or contains(@names, 'developers') or contains(@names, 'designers')]",
		"Expression does not match expected value\n%s", expr);
	xmlFree(expr);
}

Test(expr_user_or_groups, test3)
{
	// Test with invalid user and valid group
	char *user = "jane";
	char *groups[] = { "developers" };
	int nb_groups = 1;
	xmlChar *expr;
	int result = __expr_user_or_groups(&expr, user, groups, nb_groups);
	cr_assert_eq(result, 74, "Expected 74, but got %d", result);
	cr_assert_str_eq(
		(char *)expr,
		"actors/user[@name='jane'] or actors/group[contains(@names, 'developers')]",
		"Expression does not match expected value\n%s", expr);
	xmlFree(expr);
}

Test(expr_user_or_groups, test4)
{
	// Test with valid user and invalid group
	char *user = "john";
	char *groups[] = { "managers" };
	int nb_groups = 1;
	xmlChar *expr;
	int result = __expr_user_or_groups(&expr, user, groups, nb_groups);
	cr_assert_eq(result, 72, "Expected 72, but got %d", result);
	cr_assert_str_eq(
		(char *)expr,
		"actors/user[@name='john'] or actors/group[contains(@names, 'managers')]",
		"Expression obtained does not match expected value : \n%s",
		expr);
	xmlFree(expr);
}

Test(expr_search_role_by_usergroup_command, test1)
{
	char *s_bin_ls = "/bin/ls";
	char *s_opt_al[2] = { "ls", "-al" };
	cmd_t *bin_ls_opt_al = &(struct s_cmd){
		.command = s_bin_ls,
		.argv = s_opt_al,
		.argc = 2,
	};
	// Test with valid user and group
	xmlChar *expr;
	user_t *user_struct = &(struct s_user){
		.name = "john",
		.groups = malloc(sizeof(char *) * 2),
		.nb_groups = 2,
	};
	user_struct->groups[0] = "managers";
	user_struct->groups[1] = "designers";
	expr = expr_search_role_by_usergroup_command(user_struct,
						     bin_ls_opt_al);
	cr_assert_str_eq(
		(char *)expr,
		"//role[(actors/user[@name='john'] or actors/group[contains(@names, 'managers') or contains(@names, 'designers')]) and (task/command[text()='/bin/ls -al'] or task/command[string-length(translate(text(),'.+*?^$()[]{}|\\\\','')) < string-length(text())])]",
		"Expression does not match expected value\n%s", expr);
	xmlFree(expr);
}

Test(actors_match, match_user)
{
	char **groups = malloc(sizeof(char *) * 2);
	groups[0] = "users";
	groups[1] = "admin";
	user_t user = { .name = "Alice", .groups = groups, .nb_groups = 2 };
	xmlNodePtr actors = xmlNewNode(NULL, (xmlChar *)"actors");
	xmlNodePtr xuser = xmlNewChild(actors, NULL, (xmlChar *)"user", NULL);
	xmlNewProp(xuser, (xmlChar *)"name", (xmlChar *)"Alice");
	score_t score = actors_match(&user, actors);
	cr_assert_eq(score, 1, "Expected score to be 1, but got %d", score);
	xmlFreeNode(actors);
	free(groups);
}

Test(actors_match, match_group)
{
	char **groups = malloc(sizeof(char *) * 2);
	groups[0] = "users";
	groups[1] = "guests";
	user_t user = { .name = "Bob", .groups = groups, .nb_groups = 2 };
	xmlNodePtr actors = xmlNewNode(NULL, (xmlChar *)"actors");
	xmlNodePtr xgroup = xmlNewChild(actors, NULL, (xmlChar *)"group", NULL);
	xmlNewProp(xgroup, (xmlChar *)"names", (xmlChar *)"users,guests");
	score_t score = actors_match(&user, actors);
	cr_assert_eq(score, 1, "Expected score to be 1, but got %d", score);
	xmlFreeNode(actors);
	free(groups);
}

Test(actors_match, match_max_group)
{
	char **groups = malloc(sizeof(char *) * 1);
	groups[0] = "guests";
	user_t user = { .name = "Charlie", .groups = groups, .nb_groups = 1 };
	xmlNodePtr actors = xmlNewNode(NULL, (xmlChar *)"actors");
	xmlNodePtr xgroup = xmlNewChild(actors, NULL, (xmlChar *)"group", NULL);
	xmlNewProp(xgroup, (xmlChar *)"names", (xmlChar *)"guests,users");
	score_t score = actors_match(&user, actors);
	cr_assert_eq(score, 0, "Expected score to be 0, but got %d", score);
	xmlFreeNode(actors);
	free(groups);
}

Test(actors_match, unknown_error)
{
	char **groups = malloc(sizeof(char *) * 2);
	user_t user = { .name = "Dave", .groups = groups, .nb_groups = 0 };
	xmlNodePtr actors = xmlNewNode(NULL, (xmlChar *)"actors");
	score_t score = actors_match(&user, actors);
	cr_assert_eq(score, 0, "Expected score to be 0, but got %d", score);
	xmlFreeNode(actors);
	free(groups);
}

Test(setuser_min, test1)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 1,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task, (xmlChar *)"setuser", (xmlChar *)"user");
	score_t score = setuser_min(task, &settings);
	cr_assert_eq(SETUID, score, "Expected score to be %d, but got %d",
		     SETUID, score);
}

Test(setuser_min, test2)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 0,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task, (xmlChar *)"setuser", (xmlChar *)"root");
	score_t score = setuser_min(task, &settings);
	cr_assert_eq(SETUID_ROOT, score, "Expected score to be %d, but got %d",
		     SETUID_ROOT, score);
}

Test(setuser_min, test3)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 1,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	score_t score = setuser_min(task, &settings);
	cr_assert_eq(NO_SETUID_NO_SETGID, score,
		     "Expected score to be %d, but got %d", NO_SETUID_NO_SETGID,
		     score);
    xmlNewProp(task, (xmlChar *)"setuser", (xmlChar *)"");
    score =  setuser_min(task, &settings);
	cr_assert_eq(NO_SETUID_NO_SETGID, score,
		     "Expected score to be %d, but got %d", NO_SETUID_NO_SETGID,
		     score);
}

Test(setuser_min, test4)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 1,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task, (xmlChar *)"setuser", (xmlChar *)"root");
	score_t score = setuser_min(task, &settings);
	cr_assert_eq(SETUID, score, "Expected score to be %d, but got %d",
		     SETUID, score);
}

Test(setgid_min, test_no_setuid_no_setgid)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 1,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	score_t nb_setgid = -1;
	score_t score =
		setgid_min(task, &settings, NO_SETUID_NO_SETGID, &nb_setgid);
	cr_assert_eq(NO_SETUID_NO_SETGID, score,
		     "Expected score to be %d, but got %d", NO_SETUID_NO_SETGID,
		     score);
    cr_assert_eq(-1, nb_setgid, "Expected nb_setgid to be %d, but got %d", -1, nb_setgid);
}

Test(setgid_min, test_setuid)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 1,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	score_t nb_setgid = -1;
	score_t score = setgid_min(task, &settings, SETUID, &nb_setgid);
	cr_assert_eq(SETUID, score, "Expected score to be %d, but got %d",
		     SETUID, score);
    cr_assert_eq(-1, nb_setgid, "Expected nb_setgid to be %d, but got %d", -1, nb_setgid);
}

Test(setgid_min, test_no_setuid_setgid)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 1,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task, (xmlChar *)"setgroups", (xmlChar *)"test");
	score_t nb_setgid = -1;
	score_t score =
		setgid_min(task, &settings, NO_SETUID_NO_SETGID, &nb_setgid);
	cr_assert_eq(SETGID, score, "Expected score to be %d, but got %d",
		     SETGID, score);
    cr_assert_eq(1, nb_setgid, "Expected nb_setgid to be %d, but got %d", 1, nb_setgid);
}

Test(setgid_min, test_setuid_setgid)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 1,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task, (xmlChar *)"setgroups", (xmlChar *)"group1,group2");
	score_t nb_setgid = -1;
	score_t score = setgid_min(task, &settings, SETUID, &nb_setgid);
	cr_assert_eq(SETUID_SETGID, score,
		     "Expected score to be %d, but got %d", SETUID_SETGID,
		     score);
    cr_assert_eq(2, nb_setgid, "Expected nb_setgid to be %d, but got %d", 2, nb_setgid);
}

Test(setgid_min, test_setgid_root)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 0,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task, (xmlChar *)"setgroups", (xmlChar *)"root");
	score_t nb_setgid = -1;
	score_t score =
		setgid_min(task, &settings, NO_SETUID_NO_SETGID, &nb_setgid);
	cr_assert_eq(SETGID_ROOT, score, "Expected score to be %d, but got %d",
		     SETGID_ROOT, score);
    cr_assert_eq(1, nb_setgid, "Expected nb_setgid to be %d, but got %d", 1, nb_setgid);
    settings.no_root = 1;
    score = setgid_min(task, &settings, NO_SETUID_NO_SETGID, &nb_setgid);
    cr_assert_eq(SETGID, score, "Expected score to be %d, but got %d",
             SETGID, score);
}

Test(setgid_min, test_notroot_setuid_setgid_root)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 0,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task, (xmlChar *)"setgroups", (xmlChar *)"root,group1,group2");
	score_t nb_setgid = -1;
	score_t score = setgid_min(task, &settings, SETUID, &nb_setgid);
	cr_assert_eq(SETUID_NOTROOT_SETGID_ROOT, score,
		     "Expected score to be %d, but got %d",
		     SETUID_NOTROOT_SETGID_ROOT, score);
    cr_assert_eq(3, nb_setgid, "Expected nb_setgid to be %d, but got %d", 3, nb_setgid);
    settings.no_root = 1;
    score = setgid_min(task, &settings, SETUID, &nb_setgid);
    cr_assert_eq(SETUID_SETGID, score, "Expected score to be %d, but got %d",
             SETUID_SETGID, score);
}

Test(setgid_min, test_setuid_root_setgid)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 0,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task, (xmlChar *)"setgroups", (xmlChar *)"test");
	score_t nb_setgid = -1;
	score_t score = setgid_min(task, &settings, SETUID_ROOT, &nb_setgid);
	cr_assert_eq(SETUID_ROOT_SETGID, score,
		     "Expected score to be %d, but got %d", SETUID_ROOT_SETGID,
		     score);
    cr_assert_eq(1, nb_setgid, "Expected nb_setgid to be %d, but got %d", 1, nb_setgid);
}

Test(setgid_min, test_setuid_setgid_root)
{
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 0,
		.bounding = 0,
		.iab = NULL,
	};
	xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task, (xmlChar *)"setgroups", (xmlChar *)"root");
	score_t nb_setgid = -1;
	score_t score = setgid_min(task, &settings, SETUID_ROOT, &nb_setgid);
	cr_assert_eq(SETUID_SETGID_ROOT, score,
		     "Expected score to be %d, but got %d", SETUID_SETGID_ROOT,
		     score);
    cr_assert_eq((score_t) 1, nb_setgid, "Expected nb_setgid to be %lu, but got %lu", (score_t)1, nb_setgid);
    settings.no_root = 1;
    score = setgid_min(task, &settings, SETUID_ROOT, &nb_setgid);
    cr_assert_eq(SETUID_ROOT_SETGID, score, "Expected score to be %d, but got %d",
             SETUID_ROOT_SETGID, score);
}


Test(get_setuid_min, test1) {
    xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
    xmlNewProp(task, (xmlChar *)"setuser", (xmlChar *)"root");
    xmlNewProp(task, (xmlChar *)"setgroups", (xmlChar *)"root,group1,group2");
    settings_t settings = {
        .env_keep = NULL,
        .env_check = NULL,
        .path = NULL,
        .role = NULL,
        .setuid = NULL,
        .setgid = NULL,
        .no_root = 0,
        .bounding = 0,
        .iab = NULL,
    };
    score_t nb_setgid = -1;
    score_t score = get_setuid_min(task, &settings, &nb_setgid);
    cr_assert_eq(SETUID_SETGID_ROOT, score, "Expected score to be %d, but got %d",
             SETUID_SETGID_ROOT, score);
    cr_assert_eq(3, nb_setgid, "Expected nb_setgid to be %d, but got %d", 3, nb_setgid);
}

Test(set_task_min, test1) {
    xmlNodePtr task = xmlNewNode(NULL, (xmlChar *)"task");
    xmlNewProp(task, (xmlChar *)"setuser", (xmlChar *)"root");
    xmlNewProp(task, (xmlChar *)"setgroups", (xmlChar *)"root,group1,group2");
	xmlNewProp(task, (xmlChar *)"capabilities", (xmlChar *)"aLl");
    xmlNodePtr node = xmlNewChild(task, NULL, (xmlChar *)"command", NULL);
	xmlNodeSetContent(node, (xmlChar *)"/bin/ls");
    settings_t settings = {
        .env_keep = NULL,
        .env_check = NULL,
        .path = NULL,
        .role = NULL,
        .setuid = NULL,
        .setgid = NULL,
        .no_root = 0,
        .bounding = 0,
        .iab = NULL,
    };
    cmd_t cmd = (struct s_cmd) {
        .command = "/bin/ls",
        .argv = NULL,
        .argc = 0,
    };
    score_t nb_setgid = -1, cmd_min = -1, caps_min = -1, setuid_min = -1;
    score_t ret = task_match(&cmd, task, &settings,
	       &cmd_min, &caps_min, &setuid_min,
	       &nb_setgid);
    cr_assert_eq(1, ret, "Expected ret to be %d, but got %d", 1, ret);
	cr_assert_eq(SETUID_SETGID_ROOT, setuid_min, "Expected setuid_min to be %d, but got %d", SETUID_SETGID_ROOT, setuid_min);
	cr_assert_eq(3, nb_setgid, "Expected nb_setgid to be %d, but got %d", 3, nb_setgid);
	cr_assert_eq(PATH_STRICT, cmd_min, "Expected cmd_min to be %d, but got %d", PATH_STRICT, cmd_min);
	cr_assert_eq(CAPS_ALL, caps_min, "Expected caps_min to be %d, but got %d", CAPS_ALL, caps_min);

	xmlNodePtr task2 = xmlNewNode(NULL, (xmlChar *)"task");
	xmlNewProp(task2, (xmlChar *)"setuser", (xmlChar *)"root");
	xmlNewProp(task2, (xmlChar *)"setgroups", (xmlChar *)"root,group1,group2");
	xmlNewProp(task2, (xmlChar *)"capabilities", (xmlChar *)"cap_sys_admin,cap_dac_override");
	xmlNodePtr xmlnewcmd = xmlNewChild(task2, NULL, (xmlChar *)"command", NULL);
	xmlNodeSetContent(xmlnewcmd, (xmlChar *)"/bin/ls");
	xmlNodePtr min_task = NULL;
	score_t security_min = -1;
	int res = set_task_min(&cmd, task2, &min_task, &settings, &cmd_min, &caps_min, &setuid_min, &nb_setgid, &security_min);
	
	cr_assert_eq(SETUID_SETGID_ROOT, setuid_min, "Expected setuid_min to be %d, but got %d", SETUID_SETGID_ROOT, setuid_min);
	cr_assert_eq(3, nb_setgid, "Expected nb_setgid to be %d, but got %d", 3, nb_setgid);
	cr_assert_eq(PATH_STRICT, cmd_min, "Expected cmd_min to be %d, but got %d", PATH_STRICT, cmd_min);
	cr_assert_eq(CAPS_ADMIN, caps_min, "Expected caps_min to be %d, but got %d", CAPS_ADMIN, caps_min);
	cr_assert_eq(ENABLE_ROOT_DISABLE_BOUNDING, security_min, "Expected security_min to be %d, but got %d", ENABLE_ROOT_DISABLE_BOUNDING, security_min);
	cr_assert_eq(min_task, task2);
	cr_assert_eq(1, res, "Expected res to be %d, but got %d", 1, res);
	
}

Test(min_partial_order_role, test1) {
	xmlNodePtr role1 = xmlNewNode(NULL, (xmlChar *)"role");
	xmlNewProp(role1, (xmlChar *)"name", (xmlChar *)"role1");
	xmlNodePtr actors = xmlNewChild(role1, NULL, (xmlChar *)"actors", NULL);
	xmlNodePtr rootuser = xmlNewChild(actors, NULL, (xmlChar *)"user", NULL);
	xmlNewProp(rootuser, (xmlChar *)"name", (xmlChar *)"root");
	xmlNodePtr task = xmlNewChild(role1, NULL, (xmlChar *)"task", NULL);
	xmlAddNextSibling(task, NULL);
	xmlNodePtr xmlcmd = xmlNewChild(task, NULL, (xmlChar *)"command", NULL);
	xmlNodeSetContent(xmlcmd, (xmlChar *)"/bin/ls");
	xmlNodePtr xmlsettings = xmlNewChild(task, NULL, (xmlChar *)"options", NULL);
	xmlNodePtr xmlpath = xmlNewChild(xmlsettings, NULL, (xmlChar *)"path", NULL);
	xmlChar *path = (xmlChar *)"somepath";
	xmlNodeSetContent(xmlpath, path);
	xmlNodePtr xmlcaps = xmlNewChild(xmlsettings, NULL, (xmlChar *)"allow-root", NULL);
	xmlNewProp(xmlcaps, (xmlChar *)"enforced", (xmlChar *)"true");
	xmlNodePtr xmlsetuid = xmlNewChild(xmlsettings, NULL, (xmlChar *)"allow-bounding", NULL);
	xmlNewProp(xmlsetuid, (xmlChar *)"enforced", (xmlChar *)"true");
	settings_t settings = {
		.env_keep = NULL,
		.env_check = NULL,
		.path = NULL,
		.role = NULL,
		.setuid = NULL,
		.setgid = NULL,
		.no_root = 1,
		.bounding = 1,
		.iab = NULL,
	};
	cmd_t cmd = (struct s_cmd) {
		.command = "/bin/ls",
		.argv = NULL,
		.argc = 0,
	};
	user_t user = {
      .nb_groups = 0,
      .groups = NULL,
      .name = "root",
	};
	xmlNodePtr matched_role = NULL;
	xmlNodePtr matched_task = NULL;
	score_t user_min = -1, cmd_min = -1, caps_min = -1, setuid_min = -1, setgid_min = -1, security_min = -1;
	int n_roles = 0;
	min_partial_order_role(role1, &user,&cmd, &user_min, &cmd_min,
			    &caps_min, &setuid_min,
			    &setgid_min, &security_min,
			    &matched_role, &matched_task,
			    &settings, &n_roles);
	cr_assert_eq(1, n_roles, "Expected n_roles to be %d, but got %d", 1, n_roles);
	cr_assert_eq(user_min, 1, "Expected user_min to be %d, but got %d", 1, user_min);
	cr_assert_eq(cmd_min, PATH_STRICT, "Expected cmd_min to be %d, but got %d", PATH_STRICT, cmd_min);
	cr_assert_eq(caps_min, NO_CAPS, "Expected caps_min to be %d, but got %d", NO_CAPS, caps_min);
	cr_assert_eq(setuid_min, NO_SETUID_NO_SETGID, "Expected setuid_min to be %d, but got %d", NO_SETUID_NO_SETGID, setuid_min);
	cr_assert_eq(setgid_min, -1, "Expected setgid_min to be %d, but got %d", -1, setgid_min);
	cr_assert_eq(security_min, ENABLE_ROOT_DISABLE_BOUNDING, "Expected security_min to be %d, but got %d", DISABLE_BOUNDING, security_min);
	cr_assert_eq(matched_role, role1);
	cr_assert_eq(matched_task, task);
	cr_assert_eq(strncmp(settings.path, (char *)path,9), 0, "Expected settings.path to be %s, but got %s", path, settings.path);

	xmlNodePtr role2 = xmlNewNode(NULL, (xmlChar *)"role");
	xmlNewProp(role2, (xmlChar *)"name", (xmlChar *)"role2");
	xmlNodePtr actors2 = xmlNewChild(role2, NULL, (xmlChar *)"actors", NULL);
	xmlNodePtr rootuser2 = xmlNewChild(actors2, NULL, (xmlChar *)"user", NULL);
	xmlNewProp(rootuser2, (xmlChar *)"name", (xmlChar *)"root");
	xmlNodePtr task2 = xmlNewChild(role2, NULL, (xmlChar *)"task", NULL);
	xmlNodePtr xmlcmd2 = xmlNewChild(task2, NULL, (xmlChar *)"command", NULL);
	xmlNodeSetContent(xmlcmd2, (xmlChar *)"/bin/ls");
	xmlNodePtr xmlsettings2 = xmlNewChild(task2, NULL, (xmlChar *)"options", NULL);
	xmlNodePtr xmlpath2 = xmlNewChild(xmlsettings2, NULL, (xmlChar *)"path", NULL);
	xmlChar *path2 = (xmlChar *)"somepath2";
	xmlNodeSetContent(xmlpath2, path2);
	xmlNewChild(role2, NULL, NULL, NULL);

	min_partial_order_role(role2, &user,&cmd, &user_min, &cmd_min,
			    &caps_min, &setuid_min,
			    &setgid_min, &security_min,
			    &matched_role, &matched_task,
			    &settings, &n_roles);

	cr_assert_eq(1, n_roles, "Expected n_roles to be %d, but got %d", 1, n_roles);
	cr_assert_eq(user_min, 1, "Expected user_min to be %d, but got %d", 1, user_min);
	cr_assert_eq(cmd_min, PATH_STRICT, "Expected cmd_min to be %d, but got %d", PATH_STRICT, cmd_min);
	cr_assert_eq(caps_min, NO_CAPS, "Expected caps_min to be %d, but got %d", NO_CAPS, caps_min);
	cr_assert_eq(setuid_min, NO_SETUID_NO_SETGID, "Expected setuid_min to be %d, but got %d", NO_SETUID_NO_SETGID, setuid_min);
	cr_assert_eq(setgid_min, -1, "Expected setgid_min to be %d, but got %d", -1, setgid_min);
	cr_assert_eq(security_min, NO_ROOT_WITH_BOUNDING, "Expected security_min to be %d, but got %d", NO_ROOT_WITH_BOUNDING, security_min);
	cr_assert_eq(matched_role, role2);
	cr_assert_eq(matched_task, task2);
	cr_assert_eq(strncmp(settings.path, (char *)path2,10), 0, "Expected settings.path to be %s, but got %s", path2, settings.path);



}