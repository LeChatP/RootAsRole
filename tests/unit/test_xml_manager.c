#define _GNU_SOURCE
#define __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#include <criterion/criterion.h>

#include "xml_manager.c"


Test(command_match, test_all_cases) {

    char *command_xml="<commands>\
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
    char *s_opt_l[2] = {"ls","-l"};
    cmd_t *bin_ls_opt_l = &(struct s_cmd) {
        .command = s_bin_ls,
        .argv = s_opt_l,
        .argc = 2,
    };


    char *s_opt_a[2] = {"ls","-a"};
    cmd_t *bin_ls_opt_a = &(struct s_cmd) {
        .command = s_bin_ls,
        .argv = s_opt_a,
        .argc = 2,
    };

    char *s_opt_a_l[3] = {"ls","-a", "-l"};
    cmd_t *bin_ls_opt_a_l = &(struct s_cmd) {
        .command = s_bin_ls,
        .argv = s_opt_a_l,
        .argc = 3,
    };

    char *s_opt_null[1] = {"ls"};
    cmd_t *bin_ls = &(struct s_cmd) {
        .command = s_bin_ls,
        .argv = s_opt_null,
        .argc = 1,
    };

    char *s_opt_al[2] = {"ls","-al"};
    cmd_t *bin_ls_opt_al = &(struct s_cmd) {
        .command = s_bin_ls,
        .argv = s_opt_al,
        .argc = 2,
    };

    char *s_opt_la[2] = {"ls","-la"};
    cmd_t *bin_ls_opt_la = &(struct s_cmd) {
        .command = s_bin_ls,
        .argv = s_opt_la,
        .argc = 2,
    };

    char *argv_test6[2] = {"ls","--l"};
    cmd_t *bin_ls_lopt_l = &(struct s_cmd) {
        .command = s_bin_ls,
        .argv = argv_test6,
        .argc = 2,
    };

    char *s_opt_ls_space_a_null[1] = {"ls a"};
    char *s_bin_ls_space = "/bin/ls a";
    cmd_t *bin_ls_space = &(struct s_cmd) {
        .command = s_bin_ls_space,
        .argv = s_opt_ls_space_a_null,
        .argc = 1,
    };
    
    char *s_opt_lsa_null[1] = {"ls a"};
    char *s_bin_lsa = "/bin/lsa";
    cmd_t *bin_lsa = &(struct s_cmd) {
        .command = s_bin_lsa,
        .argv = s_opt_lsa_null,
        .argc = 1,
    };

    cmd_t *bin_lsa_opt_a = &(struct s_cmd) {
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
    char *s_opt_ls_minusa[1] = {"ls -a"};
    char *s_bin_ls_minusa = "/bin/ls -a";
    cmd_t *bin_ls_minusa = &(struct s_cmd) {
        .command = s_bin_ls_minusa,
        .argv = s_opt_ls_minusa,
        .argc = 1,
    };

    int tests[11] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};

    // Test case : command match
    xmlNodePtr command = root->children->next;
    int result = command_match(bin_ls_opt_a,command); // /bin/ls -a vs /bin/ls
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls -a == /bin/ls, expected false");
    tests[result] = result;
    result = command_match(bin_ls,command); // /bin/ls vs /bin/ls
    cr_assert_eq(result, PATH_STRICT, "Error: command_match() /bin/ls == /bin/ls, expected true");
    tests[result] = result;

    result = command_match(bin_ls_space,command); // /bin/ls a vs /bin/ls
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls a == /bin/ls, expected false");
    

    // Test case : command match with argument
    command = command->next->next;
    result = command_match(bin_ls_opt_a,command); // /bin/ls -a vs /bin/ls -a
    cr_assert_eq(result, PATH_ARG_STRICT, "Error: command_match() /bin/ls -a == /bin/ls -a, expected %d, got %d", PATH_ARG_STRICT, result);
    tests[result] = result;
    result = command_match(bin_ls_opt_a_l,command); // /bin/ls -a -l vs /bin/ls -a
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls -a -l == /bin/ls -a, expected false");
    result = command_match(bin_ls_minusa,command); // /bin/ls\ -a vs /bin/ls -a
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls\\ -a == /bin/ls -a, expected false");


    // Test case : command match with wildcard
    command = command->next->next;
    result = command_match(bin_ls,command); // /bin/ls vs *
    cr_assert_eq(result, PATH_FULL_WILDCARD, "Error: command_match() /bin/ls == *, expected %d, got %d",PATH_FULL_WILDCARD, result);
    tests[result] = result;
    result = command_match(bin_ls_opt_a_l,command); // /bin/ls -a -l vs *
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls -a -l == *, expected %d, got %d", NO_MATCH, result);
    result = command_match(bin_ls_minusa,command); // /bin/ls\ -a vs *
    cr_assert_eq(result, PATH_FULL_WILDCARD, "Error: command_match() /bin/ls\\ -a == *, expected %d, got %d", PATH_FULL_WILDCARD, result);

    // Test case : command full wildcard
    command = command->next->next;
    result = command_match(bin_ls,command); // /bin/ls vs **
    cr_assert_eq(result, PATH_ARG_FULL_WILDCARD, "Error: command_match() /bin/ls == **, expected %d, got %d", PATH_ARG_FULL_WILDCARD, result);
    tests[result] = result;
    result = command_match(bin_ls_opt_a_l,command); // /bin/ls -a -l vs **
    cr_assert_eq(result, PATH_ARG_FULL_WILDCARD, "Error: command_match() /bin/ls -a -l == **, expected %d, got %d", PATH_ARG_FULL_WILDCARD, result);
    result = command_match(bin_ls_minusa,command); // /bin/ls\ -a vs **
    cr_assert_eq(result, PATH_ARG_FULL_WILDCARD, "Error: command_match() /bin/ls\\ -a == **, expected %d, got %d", PATH_ARG_FULL_WILDCARD, result);

    // Test case : command match with wildcard and argument
    command = command->next->next;
    result = command_match(bin_ls_opt_a,command); // /bin/ls -a vs * -a
    cr_assert_eq(result, PATH_FULL_WILDCARD_ARG_STRICT, "Error: command_match() /bin/ls -a == * -a, expected %d, got %d", PATH_FULL_WILDCARD_ARG_STRICT, result);
    tests[result] = result;
    result = command_match(bin_ls,command); // /bin/ls vs * -a
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls == * -a, expected %d, got %d", NO_MATCH, result);
    result = command_match(bin_ls_opt_a_l,command); // /bin/ls -a -l vs * -a
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls -a -l == * -a, expected %d, got %d", NO_MATCH, result);

    // Test case : command match with wildcard and regex argument
    command = command->next->next;
    result = command_match(bin_ls_opt_a,command); // /bin/ls -a vs * -(a|l)
    cr_assert_eq(result, PATH_FULL_WILDCARD_ARG_WILDCARD, "Error: command_match() /bin/ls -a == * -(a|l), expected %d, got %d", PATH_FULL_WILDCARD_ARG_WILDCARD, result);
    tests[result] = result;
    result = command_match(bin_ls,command); // /bin/ls vs * -(a|l)
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls == * -(a|l), expected %d, got %d", NO_MATCH, result);
    result = command_match(bin_ls_opt_a_l,command); // /bin/ls -a -l vs * -(a|l)
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls -a -l == * -(a|l), expected %d, got %d", NO_MATCH, result);

    // Test case : command match with wildcard but  strict argument
    command = command->next->next;
    result = command_match(bin_ls_opt_l,command); // /bin/ls -l vs /bin/l* -l
    cr_assert_eq(result, PATH_WILDCARD_ARG_STRICT, "Error: command_match() /bin/ls -l == /bin/l* -l, expected %d, got %d", PATH_WILDCARD_ARG_STRICT, result);
    tests[result] = result;
    result = command_match(bin_ls_opt_a,command); // /bin/ls -a vs /bin/l* -l
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls -a == /bin/l* -l, expected %d, got %d", NO_MATCH, result);

    // Test case : command match without wildcard but regex argument
    command = command->next->next;
    result = command_match(bin_ls_opt_l,command); // /bin/ls -l vs /bin/ls -*(a|l)
    cr_assert_eq(result, PATH_STRICT_ARG_WILDCARD, "Error: command_match() /bin/ls -l == /bin/ls -*(a|l), expected %d, got %d", PATH_STRICT_ARG_WILDCARD, result);
    tests[result] = result;
    result = command_match(bin_ls_opt_a,command); // /bin/ls -a vs /bin/ls -*(a|l)
    cr_assert_eq(result, PATH_STRICT_ARG_WILDCARD, "Error: command_match() /bin/ls -a == /bin/ls -*(a|l), expected %d, got %d", PATH_STRICT_ARG_WILDCARD, result);
    result = command_match(bin_ls_opt_la,command); // /bin/ls -la vs /bin/ls -*(a|l)
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls -la == /bin/ls -*(a|l), expected %d, got %d", NO_MATCH, result);
    result = command_match(bin_ls_opt_al,command); // /bin/ls -al vs /bin/ls -*(a|l)
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls -al == /bin/ls -*(a|l), expected %d, got %d", NO_MATCH, result);
    result = command_match(bin_ls_lopt_l,command); // /bin/ls --l vs /bin/ls -*(a|l)
    cr_assert_eq(result, PATH_STRICT_ARG_WILDCARD, "Error: command_match() /bin/ls --l == /bin/ls -*(a|l), expected %d, got %d", PATH_STRICT_ARG_WILDCARD, result);

    // Test case : command match with wildcard but no arguments
    command = command->next->next;
    result = command_match(bin_ls,command); // /bin/ls vs /bin/l*
    cr_assert_eq(result, PATH_WILDCARD, "Error: command_match() /bin/ls == /bin/l*, expected %d, got %d", PATH_WILDCARD, result);
    tests[result] = result;
    result = command_match(bin_ls_opt_l,command); // /bin/ls -l vs /bin/l*
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/ls -l == /bin/l*, expected %d, got %d", NO_MATCH, result);
    result = command_match(bin_lsa,command); // /bin/lsa vs /bin/l*
    cr_assert_eq(result, PATH_WILDCARD, "Error: command_match() /bin/lsa == /bin/l*, expected %d, got %d", PATH_WILDCARD, result);
    result = command_match(bin_lsa_opt_a,command); // /bin/lsa -a vs /bin/l*
    cr_assert_eq(result, NO_MATCH, "Error: command_match() /bin/lsa -a == /bin/l*, expected %d, got %d", NO_MATCH, result);

    // Test case : command match with wildcard and regex argument
    command = command->next->next;
    result = command_match(bin_ls_opt_l,command); // /bin/ls -l vs /bin/l* -(l|a)*
    cr_assert_eq(result, PATH_ARG_WILDCARD, "Error: command_match() /bin/ls -l == /bin/l* -(l|a)*, expected %d, got %d", PATH_ARG_WILDCARD, result);
    tests[result] = result;
    result = command_match(bin_ls_opt_a,command); // /bin/ls -a vs /bin/l* -(l|a)*
    cr_assert_eq(result, PATH_ARG_WILDCARD, "Error: command_match() /bin/ls -a == /bin/l* -(l|a)*, expected %d, got %d", PATH_ARG_WILDCARD, result);
    result = command_match(bin_ls_opt_la,command); // /bin/ls -la vs /bin/l* -(l|a)*
    cr_assert_eq(result, PATH_ARG_WILDCARD, "Error: command_match() /bin/ls -la == /bin/l* -(l|a)*, expected %d, got %d", PATH_ARG_WILDCARD, result);
    result = command_match(bin_lsa_opt_a,command); // /bin/lsa -a vs /bin/l* -(l|a)*
    cr_assert_eq(result, PATH_ARG_WILDCARD, "Error: command_match() /bin/lsa -a == /bin/l* -(l|a)*, expected %d, got %d", PATH_ARG_WILDCARD, result);

    //Test 0,1,2,3,4,5,6,7,8,9,10
    int expected[11] = {0,1,2,3,4,5,6,7,8,9,10};
    cr_assert_arr_eq(tests, expected, 11, "Error: command_match() failed to match all tests");
    xmlFreeDoc(doc);

}


// Define the test suite
Test(count_matching_groups, test_matching_groups) {
    char *names = "group1,group2,group3";
    char *groups[] = {"group1", "group2", "group3"};
    int nb_groups = 3;
    int all;
    int result = count_matching_groups(names, groups, nb_groups, &all);
    cr_assert_eq(result, 3, "Expected 3 matching groups, but got %d", result);
    cr_assert_eq(all, 3, "Expected 3 total groups, but got %d", all);
}

Test(count_matching_groups, test_non_matching_groups) {
    char *names = "group1,group2,group3";
    char *groups[] = {"group1", "group2", "group4"};
    int nb_groups = 3;
    int all;
    int result = count_matching_groups(names, groups, nb_groups, &all);
    cr_assert_eq(result, 0, "Expected 0 matching groups, but got %d", result);
    cr_assert_eq(all, 3, "Expected 3 total groups, but got %d", all);
}

Test(count_matching_groups, test_partial_matching_groups) {
    char *names = "group1,group2,group3";
    char *groups[] = {"group1", "group2", "group3", "group4", "group6", "group5"};
    int nb_groups = 6;
    int all;
    int result = count_matching_groups(names, groups, nb_groups, &all);
    cr_assert_eq(result, 3, "Expected 3 matching group, but got %d", result);
    cr_assert_eq(all, 3, "Expected 3 total groups, but got %d", all);
}

Test(expr_user_or_groups, test1)
{
    // Test with valid user and group
    char *user = "john";
    char *groups[] = {"developers", "designers"};
    int nb_groups = 2;
    xmlChar *expr;
    int result = __expr_user_or_groups(&expr, user, groups, nb_groups);
    cr_assert_eq(result, 107, "Expected 107, but got %d", result);
    cr_assert_str_eq((char *)expr, "actors/user[@name='john'] or actors/group[contains(@names, 'developers') or contains(@names, 'designers')]", "Expression does not match expected value\n%s", expr);
    xmlFree(expr);
}

Test(expr_user_or_groups, test2)
{
    // Test with invalid user and group
    char *user = "jane";
    char *groups[] = {"managers", "admins", "developers", "designers"};
    int nb_groups = 4;
    xmlChar *expr;
    int result = __expr_user_or_groups(&expr, user, groups, nb_groups);
    cr_assert_eq(result, 169, "Expected 169, but got %d", result);
    cr_assert_str_eq((char *)expr, "actors/user[@name='jane'] or actors/group[contains(@names, 'managers') or contains(@names, 'admins') or contains(@names, 'developers') or contains(@names, 'designers')]", "Expression does not match expected value\n%s", expr);
    xmlFree(expr);
}

Test(expr_user_or_groups, test3)
{
    // Test with invalid user and valid group
    char *user = "jane";
    char *groups[] = {"developers"};
    int nb_groups = 1;
    xmlChar *expr;
    int result = __expr_user_or_groups(&expr, user, groups, nb_groups);
    cr_assert_eq(result, 74, "Expected 74, but got %d", result);
    cr_assert_str_eq((char *)expr, "actors/user[@name='jane'] or actors/group[contains(@names, 'developers')]", "Expression does not match expected value\n%s", expr);
    xmlFree(expr);
}

Test(expr_user_or_groups, test4)
{
    // Test with valid user and invalid group
    char *user = "john";
    char *groups[] = {"managers"};
    int nb_groups = 1;
    xmlChar *expr;
    int result = __expr_user_or_groups(&expr, user, groups, nb_groups);
    cr_assert_eq(result, 72, "Expected 72, but got %d", result);
    cr_assert_str_eq((char *)expr, "actors/user[@name='john'] or actors/group[contains(@names, 'managers')]", "Expression obtained does not match expected value : \n%s", expr);
    xmlFree(expr);
}

Test(expr_search_role_by_usergroup_command, test1) {
    // Test with valid user and group
    char *user = "john";
    char *groups[] = {"managers", "designers"};
    int nb_groups = 2;
    char *command = "/bin/ls -la";
    xmlChar *expr;
    user_t *user_struct = malloc(sizeof(user_t));
    user_struct->name = user;
    user_struct->groups = groups;
    user_struct->nb_groups = nb_groups;
    cmd_t *cmd_struct = malloc(sizeof(cmd_t));
    cmd_struct->command = command;
    expr = expr_search_role_by_usergroup_command(user_struct, cmd_struct);
    cr_assert_str_eq((char *)expr, "//role[(actors/user[@name='john'] or actors/group[contains(@names, 'managers') or contains(@names, 'designers')]) and (task/command[text()='/bin/ls -la'] or task/command[string-length(translate(text(),'.+*?^$()[]{}|\\\\','')) < string-length(text())])]", "Expression does not match expected value\n%s", expr);
    xmlFree(expr);
    free(user_struct);
    free(cmd_struct);
}