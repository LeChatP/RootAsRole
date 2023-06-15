#include <criterion/criterion.h>
#include "params.c"

Test(params_set_role, sets_role) {
    const char *tmp_role = "admin";
    char *result = params_set_role(tmp_role);
    cr_assert_str_eq(result, role, "params_set_role did not set the role correctly");
}

Test(params_get_role, returns_role) {
    const char *tmp_role = "admin";
    params_set_role(tmp_role);
    char *result = params_get_role();
    cr_assert_str_eq(result, tmp_role, "params_get_role did not return the correct role");
}

Test(params_user_posix_set, sets_user_posix) {
    char *tmp_user_posix = "user1";
    char *tmp_user_posix_groups[] = {"group1", "group2"};
    const int tmp_user_posix_nb_groups = 2;

    user_t *result = params_user_posix_set(tmp_user_posix, tmp_user_posix_nb_groups, tmp_user_posix_groups);
    cr_assert_str_eq(result->name, tmp_user_posix, "params_set_user_posix did not set the user_posix correctly");
    cr_assert_eq(result->nb_groups, tmp_user_posix_nb_groups, "params_set_user_posix did not set the user_posix correctly");
    cr_assert_str_eq(result->groups[0], tmp_user_posix_groups[0], "params_set_user_posix did not set the user_posix correctly");
    cr_assert_str_eq(result->groups[1], tmp_user_posix_groups[1], "params_set_user_posix did not set the user_posix correctly");
    
}

Test(params_command_set, set_command_test) {
    char *tmp_command = "/bin/ls";
    char *tmp_argv[] = {"ls", "-l", NULL};
    const int tmp_argc = 2;

    cmd_t *result = params_command_set(tmp_command, tmp_argc, tmp_argv);
    cr_assert_str_eq(result->command, tmp_command, "params_set_command did not set the command correctly");
    cr_assert_eq(result->argc, tmp_argc, "params_set_command did not set the command correctly");
    cr_assert_str_eq(result->argv[0], tmp_argv[0], "params_set_command did not set the command correctly");
    cr_assert_str_eq(result->argv[1], tmp_argv[1], "params_set_command did not set the command correctly");
}

Test(params_command_get, get_command_test){
    char *tmp_command = "/bin/ls";
    char *tmp_argv[] = {"ls", "-l", NULL};
    const int tmp_argc = 2;

    cmd_t *element = params_command_set(tmp_command, tmp_argc, tmp_argv);
    cmd_t *result = params_command_get();
    cr_assert_str_eq(result->command, tmp_command, "params_get_command did not get the command correctly");
    cr_assert_eq(result->argc, tmp_argc, "params_get_command did not get the command correctly");
    cr_assert_str_eq(result->argv[0], tmp_argv[0], "params_get_command did not get the command correctly");
    cr_assert_str_eq(result->argv[1], tmp_argv[1], "params_get_command did not get the command correctly");
    cr_assert_eq(result, element, "params_get_command did not get the command correctly");
}