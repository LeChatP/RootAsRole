#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#include <criterion/criterion.h>
#include "env.c"

Test(filter_env_vars, returns_1_when_envp_is_null) {
    char **envp = NULL;
    char **whitelist = NULL;
    char **checklist = NULL;
    char **new_envp = NULL;
    int result = filter_env_vars(envp, whitelist, checklist, &new_envp);
    cr_assert_eq(result, 1);
}

Test(filter_env_vars, returns_0_when_env_var_name_is_path) {
    char *envp[] = {"PATH=/usr/bin:/bin", NULL};
    char **whitelist = NULL;
    char **checklist = NULL;
    char **new_envp = NULL;
    int result = filter_env_vars(envp, whitelist, checklist, &new_envp);
    cr_assert_eq(result, 0);
    cr_assert_str_eq(new_envp[0], "PATH=/usr/bin:/bin");
    cr_assert_null(new_envp[1]);
    free(new_envp);
}

Test(filter_env_vars, returns_0_when_env_var_name_is_in_checklist_and_value_passes_check) {
    char *envp[] = {"MY_VAR=1234", NULL};
    char *checklist[] = {"MY_VAR", NULL};
    char **whitelist = NULL;
    char **new_envp = NULL;
    int result = filter_env_vars(envp, whitelist, checklist, &new_envp);
    cr_assert_eq(result, 0);
    cr_assert_str_eq(new_envp[0], "MY_VAR=1234");
    cr_assert_null(new_envp[1]);
    free(new_envp);
}

Test(filter_env_vars, returns_0_when_env_var_name_is_in_whitelist) {
    char *envp[] = {"MY_VAR=1234", NULL};
    char *whitelist[] = {"MY_VAR", NULL};
    char **checklist = NULL;
    char **new_envp = NULL;
    int result = filter_env_vars(envp, whitelist, checklist, &new_envp);
    cr_assert_eq(result, 0);
    cr_assert_str_eq(new_envp[0], "MY_VAR=1234");
    cr_assert_null(new_envp[1]);
    free(new_envp);
}