#include <criterion/criterion.h>
#include "command.c"

char abspath[256];
char args[256];

void set_up_get_abspath_from_cmdline(void){
    abspath[0] = '\0';
    args[0] = '\0';
}

Test(get_abspath_from_cmdline, absolute_path, .init = set_up_get_abspath_from_cmdline) {
    

    // Test case 1: Absolute path
    int result = get_abspath_from_cmdline("/home/user/file.txt", abspath, sizeof(abspath),args, sizeof(args));
    cr_assert_eq(result, 1, "Error: get_abspath_from_cmdline() failed to return 1 for an absolute path");
    cr_assert_str_eq(abspath, "/home/user/file.txt", "Error: get_abspath_from_cmdline() failed to return the correct absolute path");
    cr_assert_str_eq(args, "", "Error: get_abspath_from_cmdline() failed to return the correct arguments");

}

Test(get_abspath_from_cmdline, relative_path, .init = set_up_get_abspath_from_cmdline) {
    // Test case 2: Relative path
    int result = get_abspath_from_cmdline("file.txt", abspath, sizeof(abspath), args, sizeof(args));
    cr_assert_eq(result, 0, "Error: get_abspath_from_cmdline() failed to return 0 for a relative path");
    cr_assert_str_eq(abspath, "", "Error: get_abspath_from_cmdline() failed to return the correct absolute path for a relative path");
    cr_assert_str_eq(args, "", "Error: get_abspath_from_cmdline() failed to return the correct arguments");
}

Test(get_abspath_from_cmdline, relative_command_line, .init = set_up_get_abspath_from_cmdline) {
    // Test case 3: command line with arguments
    int result = get_abspath_from_cmdline("ls -l", abspath, sizeof(abspath), args, sizeof(args));
    cr_assert_eq(result, 0, "Error: get_abspath_from_cmdline() failed to return 0 for a command line with arguments");
    cr_assert_str_eq(abspath, "", "Error: get_abspath_from_cmdline() failed to return the correct absolute path for a command line with arguments");
    cr_assert_str_eq(args, "", "Error: get_abspath_from_cmdline() failed to return the correct arguments for a command line with arguments");

}

Test(get_abspath_from_cmdline, command_line_with_absolute_path, .init = set_up_get_abspath_from_cmdline) {
    // Test case 4: command line with arguments and absolute path
    int result = get_abspath_from_cmdline("/bin/ls -l", abspath, sizeof(abspath), args, sizeof(args));
    cr_assert_eq(result, 1, "Error: get_abspath_from_cmdline() failed to return 1 for a command line with arguments and an absolute path");
    cr_assert_str_eq(abspath, "/bin/ls", "Error: get_abspath_from_cmdline() failed to return the correct absolute path for a command line with arguments and an absolute path");
    cr_assert_str_eq(args, "-l", "Error: get_abspath_from_cmdline() failed to return the correct arguments for a command line with arguments and an absolute path");

}

Test(get_abspath_from_cmdline, command_line_with_space_in_absolute_path, .init = set_up_get_abspath_from_cmdline) {
    // Test case 5: command line with space in absolute path
    int result = get_abspath_from_cmdline("/home/us\\ er/file.txt -test", abspath, sizeof(abspath), args, sizeof(args));
    cr_assert_eq(result, 1, "Error: get_abspath_from_cmdline() failed to return 0 for a command line with arguments");
    cr_assert_str_eq(abspath, "/home/us er/file.txt", "Error: get_abspath_from_cmdline() failed to return the correct absolute path for a command line with arguments and an absolute path");
    cr_assert_str_eq(args, "-test", "Error: get_abspath_from_cmdline() failed to return the correct arguments for a command line with arguments and an absolute path");
}

Test(get_abspath_from_cmdline, command_line_with_wildcard, .init = set_up_get_abspath_from_cmdline) {
    // Test case 6: special case, command line with only wildcard
    int result = get_abspath_from_cmdline("*", abspath, sizeof(abspath), args, sizeof(args));
    cr_assert_eq(result, 1, "Error: get_abspath_from_cmdline() failed to return 0 for a command line with only wildcard");
    cr_assert_str_eq(abspath, "*", "Error: get_abspath_from_cmdline() failed to return the correct absolute path for a command line with only wildcard");
    cr_assert_str_eq(args, "", "Error: get_abspath_from_cmdline() failed to return the correct arguments for a command line with only wildcard");
}

Test(get_abspath_from_cmdline, command_line_double_wildcard, .init = set_up_get_abspath_from_cmdline) {
    // Test case 6: special case, command line with only double wildcard
    int result = get_abspath_from_cmdline("**", abspath, sizeof(abspath), args, sizeof(args));
    cr_assert_eq(result, 1, "Error: get_abspath_from_cmdline() failed to return 0 for a command line with only wildcard");
    cr_assert_str_eq(abspath, "*", "Error: get_abspath_from_cmdline() failed to return the correct absolute path for a command line with only wildcard");
    cr_assert_str_eq(args, ".*", "Error: get_abspath_from_cmdline() failed to return the correct arguments for a command line with only wildcard");
}

    
Test(get_abspath_from_cmdline, command_line_with_wildcard_and_args, .init = set_up_get_abspath_from_cmdline) {
    // Test case 7: special case, command line with only wildcard and args
    int result = get_abspath_from_cmdline("* -l", abspath, sizeof(abspath), args, sizeof(args));
    cr_assert_eq(result, 1, "Error: get_abspath_from_cmdline() failed to return 0 for a command line with only wildcard and args");
    cr_assert_str_eq(abspath, "*", "Error: get_abspath_from_cmdline() failed to return the correct absolute path for a command line with only wildcard and args");
    cr_assert_str_eq(args, "-l", "Error: get_abspath_from_cmdline() failed to return the correct arguments for a command line with only wildcard and args");
}

Test(get_abspath_from_cmdline, command_line_with_some_wildcard_and_args, .init = set_up_get_abspath_from_cmdline) {
    // Test case 8: special case, command line with some wildcard and args
    int result = get_abspath_from_cmdline("/*.txt -l", abspath, sizeof(abspath), args, sizeof(args));
    cr_assert_eq(result, 1, "Error: get_abspath_from_cmdline() failed to return 0 for a command line with some wildcard and args");
    cr_assert_str_eq(abspath, "/*.txt", "Error: get_abspath_from_cmdline() failed to return the correct absolute path for a command line with some wildcard and args");
    cr_assert_str_eq(args, "-l", "Error: get_abspath_from_cmdline() failed to return the correct arguments for a command line with some wildcard and args");
}


Test(join_argv, test_join) {
    char *argv[] = {"ls", "-l"};
    char result[ARG_MAX];
    result[0] = '\0';
    int len = 0;
    int res = join_argv(2, argv, result, ARG_MAX, &len);
    cr_assert_eq(res, 0, "Error: join_argv() failed to return 0");
    cr_assert_eq(len, 5, "Error: join_argv() failed to return the correct length");
    cr_assert_str_eq(result, "ls -l", "Error: join_argv() failed to return the correct string");
    
}

Test(join_cmd, test_join) {
    char *argv[2] = {"-a", "-l"};
    cmd_t *cmd = & (struct s_cmd) {
        .command = "/bin/ls",
        .argv = argv,
        .argc = 2
    };

    char result[ARG_MAX];
    int len = 0;
    int res = join_cmd(cmd, result, ARG_MAX, &len);
    cr_assert_eq(res, 0, "Error: join_cmd() failed to return 0");
    cr_assert_eq(len, 13, "Error: join_cmd() failed to return the correct length");
    cr_assert_str_eq(result, "/bin/ls -a -l", "Error: join_cmd() failed to return the correct string");


}

Test(may_be_regex, test_regex){
    char *test1 = "test";
    cr_assert_eq(may_be_regex(test1,strlen(test1)),0,"Error: may_be_regex() \"test\" failed to return false");
    char *test2 = "test*";
    cr_assert_eq(may_be_regex(test2,strlen(test2)),1,"Error: may_be_regex() \"test*\" failed to return true");
    char *test3 = "test?";
    cr_assert_eq(may_be_regex(test3,strlen(test3)),1,"Error: may_be_regex() \"test?\" failed to return true");
    char *test4 = "test[\\]";
    cr_assert_eq(may_be_regex(test4,strlen(test4)),1,"Error: may_be_regex() \"test[\\]\" failed to return true");
    char *realtest = "^-a -l$";
    cr_assert_eq(may_be_regex(realtest+1,strlen(realtest)-2),0,"Error: may_be_regex() \"^-a -l$\" failed to return false");
    char *test = "-(a|l)";
    cr_assert_eq(may_be_regex(test,strlen(test)),1,"Error: may_be_regex() \"-(a|l)\" failed to return true");
}