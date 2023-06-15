#ifndef COMMAND_H
#define COMMAND_H
#include "params.h"

cmd_t *get_cmd(int argc, char *argv[]);

int get_abspath_from_cmdline(const char *content, char *abspath, int size, char *args, int size_args);

int join_argv(int argc, char **argv, char *res, int res_size, int *res_len);

int join_cmd(cmd_t *cmd, char *res, int res_size, int *res_len);

int may_be_regex(const char *str, int size);

#endif // COMMAND_H