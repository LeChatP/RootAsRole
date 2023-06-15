#ifndef PARAMS_H
#define PARAMS_H

#include <libxml/xpath.h>

struct s_cmd {
    char *command;
    int argc;
    char **argv;
};

typedef struct s_cmd cmd_t;

struct s_user {
    int nb_groups;
    char **groups;
    char *name;
};

typedef struct s_user user_t;

struct s_settings {
    char** env_keep;
    char** env_check;
    char *path;
    char *role;
    char *setuid;
    char *setgid;
    int no_root;
    int bounding;
};

typedef struct s_settings settings_t;

/**
 * @brief Set the POSIX user variables
 * @param name The input user name
 * @param nb_groups The input user nb_groups
 * @param groups The input user groups
 * @return static user_t on success, NULL on error
*/
user_t *params_user_posix_set(char *name,int nb_groups,char **groups);

user_t *params_user_get();

/**
 * @brief Set the command variables
 * @param command The input command absolute path
 * @param argc The input command argc
 * @param argv The input command argv
 * @param cmd The output command object
 * @return static cmd_t on success, NULL on error
*/
cmd_t *params_command_set(char *command, int argc, char **argv);

cmd_t *params_command_get();

/**
 * @brief Set the role variable
*/
char *params_set_role(const char *p_role);

/**
 * @brief Get the role param
 * @return The role param
*/
char *params_get_role();

void set_default_options(settings_t *settings);
void options_assign(settings_t *dst, settings_t *src);
void get_options_from_config(xmlNodePtr task_node, settings_t *options);
void free_options(settings_t *options);

#endif /* !PARAMS_H */