#ifndef XML_MANAGER_H
#define XML_MANAGER_H

#include <sys/capability.h>

#define XML_FILE "/etc/security/rootasrole.xml"

#define RESTRICTED 1
#define UNRESTRICTED 0

struct s_options {
    char** env_keep;
    char** env_check;
    char* path;
    int no_root;
    int bounding;
};

typedef struct s_options *options_t;

int get_settings_from_config(char *user, int nb_groups, char **groups, char *command, cap_iab_t *p_iab, options_t *p_options);

void print_full_role(char *role);

void print_full_roles();

void print_rights(char *user, int nb_groups, char **groups, int restricted);

void print_rights_role(char *role, char *user, int nb_groups, char **groups, int restricted);

#endif