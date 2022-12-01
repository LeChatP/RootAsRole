#ifndef XML_MANAGER_H
#define XML_MANAGER_H

#include <sys/capability.h>
#include <libxml/parser.h>

#define XML_FILE "/etc/security/rootasrole.xml"

#define RESTRICTED 1
#define UNRESTRICTED 0

typedef struct s_session {
    cap_iab_t *iab;
    char **envp;
    int no_root;
} session_t;



cap_iab_t get_capabilities_from_config(char *user, int nb_groups, char **groups, char *command);

void print_full_role(char *role);

void print_full_roles();

void print_rights(char *user, int nb_groups, char **groups, int restricted);

void print_rights_role(char *role, char *user, int nb_groups, char **groups, int restricted);

#endif