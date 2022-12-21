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

/**
 * @brief free the options
*/
void free_options(options_t options);

/**
 * @brief Get every configuration settings from the xml file according to the user, the groups and the command
 * @param user The user of query
 * @param nb_groups The number of groups of the user
 * @param groups The groups of the user
 * @param command The command asked by the user
 * @param p_iab The capabilities to set
 * @param p_options The options to set
 * @return 1 if the user is allowed to execute the command, 0 otherwise
*/
int get_settings_from_config(char *user, int nb_groups, char **groups, char *command, cap_iab_t *p_iab, options_t *p_options);

/**
 * @brief Print informations of a role
*/
void print_full_role(char *role);

/**
 * @brief Print all roles
*/
void print_full_roles();

/**
 * @brief Print the rights of all accessible roles for a user
 * @param user The user to check
 * @param nb_groups The number of groups of the user
 * @param groups The groups of the user
 * @param restricted 1 to display limited information, 0 to display all information
*/
void print_rights(char *user, int nb_groups, char **groups, int restricted);

/**
 * @brief Print the rights of a role if user is in the role
 * @param role The role to print
 * @param user The user to check
 * @param nb_groups The number of groups of the user
 * @param groups The groups of the user
 * @param restricted 1 to display limited information, 0 to display all information
*/
void print_rights_role(char *role, char *user, int nb_groups, char **groups, int restricted);

#endif