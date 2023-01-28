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
    char *role;
    char *setuid;
    char *setgid;
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
 * @brief Get every configuration settings from the xml file according to the role, the user, the groups and the command
 * @param role The role of query
 * @param user The user of query
 * @param nb_groups The number of groups of the user
 * @param groups The groups of the user
 * @param command The command asked by the user
 * @param p_iab The capabilities to set
 * @param p_options The options to set
 * @return 1 if the user is allowed to execute the command, 0 otherwise
*/
int get_settings_from_config_role(char* role, char *user, int nb_groups, char **groups, char *command, cap_iab_t *p_iab, options_t *p_options);

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
/* 
 * 
 * Copyright Ahmad Samer Wazan <ahmad-samer.wazan@irit.fr>, 2022
 * Copyright Eddie Billoir <eddie.billoir@irit.fr>, 2022
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.  */