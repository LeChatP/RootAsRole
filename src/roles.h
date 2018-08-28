/*
 * <roles.h>
 *
 * This file contains the signatures of roles management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#ifndef ROLES_H_INCLUDED
#define ROLES_H_INCLUDED
#include "sr_constants.h"
#include <sys/capability.h>

#define USER_CAP_FILE_ROLE	"/etc/security/capabilityRole.xml"

/* list of capabilities structure */
typedef struct s_role_capabilities_t {
    int nb_caps;
    cap_value_t *capabilities;
} role_capabilities_t;
/* Role structure */
typedef struct s_user_role_capabilities_t {
    char *role;
    char *user;
    int nb_groups;
    char **groups;
    char *command;
    role_capabilities_t caps;
} user_role_capabilities_t;

/* 
Initialize a user_role_capabilities_t for a given role role, and
for the given user and the groups.
Every entry in the struct is a copy in memory.
The structure must be deallocated with free_urc() afterwards.
Return 0 on success, -1 on failure.
*/
int init_urc(const char *role, const char *user, int nb_groups,
             char **groups, user_role_capabilities_t **urc);

/* 
Initialize a user_role_capabilities_t for a given role role,
for a specific command command, and
for the given user and the groups.
Every entry in the struct is a copy in memory.
The structure must be deallocated with free_urc() afterwards.
Return 0 on success, -1 on failure.
*/
int init_urc_command(const char *role, const char *command, const char *user,
                    int nb_groups, char **groups,
                    user_role_capabilities_t **urc);

/* 
Deallocate a user_role_capabilities_t
Always return 0.
*/
int free_urc(user_role_capabilities_t *urc);

/*
Given an urc (user/groups-role-command), check in the configuration if the
role can be used with that user or these groups (and the given command if
require). If true, set the capabilities provided by the role in the urc.
return :
0: success
-2 (EINVAL): missing mandatory parameter (either role or user)
-3 (ENOENT): missing configuration file
-4 (EINVAL): the configuration file is invalid
-5 (EINVAL): the role does not exists
-6 (EACCES): the role cannot be use with that user or his groups or with 
that command
-1 other error (errno will be set)
*/
int get_capabilities(user_role_capabilities_t *urc);

/*
Given an urc (user/groups-role), print if he/she can use the role 
(whatever the command is in urc). In this case, and if needed, 
also print the commands he/she can use with that role.
return :
0: success
-2 (EINVAL): missing mandatory parameter (either role or user)
-3 (ENOENT): missing configuration file
-4 (EINVAL): the configuration file is invalid
-5 (EINVAL): the role does not exists
-6 (EACCES): the role cannot be use with that user or his groups or with 
that command
-1 other error (errno will be set)
*/
int print_capabilities(user_role_capabilities_t *urc);

/* 
Printout on stdout a user_role_capabilities_t
*/
void print_urc(const user_role_capabilities_t *urc);

#endif // ROLES_H_INCLUDED

/* 
 * 
 * Copyright Guillaume Daumas <guillaume.daumas@univ-tlse3.fr>, 2018
 * Copyright Ahmad Samer Wazan <ahmad-samer.wazan@irit.fr>, 2018
 * Copyright Rémi Venant <remi.venant@irit.fr>, 2018
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
