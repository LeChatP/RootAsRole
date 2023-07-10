#ifndef PARAMS_H
#define PARAMS_H

#include <libxml/xpath.h>
#include <sys/capability.h>

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
    cap_iab_t iab;
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
char *params_set_role(char *p_role);

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