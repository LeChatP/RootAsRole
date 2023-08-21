/*
 * <user.h>
 *
 * This file contains the signatures of user management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#ifndef USER_H_INCLUDED
#define USER_H_INCLUDED
#ifndef LOGIN_NAME_MAX
# ifdef _POSIX_LOGIN_NAME_MAX
#  define LOGIN_NAME_MAX _POSIX_LOGIN_NAME_MAX
# else
#  define LOGIN_NAME_MAX 256
# endif
#endif

#include <sys/types.h>
#include "params.h"

/**
 * @brief Get user_t object from POSIX system context
 * @return user_t object
*/
user_t *user_posix_get();

/**
 * @brief Free the memory of a POSIX user_t object
*/
void user_posix_free(user_t *user);

/**
 * @brief Get the current username
 * @return The current username, to be freed with free()
*/
char *get_current_username();

/*
Retrieve the name of a user id.
Return the username or NULL if an error has occured.
The username should be deallocated with free afterwards.
*/
char *get_username(uid_t uid);

/*
Retrieve the user id of a given username or from integer.
*/
uid_t get_user_id(const char *username);

/*
Retrieve the user group id of the user_id uid.
Return the user group id, or -1 on failure.
*/
gid_t get_group_id(uid_t uid);

gid_t get_group_id_from_name(const char *group);

int get_group_ids_from_names(char *groups_str, int *nb_groups, gid_t **groups);

/*
Init and close a pam session to authenticate a given user.
Return 1 if the authentication succeeded, 0 otherwise. Return -1 if an error
occured.
*/
int pam_authenticate_user(const char *user);

/* 
Retrieve the list of names of group for a given user.
The main group id of the user must be known
Allocate an array of array of char that must be deallocate afterwards.
Return 0 on success and -1 on failure.
*/
int get_group_names(const char *user, gid_t group, int *nb_groups,
		    char ***groups);

/**
 * Free the memory of groups allocated by get_group_names
*/
void free_group_names(int nb_groups, char **groups);

/**
 * @brief Check if the user should enter his password again within the timeout
 * @param user The user name
 * @param timeout The timeout in seconds
 * @return 1 if the user should enter his password again, 0 otherwise
*/
int check_timestamp_timeout(const char *user, const unsigned long timeout);

/**
 * @brief Set the timestamp for the user
 * @param user The user name
 * @return 1 if the timestamp was set, 0 otherwise
*/
int set_timestamp_user(const char *user);

#endif // USER_H_INCLUDED

/* 
 * 
 * Copyright Guillaume Daumas <guillaume.daumas@univ-tlse3.fr>, 2018
 * Copyright Ahmad Samer Wazan <ahmad-samer.wazan@irit.fr>, 2018
 * Copyright Rémi Venant <remi.venant@irit.fr>, 2018
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
