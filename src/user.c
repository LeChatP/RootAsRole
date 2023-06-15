/*
 * <user.c>
 *
 * This file contains the definitions of user management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#include "user.h"
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <grp.h>
#include <syslog.h>

/******************************************************************************
 *                      PUBLIC FUNCTIONS DEFINITION                           *
 ******************************************************************************/

/**
 * @brief Get user_t object from POSIX system context
*/
user_t *user_posix_get(){
	uid_t euid = geteuid();
	char *user = get_username(euid);
	if (user == NULL) {
		error(0, 0, "Unable to retrieve the username of the executor");
		goto free_error;
	}
	gid_t egid = get_group_id(euid);
	char **groups = NULL;
	int nb_groups = 0;
	if (get_group_names(user, egid, &nb_groups, &groups)) {
		error(0, 0, "Unable to retrieve the groups of the executor");
		goto free_error;
	}
	return params_user_posix_set(user, nb_groups, groups);
	free_error:
	return NULL;
}

/**
 * @brief Free the memory of a user_t object
*/
void user_posix_free(user_t *user){
	if(user == NULL){
		return;
	}
	if(user->name != NULL)
		free(user->name);
	if(user->groups != NULL)
		free_group_names(user->nb_groups, user->groups);
}

char *get_current_username(){
	uid_t euid = geteuid();
	return get_username(euid);
}

/*
Retrieve the name of a user id.
Return the username or NULL if an error has occured.
The username should be deallocated with free afterwards.
*/
char *get_username(uid_t uid)
{
	char *username;
	int username_len;
	struct passwd *info_user;

	if ((info_user = getpwuid(uid)) == NULL || info_user->pw_name == NULL) {
		return NULL;
	} else {
		//We do not have to deallocate info_user, as it points to a static
		//memory adress
		username_len = strlen(info_user->pw_name) + 1;
		if ((username = malloc(username_len * sizeof(char))) == NULL) {
			return NULL;
		}
		strncpy(username, info_user->pw_name, username_len);
		return username;
	}
}

/*
Retrieve the user id of a given username or from integer.
*/
uid_t get_user_id(const char *username){
	struct passwd *info_user;

	if ((info_user = getpwnam(username)) == NULL) {
		//check username as integer
		char *endptr = NULL;
        long int iuid = strtol(username, &endptr, 10);
		if (endptr == username || *endptr != '\0' || iuid < 0 || iuid > (uid_t)-1) {
			return -1;
		}else {
			return (uid_t)iuid;
		}
	} else {
		//We do not have to deallocate info_user, as it points to a static
		//memory adress
		return info_user->pw_uid;
	}

}

/*
Retrieve the user group id of the user_id uid.
Return the user group id, or -1 on failure.
*/
gid_t get_group_id_from_name(const char *group)
{
	struct group *info_group;

	if ((info_group = getgrnam(group)) == NULL) {
		//check group as integer
		char *endptr = NULL;
		long int igid = strtol(group, &endptr, 10);
		if (endptr == group || *endptr != '\0' || igid < 0 || igid > (uid_t)-1) {
			return -1;
		}else {
			return (gid_t)igid;
		}
	} else {
		//We do not have to deallocate info_user, as it points to a static
		//memory adress
		return info_group->gr_gid;
	}
}

/**
 * @brief retrieve multiple gid from comma separated string
 * @param groups_str comma separated string of group names
 * @param nb_groups number of groups
 * @param groups array of group
 * @return 0 on success, -1 on failure
*/
int get_group_ids_from_names(const char *groups_str, int *nb_groups, gid_t *groups){
	char *groups_str_copy = strdup(groups_str);
	*nb_groups = 1;
	for (int i=0; groups_str_copy[i] != '\0'; i++) {
		if (groups_str_copy[i] == ',') {
			(*nb_groups)++;
		}
	}
	groups = malloc(*nb_groups * sizeof(gid_t));
	if (groups == NULL) {
		syslog(LOG_ERR, "Unable to allocate memory for groups");
		return -1;
	}
	char *group = strtok(groups_str_copy, ",");
	for (int i=0; i<*nb_groups; i++){
		groups[i] = get_group_id_from_name(group);
		if(groups[i] == -1){
			syslog(LOG_ERR, "Unable to retrieve group id of group %s", group);
			return -1;
		}
		group = strtok(NULL, ",");
	}
	return 0;
}

/*
Retrieve the user group id of the user_id uid.
Return the user group id, or -1 on failure.
*/
gid_t get_group_id(uid_t uid)
{
	struct passwd *info_user;

	if ((info_user = getpwuid(uid)) == NULL) {
		return -1;
	} else {
		//We do not have to deallocate info_user, as it points to a static
		//memory adress
		return info_user->pw_gid;
	}
}

/*
Init and close a pam session to authenticate a given user.
Return 1 if the authentication succeeded, 0 otherwise. Return -1 if an error
occured.
*/
int pam_authenticate_user(const char *user)
{
	pam_handle_t *pamh = NULL;
	const struct pam_conv conv = { misc_conv, NULL };
	int pamret;
	int return_code = 0;
	openlog("sr", LOG_PID, LOG_AUTH);

	//Initiate the pam transaction to check the user
	if ((pamret = pam_start("sr", user, &conv, &pamh)) !=
	    PAM_SUCCESS) {
		return_code = -1; //An error occured
		syslog(LOG_ERR, "failed to start pam transaction: %s",
		       pam_strerror(pamh, pamret));
		goto close_pam;
	}

	//Establish the credential, then
	if ((pamret = pam_setcred(pamh, 0)) != PAM_SUCCESS){
		syslog(LOG_ERR, "failed to set credentials: %s",
		       pam_strerror(pamh, pamret));
		goto close_pam;
	}
	//Authenticate the user with password,	   
	if ((pamret = pam_authenticate(pamh, 0)) != PAM_SUCCESS){
		syslog(LOG_ERR, "failed to authenticate: %s",
		       pam_strerror(pamh, pamret));
		goto close_pam;
	}
	//Then check if the user if valid
	if ((pamret = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS) {
		syslog(LOG_ERR, "failed to check account: %s",
		       pam_strerror(pamh, pamret));
		goto close_pam;
	}

	//Authentication succeeded
	return_code = 1;

close_pam:
	// close PAM (end session)
	if (pam_end(pamh, pamret) != PAM_SUCCESS) { //An Error occured
		syslog(LOG_ERR, "failed to release pam transaction");
		pamh = NULL;
		return_code = -1;
	}
	return return_code;
}

/* 
Retrieve the list of names of group for a given user.
The main group id of the user must be known
Allocate an array of array of char that must be deallocate afterwards.
Return 0 on success and -1 on failure.
*/
int get_group_names(const char *user, gid_t group, int *nb_groups,
		    char ***groups)
{
	int return_code = -1;
	int ng = 1;
	gid_t *gps = NULL;
	int ret_ggl;
	int i;

	*nb_groups = 0;
	*groups = NULL;

	//Retrieve group_ids
	if ((gps = malloc(ng * sizeof(gid_t))) == NULL)
		return -1;
	if ((ret_ggl = getgrouplist(user, group, gps, &ng)) == -1) {
		gid_t *tmp;
		if ((tmp = realloc(gps, ng * sizeof(gid_t))) == NULL){
			goto on_error;
		}
		gps = tmp;
			
		if ((ret_ggl = getgrouplist(user, group, gps, &ng)) == -1) {
			goto on_error;
		}
	}
	//Enforce consistency in results
	if (ret_ggl != ng)
		goto on_error;
	*nb_groups = ng;

	//Retrieve group name for all group ids
	if ((*groups = (char **)malloc((ng+1) * sizeof(char *))) == NULL)
		return -1;
	for (i = 0; i < ng; i++) {
		int gpname_len;
		char *gpname;
		struct group *rec = getgrgid(gps[i]); //Retrieve group info
		if (rec == NULL || rec->gr_name == NULL) {
			perror("Cannot retrieve group info or group name");
			goto on_error;
		}
		//Copy group name
		gpname_len = strlen(rec->gr_name) + 1;
		if ((gpname = malloc(gpname_len * sizeof(char))) == NULL)
			goto on_error;
		strncpy(gpname, rec->gr_name, gpname_len);
		(*groups)[i] = gpname;
	}

	return_code = 0;
	goto free_rsc;

on_error:
	if (*groups != NULL) {
		free(*groups);
		*groups = NULL;
	}
	*nb_groups = 0;
free_rsc:
	if (gps != NULL)
		free(gps);
	return return_code;
}

void free_group_names(int nb_groups, char **groups){
	int i;
	for (i = 0; i < nb_groups; i++) {
		free(groups[i]);
	}
	free(groups);
}

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
