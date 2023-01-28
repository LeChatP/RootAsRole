#define _GNU_SOURCE
#include <stdlib.h>
#include <error.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <grp.h>

#include <errno.h>
#include <linux/limits.h>
#include <syslog.h>
#include "env.h"
#include "xml_manager.h"
#include "user.h"
#include "capabilities.h"

#ifndef SR_VERSION
#define SR_VERSION "3.0"
#endif

typedef struct _arguments_t {
	char *role;
	int info;
	int version;
	int help;
} arguments_t;

extern char **environ;

/**
 * @brief parse the command line arguments where command is the rest of the command line like this sr (options) command [args]
 * @param argc number of arguments
 * @param argv array of arguments
 * @param args structure to store the parsed arguments
 * @return 0 on success, -1 on error
*/
int parse_arguments(int *argc, char **argv[], arguments_t *args)
{
	int c;
	static struct option long_options[] = {
		{ "role", required_argument, 0, 'r' },
		{ "info", no_argument, 0, 'i' },
		{ "version", no_argument, 0, 'v' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((c = getopt_long(*argc, *argv, "+r:ivh", long_options, NULL)) !=
	       -1) {
		switch (c) {
		case 'r':
			args->role = optarg;
			break;
		case 'i':
			args->info = 1;
			break;
		case 'v':
			args->version = 1;
			break;
		case 'h':
			args->help = 1;
			break;
		default:
			return 0;
		}
	}
	*argc -= optind;
	*argv += optind;
	return 1;
}

char *find_absolute_path_from_env(char *file)
{
	char *path = strdup(getenv("PATH"));
	if (path == NULL) {
		return NULL;
	}
	char *token = strtok(path, ":");
	char *full_path = NULL;
	while (token != NULL) {
		full_path = malloc(strlen(token) + strlen(file) + 2);
		snprintf(full_path, strlen(token) + strlen(file) + 2, "%s/%s",
			 token, file);
		if (access(full_path, X_OK) == 0) {
			return full_path;
		}
		free(full_path);
		token = strtok(NULL, ":");
	}
	return NULL;
}

void sr_execve(char *command, int p_argc, char *p_argv[], char *p_envp[])
{
	int i = execve(command, p_argv, p_envp);
	if (i == -1 || errno == ENOEXEC) {
		const char **nargv;

		nargv = reallocarray(NULL, p_argc + 1, sizeof(char *));
		if (nargv != NULL) {
			nargv[0] = "sh";
			nargv[1] = command;
			memcpy(nargv + 2, p_argv, p_argc * sizeof(char *));
			execve("/bin/sh", (char **)nargv, p_envp);
			free(nargv);
		}
	}
}

/**
 * Set uid from options on current process
*/
int sr_setuid(options_t options)
{
	if (options->setuid != NULL) {
		if (setuid_effective(1)) {
			error(0, 0, "Unable to setuid capability");
			syslog(LOG_ERR, "Unable to setuid capability");
			return -1;
		}
		uid_t uid = get_user_id(options->setuid);
		if (uid == (uid_t)-1) {
			error(0, 0,
			      "Unable to retrieve the uid from the user/number '%s'",
			      options->setuid);
			syslog(LOG_ERR,
			       "Unable to retrieve the uid from the user/number '%s'",
			       options->setuid);
			return -1;
		}
		if (setuid(uid)) {
			perror("setuid");
			syslog(LOG_ERR, "Unable to setuid");
			return -1;
		}
		if (setuid_effective(0)) {
			error(0, 0, "Unable to setuid capability");
			syslog(LOG_ERR, "Unable to setuid capability");
			return -1;
		}
	}
	return 0;
}

/**
 * set gid from options on current process
*/
int sr_setgid(options_t options)
{
	if (options->setgid != NULL) {
		if (setgid_effective(1)) {
			error(0, 0, "Unable to setuid capability");
			syslog(LOG_ERR, "Unable to setuid capability");
			return -1;
		}
		gid_t gid = get_group_id_from_name(options->setgid);
		if (gid == (gid_t)-1) {
			error(0, 0,
			      "Unable to retrieve the uid from the user/number '%s'",
			      options->setuid);
			syslog(LOG_ERR,
			       "Unable to retrieve the uid from the user/number '%s'",
			       options->setuid);
			return -1;
		}
		if (setgid(gid)) {
			perror("setgid");
			syslog(LOG_ERR, "Unable to setgid");
			return -1;
		}
		if (setgroups(1,&gid)) {
			perror("setgroups");
			syslog(LOG_ERR, "Unable to setgroups");
			return -1;
		}
		if (setgid_effective(0)) {
			error(0, 0, "Unable to setuid capability");
			syslog(LOG_ERR, "Unable to setuid capability");
			return -1;
		}
	}
	return 0;
}

/**
 * Set capabilities on current process from options
*/
int sr_setcaps(cap_iab_t iab)
{
	if (setpcap_effective(1)) {
		error(0, 0, "Unable to setpcap capability");
		syslog(LOG_ERR, "Unable to setpcap capability");
		return -1;
	}
	if (cap_iab_set_proc(iab)) {
		error(0, 0, "Unable to set capabilities");
		syslog(LOG_ERR, "Unable to set capabilities");
		return -1;
	}
	if (setpcap_effective(0)) {
		error(0, 0, "Unable to setpcap capability");
		syslog(LOG_ERR, "Unable to setpcap capability");
		return -1;
	}
	return 0;
}

/**
 * Jail root as a non super user
*/
int sr_noroot(options_t options)
{
	if (options->no_root) {
		if (activates_securebits()) {
			error(0, 0, "Unable to activate securebits");
			syslog(LOG_ERR, "Unable to activate securebits");
			return -1;
		}
	}
	return 0;
}

/**
 * @brief main function of the SR module
*/
int main(int argc, char *argv[])
{
	arguments_t arguments = { NULL, 0, 0, 0 };
	char *callpath = argv[0];
	if (!parse_arguments(&argc, &argv, &arguments) || arguments.help ||
	    (argc == 0 && !arguments.info)) {
		printf("Usage: %s [options] [command [args]]\n", callpath);
		printf("Options:\n");
		printf("  -r, --role <role>      Role to use\n");
		printf("  -i, --info             Display rights of executor\n");
		printf("  -v, --version          Display version\n");
		printf("  -h, --help             Display this help\n");
		return 0;
	} else if (arguments.version) {
		printf("SR version %s\n", SR_VERSION);
		return 0;
	}
	openlog("sr", LOG_PID, LOG_AUTH);
	cap_iab_t iab = NULL;
	options_t options = NULL;
	uid_t euid = geteuid();
	char *user = get_username(euid);
	if (user == NULL) {
		error(0, 0, "Unable to retrieve the username of the executor");
		goto free_error;
	}
	if (!pam_authenticate_user(user)) {
		error(0, 0, "Authentication failed");
		goto free_error;
	}
	char *command = NULL;
	gid_t egid = get_group_id(euid);
	char **groups = NULL;
	int nb_groups = 0;
	if (get_group_names(user, egid, &nb_groups, &groups)) {
		error(0, 0, "Unable to retrieve the groups of the executor");
		goto free_error;
	}

	if (arguments.info) {
		if (arguments.role == NULL)
			print_rights(user, nb_groups, groups, RESTRICTED);
		else {
			print_rights_role(arguments.role, user, nb_groups,
					  groups, RESTRICTED);
		}

	} else if (arguments.role){
		command = strndup(argv[0], PATH_MAX);
		int ret = get_settings_from_config_role(arguments.role, user, nb_groups,
						 groups, command, &iab,
						 &options);
		if (!ret) {
			syslog(LOG_ERR,
			       "User '%s' tries to execute '%s', without permission",
				   user, command);
			error(0, 0, "Permission denied");
			goto free_error;
		}		   	
	} else if (strnlen(argv[0], PATH_MAX) < PATH_MAX) {
		command = strndup(argv[0], PATH_MAX);
		int ret = get_settings_from_config(user, nb_groups, groups,
						   command, &iab, &options);
		if (!ret) {
			syslog(LOG_ERR,
			       "User '%s' tries to execute '%s', without permission",
			       user, command);
			error(0, 0, "Permission denied");
			goto free_error;
		}
	} else {
		error(0, 0, "Command too long");
		syslog(LOG_ERR,
		       "User '%s' failed to execute '%s', command too long",
		       user, command);
		goto free_error;
	}
	
	syslog(LOG_INFO,
			"User '%s' tries to execute '%s' with role '%s'", user,
			command, options->role);
	if (sr_noroot(options) || sr_setuid(options) ||
		sr_setgid(options) || sr_setcaps(iab)) {
		goto free_error;
	}

	char **env = NULL;
	int res = filter_env_vars(environ, options->env_keep,
					options->env_check, &env);
	if (res > 0) {
		error(0, 0, "Unable to filter environment variables");
		syslog(LOG_ERR,
				"Unable to filter environment variables");
		goto free_error;
	}
	res = secure_path(getenv("PATH"), options->path);
	if (!res) {
		error(0, 0, "Unable to secure path");
		syslog(LOG_ERR, "Unable to secure path");
		goto free_error;
	}

	command = realpath(argv[0], NULL);
	if (errno == ENAMETOOLONG) {
		error(0, 0, "Path too long");
		syslog(LOG_ERR,
				"User '%s' failed to execute '%s', path too long",
				user, command);
		goto free_error;
	}
	if (access(command, X_OK) != 0) {
		command = find_absolute_path_from_env(argv[0]);
		if (command == NULL) {
			syslog(LOG_ERR,
					"User '%s' failed to execute '%s', command not found",
					user, command);
			error(0, 0, "%s : Command not found", argv[0]);
			goto free_error;
		}
	} else {
		error(0, 0, "%s : Command not found", argv[0]);
		syslog(LOG_ERR,
				"User '%s' failed to execute '%s', command not found",
				user, command);
		goto free_error;
	}
	sr_execve(command, argc, argv, env);

free_error:
	if (command != NULL)
		free(command);
	if (iab != NULL)
		cap_free(iab);
	if (options != NULL)
		free_options(options);
	if (user != NULL)
		free(user);
	if (groups != NULL)
		free_group_names(nb_groups, groups);
	return 0;
}
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