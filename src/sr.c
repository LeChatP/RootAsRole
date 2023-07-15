#define _GNU_SOURCE
#define __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1

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
#include "command.h"

#ifndef SR_VERSION
#define SR_VERSION "3.0"
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
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
	if (*argc < 2 ) {
		return -1;
	}
	//check if argument array is correctly terminated
	if ((*argv)[*argc] != NULL) {
		return -1;
	}

	while ((c = getopt_long(*argc, *argv, "+r:ivh", long_options, NULL)) != // Flawfinder: ignore
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

void safe_memcpy(void* dest, size_t dest_size, const void* src, size_t count) {
    if (dest == NULL || src == NULL || dest_size < count) {
        // Handle error: Invalid arguments or buffer overflow
        return;
    }

    memcpy(dest, src, count); // Flawfinder: ignore
}


int sr_execve(char *command, int p_argc, char *p_argv[], char *p_envp[])
{
	int ret = 0;
	int i = execve(command, p_argv, p_envp);
	if (i == -1 || errno == ENOEXEC) {
		const char **nargv;
		size_t nargc = p_argc + 1;
		nargv = reallocarray(NULL, nargc, sizeof(char *));
		if (nargv != NULL) {
			nargv[0] = "sh";
			nargv[1] = command;
			safe_memcpy(nargv + 2, nargc, p_argv, p_argc * sizeof(char *)); 
			nargv[p_argc] = NULL;
			ret = execve("/bin/sh", (char **)nargv, p_envp);
			printf("sr: %s : %s", p_argv[0], strerror(errno));
			free(nargv);
		}
	}
	return ret;
}

/**
 * Set uid from options on current process
*/
int sr_setuid(settings_t *options)
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
int sr_setgid(settings_t *options)
{
	if (options->setgid != NULL) {
		if (setgid_effective(1)) {
			error(0, 0, "Unable to setgid capability");
			syslog(LOG_ERR, "Unable to setgid capability");
			return -1;
		}
		int nb_groups = 0;
		gid_t *groups = NULL;
		int result = get_group_ids_from_names(options->setgid,
						     &nb_groups, &groups);
		if (result) {
			error(0, 0,
			      "Unable to retrieve the gids from the groupnames/numbers '%s'",
			      options->setgid);
			syslog(LOG_ERR,
			       "Unable to retrieve the gids from the groupnames/numbers '%s'",
			       options->setgid);
			return -1;
		}
		if (setgid(groups[0])) {
			perror("setgid");
			syslog(LOG_ERR, "Unable to setgid");
			return -1;
		}
		if (setgroups(nb_groups, groups)) {
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
int sr_setcaps(settings_t *settings)
{
	if (setpcap_effective(1)) {
		error(0, 0, "Unable to setpcap capability");
		syslog(LOG_ERR, "Unable to setpcap capability");
		return -1;
	}
	if (cap_iab_set_proc(settings->iab)) {
		perror("Unable to set capabilities");
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
int sr_noroot(settings_t *options)
{
	if (options->disable_root) {
		if (activates_securebits()) {
			error(0, 0, "Unable to activate securebits");
			syslog(LOG_ERR, "Unable to activate securebits");
			return -1;
		}
	}
	return 0;
}

void escape_special_chars(char* input, size_t input_length) {
    char* special_chars = "%\\";
    char* escape_char = "\\";
    size_t i, j;

    for (i = 0, j = 0; i < input_length && input[i] != '\0'; i++, j++) {
        if (strchr(special_chars, input[i]) != NULL) {
            strncpy(&input[j + 1], &input[j], input_length - j);
            input[j] = escape_char[0];
            j++;
            input_length++;
        }
        input[j] = input[i];
    }
    input[j] = '\0';
}


/**
 * @brief main function of the SR module
*/
int main(int argc, char *argv[])
{
	arguments_t arguments = { NULL, 0, 0, 0 };
	char callpath[PATH_MAX];
	if (strnlen(argv[0], PATH_MAX) == PATH_MAX) {
		error(0, 0, "Path of the executable is too long");
		syslog(LOG_ERR, "Path of the executable is too long");
		return -1;
	}
	strncpy(callpath, argv[0], PATH_MAX);
	callpath[PATH_MAX - 1] = '\0';
	escape_special_chars(callpath, PATH_MAX);
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
	settings_t options;
	set_default_options(&options);
	user_t *user = user_posix_get();
	if (!pam_authenticate_user(user->name)) {
		error(0, 0, "Authentication failed");
		goto free_error;
	}

	if (arguments.info) {
		if (arguments.role == NULL)
			print_rights(user);
		else {
			print_rights_role(arguments.role, user);
		}
		goto free_error;
	}

	cmd_t *cmd = get_cmd(argc, argv);
	if (cmd == NULL) {
		error(0, 0, "Unable to get command");
		goto free_error;
	}
	if (arguments.role){
		int ret = get_settings_from_config_role(arguments.role, user, cmd,
						 &options);
		if (!ret) {
			syslog(LOG_ERR,
			       "User '%s' tries to execute '%s', without permission",
				   user->name, cmd->command);
			error(0, 0, "Permission denied");
			goto free_error;
		}		   	
	} else {
		int ret = get_settings_from_config(XML_FILE, user, cmd, &options);
		if (!ret) {
			syslog(LOG_ERR,
			       "User '%s' tries to execute '%s', without permission",
			       user->name, cmd->command);
			error(0, 0, "Permission denied");
			goto free_error;
		}
	}
	
	syslog(LOG_INFO,
			"User '%s' tries to execute '%s' with role '%s'", user->name,
			cmd->command, options.role);
#ifndef GDB_DEBUG
	if (sr_noroot(&options) || sr_setuid(&options) ||
		sr_setgid(&options) || sr_setcaps(&options)) {
		goto free_error;
	}
#endif

	char **env = NULL;
	int res = filter_env_vars(environ, options.env_keep,
					options.env_check, &env);
	if (res > 0) {
		error(0, 0, "Unable to filter environment variables");
		syslog(LOG_ERR,
				"Unable to filter environment variables");
		goto free_error;
	}
	res = secure_path(getenv("PATH"), options.path);
	if (!res) {
		error(0, 0, "Unable to secure path");
		syslog(LOG_ERR, "Unable to secure path");
		goto free_error;
	}
	free_options(&options);
	if (user != NULL)
		user_posix_free(user);
	return sr_execve(cmd->command, cmd->argc, cmd->argv, env);

free_error:
	free_options(&options);
	if (user != NULL)
		user_posix_free(user);
	return -1;
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