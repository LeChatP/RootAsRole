#include "command.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <error.h>
#include <linux/limits.h>
#include <string.h>

char * find_absolute_path_from_env(char *file)
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

/*********************
 * PUBLIC FUNCTIONS **
**********************/

cmd_t *get_cmd(int argc, char *argv[]) {
    char *command = realpath(argv[0], NULL);
	if (errno == ENAMETOOLONG) {
        user_t *user = params_user_get();
		error(0, 0, "Path too long");
		syslog(LOG_ERR,
				"User '%s' failed to execute '%s', path too long",
				user->name, command);
		return NULL;
	}
	if (access(command, X_OK) != 0) {
		command = find_absolute_path_from_env(argv[0]);
		if (command == NULL) {
            user_t *user = params_user_get();
			syslog(LOG_ERR,
					"User '%s' failed to execute '%s', command not found",
					user->name, command);
			error(0, 0, "%s : Command not found", argv[0]);
			return NULL;
		}
	} else {
        user_t *user = params_user_get();
		error(0, 0, "%s : Command not found", argv[0]);
		syslog(LOG_ERR,
				"User '%s' failed to execute '%s', command not found",
				user->name, command);
        return NULL;
	}
    return params_command_set(command, argc, argv);	
}

/**
 * @brief return 1 if command start with absolute path, this is not checking if the path exists
 * @param content the command line
 * @param abspath the absolute path found
 * @param size the size of the absolute path
 * @param args the arguments of the command
 * @param size_args the size of the arguments
 * @note if * provided only, the absolute path is set to * and the arguments to .*
 * @return 1 on success, or 0 if no absolute path found
*/
int get_abspath_from_cmdline(const char *content, char *abspath, int size, char *args, int size_args){
    char *abspath_ptr = abspath;
    char *content_ptr = content;
    char *args_ptr = args;
    if (*content_ptr == '*') {
        *abspath_ptr = '*';
        *(abspath_ptr+1) = '\0';
        if(*(content_ptr+1) == '*' && strlen(content) == 2){
            *args_ptr = '.';
            *(args_ptr+1) = '*';
            *(args_ptr+2) = '\0';
            return 1;
        }
    }
    
    if (*content_ptr != '/' && *content_ptr != '*'){
        return 0;
    }
    while( (*content_ptr != ' ' || *(content_ptr-1) == '\\') 
            && *content_ptr != '\t'
            && *content_ptr != '\0' 
            && abspath_ptr < abspath+size-1){
        if (*content_ptr == ' ' && *(content_ptr-1) == '\\') {
            abspath_ptr--;
        }
        *abspath_ptr = *content_ptr;
        abspath_ptr++;
        content_ptr++;
    }
    if(*content_ptr == ' ') content_ptr++;
    *abspath_ptr = '\0';
    if (args != NULL) {
        while( *content_ptr != '\0' 
                && args_ptr < args+size_args-1){
            *args_ptr = *content_ptr;
            args_ptr++;
            content_ptr++;
        }
        *args_ptr = '\0';
    }
    return 1;
}

/**
 * @brief join argv to a space separated string
 * @param argc the number of arguments
 * @param argv the arguments
 * @param res the result string
 * @param res_size the limit size of the result string
 * @param res_len the length of the result string
 * @return 0 on success, 1 on error
*/
int join_argv(int argc, char **argv, char *res, int res_size, int *res_len){
    *res_len = 0;
    char * res_ptr = res;
    if(argc == 0){
        return 0;
    }
    for (int i = 0; i < argc; ++i) {
        if(res_ptr - res >= res_size){
            return 1;
        }
        strncpy(res_ptr, argv[i], res_size - *res_len);
        res_ptr += strnlen(argv[i], res_size - *res_len);
        *res_ptr = ' ';
        res_ptr++;
        *res_len = res_ptr - res;
    }
    res_ptr--;
    *res_ptr = '\0';
    *res_len = res_ptr - res;
    return 0;
}

/**
 * @brief join command to a space separated string
 * @param cmd the command to join
 * @param res the result string
 * @param res_size the limit size of the result string
 * @param res_len the length of the result string
 * @return 0 on success, 1 on error
*/
int join_cmd(cmd_t *cmd, char *res, int res_size, int *res_len){
    char * res_ptr = res;
    *res_len = 0;
    int commandlen = strlen(cmd->command);
    if(commandlen+1 >= res_size){
        return 1;
    }
    strncpy(res_ptr, cmd->command, res_size);
    
    res_ptr += commandlen;
    if (cmd->argc > 1)*res_ptr = ' ';
    res_ptr++;
    int max_len = res_size - (res_ptr - res);
    if(join_argv(cmd->argc-1, cmd->argv+1, res_ptr, max_len, res_len)) return 1;
    *res_len += res_ptr - res;
    res_ptr[*res_len] = '\0';
    return 0;
}

int may_be_regex(const char *str, int size){
    char *dup = strndup(str, size);
    int ret = strpbrk(dup, ".^+*)(][?}{$|\\")!=NULL ? 1 : 0;
    free(dup);
    return ret;
}