#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef __STDC_LIB_EXT1__
#define __STDC_LIB_EXT1__
#endif
#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include "env.h"
#include <string.h>
#include <ctype.h>

#include <errno.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * This function is based on the tz_is_safe() function from sudo.
 * The original function is licensed under the ISC license.
 * which is compatible with the GPL license.
 * The original function is available at: https://www.sudo.ws/repos/sudo/file/tip/plugins/sudoers/env.c
 * 
 * Verify the TZ environment variable is safe.
 * On many systems it is possible to set this to a pathname.
 */
static int tz_is_safe(const char *tzval)
{
    const char *cp;
    char lastch;

    /* tzcode treats a value beginning with a ':' as a path. */
    if (tzval[0] == ':')
	tzval++;

    /* Reject fully-qualified TZ that doesn't being with the zoneinfo dir. */
    if (tzval[0] == '/') {
	    return 0;
    }

    /*
     * Make sure TZ only contains printable non-space characters
     * and does not contain a '..' path element.
     */
    lastch = '/';
    for (cp = tzval; *cp != '\0'; cp++) {
	if (isspace((unsigned char)*cp) || !isprint((unsigned char)*cp))
	    return 0;
	if (lastch == '/' && cp[0] == '.' && cp[1] == '.' &&
	    (cp[2] == '/' || cp[2] == '\0'))
	    return 0;
	lastch = *cp;
    }

    /* Reject extra long TZ values (even if not a path). */
    if ((size_t)(cp - tzval) >= PATH_MAX) return 0;

    return 1;
}

/**
 * @brief check if string matches another string with wildcards
*/
static int match(char *str, char *pattern){
    if (str == NULL || pattern == NULL){
        return 0;
    }
    char *wildcard;
    if ((wildcard = strchr(pattern, '*')) != NULL){
        if(wildcard[1] == '\0') {
            return strncmp(str, pattern, wildcard - pattern) == 0;
        } else if (strncmp(str, pattern, wildcard - pattern) == 0){
            return match(str + (wildcard - pattern) - 1, wildcard + 1);
        } else {
            return 0;
        }
    } else{
        return strcmp(str, pattern) == 0;
    }
    return 0;
}

/**
 * @brief check if a string is in an array of strings
 * @param str the string to check
 * @param array the array of strings
 * @return 1 if the string is in the array, 0 otherwise
*/
static int is_in_array(char *str, char **array){
    if (str == NULL || array == NULL){
        return 0;
    }
    for(int i = 0; array[i] != NULL; i++){
        if (match(str, array[i])){
            return 1;
        }
    }
    return 0;
}

int check_var(char *var_name,char *var_value){
    if (var_name == NULL || var_value == NULL){
        return 0;
    }
    if (strncmp(var_name, "TZ",2) == 0){
        return tz_is_safe(var_value);
    }
    if(strpbrk(var_value,"/%") != NULL){
        return 0;
    }
    return 1;
}

long long array_len(char **array){
    if (array == NULL){
        return 0;
    }
    long long i = 0;
    while(i < __LONG_MAX__ && array[i] != NULL){
        i++;
    }
    return i;
}

/**
 * This function is based on sudo code source.
 * @brief filter some environment variables according to the blacklist and next to the whitelist
 * @param envp the environment variables to filter
 * @param whitelist the whitelist of environment variables to keep separated by a comma
 * @param checklist the checklist of environment variables to check separated by a comma
 * @param new_envp the new environment variables array
 * @return 0 if the function succeed, 1 otherwise
*/
int filter_env_vars(char **envp, char **whitelist, char **checklist, char ***p_new_envp){
    if (envp == NULL){
        return 1;
    }
    int res = 0;
    int i = 0;
    char **new_envp = (char**)malloc(sizeof(char*)*array_len(envp) + 1);
    *new_envp = NULL;

    if (checklist == NULL && whitelist == NULL){
        *p_new_envp = envp;
    }

    for(int j = 0; envp[j] != NULL; j++){
        char *env_var = strdup(envp[j]);
        char *env_var_name = strtok(env_var, "=");
        if (env_var_name == NULL || *env_var_name == '\0'){
            res++;
            goto error;
        }
        char *env_var_value = env_var_name + strnlen(env_var_name,ARG_MAX) + 1;
        if (strncmp(env_var_name, "PATH", 4) == 0 || (is_in_array(env_var_name, checklist) && check_var(env_var_name, env_var_value)) || is_in_array(env_var_name, whitelist)){
            new_envp[i] = envp[j];
            new_envp[i + 1] = NULL;
            i++;
        }
        free(env_var);
    }
    *p_new_envp = new_envp;
    error:
    return res;

}

int secure_path(char *path, char *secure_path){
    return snprintf(path, ARG_MAX, "%s", secure_path) > 0;
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