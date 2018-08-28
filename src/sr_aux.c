/*
 * <sr_aux.c>
 *
 * This file contains the program called by sr to launch a program with a set
 * of capabilities put in the ambient set.
 *
 * Note, the copyright+license information is at end of file.
 */

#include "sr_constants.h"
#include "capabilities.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

#define PS1ENV_PREFIX "PS1=\\W:\\u \033[38;5;9m("
#define PS1ENV_SUFFIX ")\033[38;5;15m\\\\$ "

/*
Create the PS1 value for the new shell environnement based on the role name
Return the value on success or NULL on failure.
*/
char *create_ps1(const char *role);

/*
    sr_aux should be called with 2 or 3 arguments:
    - role: the role name
    - no root indicator: either "noroot" or something else
    - [command]: the command to execute instead of the bash, if the third indicator is "yes"
*/
int main(int argc, char *argv[])
{
    int noroot; //no-root option indicator
    const char *role;
	const char *command; //command optional parameter
	cap_value_t *capabilities = NULL; //array of caps
	int nb_caps = 0; //size of capapbilities
	char *cap_text = NULL; //Text of caps
	
	char *new_env[2] = {NULL, NULL}; //the futur shell environment
	
	#ifdef SR_DEBUG
	printf("sr_aux, launching...\n");
	print_debug_resume();
	#endif
	
	//Check and init params
	if (argc < 3 || argc > 4){
		fprintf(stderr, "Bad params.\n");
		exit(EXIT_FAILURE);
	}
	role = argv[1];
	if (!strcmp("noroot", argv[2])) {
	    noroot = 1;
	}else{
	    noroot = 0;
	}
	if(argc > 3){
		command = argv[3];
	}else{
		command = NULL;
	}
	
	//Retrieve permitted capabilities
	if(get_permitted_caps(&nb_caps, &capabilities)){
	    perror("Unable to retrieve permitted capabilities");
	    goto on_error;
	}
	//Set them in inheritable
	if(set_inheritable_capabilities(nb_caps, capabilities)){
	    perror("Unable to set inheritable capabilities");
	    goto on_error;
	}
    //Set them in ambiant
	if (add_ambient_capabilities(nb_caps, capabilities)){
	    perror("Unable to set ambient capabilities");
        goto on_error;
	}

	//Manage the no root option
	if (noroot) { 
        if(activates_no_new_privs()){
            perror("Unable to set the no-new-privs option (no-root option)");
            goto on_error;
        }
	}

	//Print an alert with the list of capabilities
	printf("Privileged bash launched with ");
	if(noroot){
	    printf("no-root option and ");
	}
	if(nb_caps > 0){
	    //Create a textual repr of cap list
	    cap_text = cap_list_to_text(nb_caps, capabilities);
	    if(cap_text == NULL && nb_caps > 0){
	        perror("Unable to create a textual representation of capabilities");
	        goto on_error;
	    }
    	printf("the following capabilities : %s.\n", cap_text);
    	free(cap_text);
	    cap_text = NULL;
    }else{
        printf("without any capability!\n");    
    }
	
	//deallocate the list of caps
	free(capabilities);
	capabilities = NULL;
	
	//Create the PS1 value and set it to the environement;
	new_env[0] = create_ps1(role);
	
	#ifdef SR_DEBUG
	printf("sr_aux, before execve final program...\n");
	print_debug_resume();
	#endif

	//Exec the bash (with or without a given command), with an empty env
	
    if (command == NULL){
        execle(BASH, BASH, BASH_OPTION, (char *) NULL, new_env);
    }else{
        execle(BASH, BASH, BASH_OPTION, "-c", command, (char *) NULL, new_env);
    }
    //We should never go to this point if everything's all right
    perror("Execution failed");
    
  on_error:
    if(new_env[0] != NULL) free(new_env[0]);
    if(cap_text != NULL) free(cap_text);
	if(capabilities != NULL) free(capabilities);
	exit(EXIT_FAILURE);
}

/*
Create the PS1 value for the new shell environnement based on the role name
Return the value on success or NULL on failure.
*/
char *create_ps1(const char *role)
{
    char *ps1_val = NULL;
    int ps1_val_len = 0;
    ps1_val_len = strlen(PS1ENV_PREFIX) + strlen(role) 
                    + strlen(PS1ENV_SUFFIX) + 1;
    if((ps1_val = malloc(ps1_val_len * sizeof(char))) == NULL) return NULL;
    
    strncpy(ps1_val, PS1ENV_PREFIX, strlen(PS1ENV_PREFIX) + 1);
    strncat(ps1_val, role, strlen(role) + 1);
    strncat(ps1_val, PS1ENV_SUFFIX, strlen(PS1ENV_SUFFIX) + 1);
    
    return ps1_val;
}

/* ... adapted from the pam_cap.c file created by Andrew G. Morgan
 *
 * Copyright Guillaume Daumas <guillaume.daumas@univ-tlse3.fr>, 2018
 * Copyright Ahmad Samer Wazan <ahmad-samer.wazan@irit.fr>, 2018
 * Copyright (c) Andrew G. Morgan <morgan@linux.kernel.org>, 1996-8
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
