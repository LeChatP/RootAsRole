/*
 * <sr.c>
 *
 * This file contains the main program to start a capability role session.
 *
 * Note, the copyright+license information is at end of file.
 */
#include "sr_constants.h"
#include "user.h"
#include "capabilities.h"
#include "roles.h"
#include "sraux_management.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <libxml/parser.h>
#include <getopt.h>

extern char *optarg;
extern int optind, opterr, optopt;

//Internal structure of input parameters
typedef struct _arguments_t {
    char *role;
    char *user;
    char *command;
    int noroot;
    int info;
    int help;
} arguments_t;

/*
Parse input arguments and check arguments validity (in length)
return 0 on success, -1 on unknown arguments, -2 on invalid argument
*/
static int parse_arg(int argc, char **argv, arguments_t *args);

/*
Print Help message
*/
static void print_help(int long_help);

/* 
Authenticate / Check user or user_id
If *user is not NULL and different than the effective user, check that 
the process has set-uid and set-gid then set *user_id as the id of *user,
*group_id as the group of the *user and *change_required to 1.
If *user is NULL, authenticate the effective user of the process through PAM
if the user is not root, then set *user to that user, 
*user_id to the user id, *group_id to the user group id 
and *change_required to 0.
Return 0 on success, -1 on failure.
*/
static int verify_user(char **user, uid_t *user_id, gid_t *group_id, 
                        int *change_required);
                        
/* 
Create a user-role-capabilities  with the role, the user, the command.
Retrieve all the group the user belongs then retrieve the capabilities
the role provides if the user can apply for that role.
A root user can apply for any role.
The user-role must be deallocated by free_urc() afterwards.
Return the user-role pointer on success, or NULL on failure
*/
static user_role_capabilities_t *retrieve_urc(const char* role, 
        const char* user, const char *command, uid_t user_id, gid_t group_id,
        int print_urc_info);

/*
Mask/Unmasks signals to prevent stopping the father until the child is done
(Usefull when the user send eg ^C to stop the command runned under a role).
Unmask the signals if mask_signals is 0, mask them otherwise.
Return 0 on success, -1 on failure.
*/
static int mask_signals(int mask_signals);

/* 
Entry point
*/
int main(int argc, char *argv[])
{
    int return_code = EXIT_FAILURE;
    arguments_t args; //The input args
    uid_t user_id; //the user id that will be used
    gid_t group_id; //the user group Id that will be used
    int change_user_required; //a indicator that we need to change user
    user_role_capabilities_t *urc = NULL; //user role capabilities
    char *sr_aux_filepath = NULL; //The filepath of the temporary sr_aux
    int idfork; //The id of the forked process

	// Parse and validate arguments
	if(parse_arg(argc, argv, &args)){
	    fprintf(stderr, "Bad parameter.\n");
		print_help(0);
        goto free_rscs;
	}
	if(args.help){
	    print_help(1);
	    return_code = EXIT_SUCCESS;
		goto free_rscs;
	}
    //Assert a role has been given
	if (args.role == NULL){
        fprintf(stderr, "A role is mandatory\n");
		print_help(0);
        goto free_rscs;
	}
	
	#ifdef SR_DEBUG
    printf("sr, at launch...\n");
    print_debug_resume();
    #endif
	
	//Authenticate / verify given user
	//user will have to be dealloced afterwards
	if(verify_user(&args.user, &user_id, &group_id, 
	                &change_user_required)) goto free_rscs;
	
	//Prevention of execution if user is root and no-root is not active
	if(user_id == 0 && args.noroot == 0){
	    fprintf(stderr, "For security reason, you cannot execute a role under root. Please change the user or use the no-root option\n");
	    goto free_rscs;
	}
	
	//Retrieve the user capabilities from role (depending of the command)
	//Print role info if info required
	if((urc = retrieve_urc(args.role, args.user, args.command, user_id, 
	                    group_id, args.info)) == NULL){
        goto free_rscs;
    }
	if(args.info){
	    //Quit here if info required
	    return_code = EXIT_SUCCESS;
	    goto free_rscs;
	}

	//Create a temporary sr_aux with the given capabilities
	if((sr_aux_filepath = create_sr_aux_temp(args.user, urc, 
	                           change_user_required)) == NULL){
        perror("Unable to create temporary sr_aux file");
        goto free_rscs;
	}

	//Create a child process to launch sr_aux
	idfork = fork();
	if (idfork == 0){ //Child work
	    //if no-root option is required, activates securebits
	    //We must activates securebits before changing uid !
        if(args.noroot){
            if(activates_securebits()){
                perror("Unable to activate securebits for no-root option");
                goto free_rscs;
            }
        }
        //if root uses an other user, keep capabilities and set uid
        if(change_user_required){ 
            //Remember that we are going to loose all caps in E, P and Ambient
            if(setgid(group_id) || setuid(user_id)){
                perror("Unable to change user id or group id");
                goto free_rscs;
            }
        }
        
        #ifdef SR_DEBUG
	    printf("sr, before execve sr_aux...\n");
	    print_debug_resume();
	    #endif
        
        //Execute temporary sr_aux
        //The call should never return
        if (call_sr_aux(sr_aux_filepath, urc, args.noroot)){
            perror("Unable to execute sr_aux");
            goto free_rscs;
        }
	}else{ //Father work
        if(idfork < 0){
            perror("Unable to fork");
        }else{
            //Mask signals to avoid premature abortion
            if(mask_signals(1)){
                perror("Cannot mask signals"); //do not terminate
            }
            //Wait for sr_aux to be done
            while(wait(NULL) == -1 && errno == EINTR);
            //Unmask signals
            if(mask_signals(0)){
                perror("Cannot unmask signals"); //do not terminate
            }
            return_code = EXIT_SUCCESS;
        }
        //delete the sr_aux temporary file
        printf("End of role %s session.\n", args.role);
        if(remove(sr_aux_filepath)){
            perror("Error while deleting temporary sr_aux file");
            return_code = EXIT_FAILURE;
        }
	}

	//Proper clean
  free_rscs:
    if(urc != NULL){
        free_urc(urc);
    }
    if(args.user != NULL){
        free(args.user);
    }
    if(sr_aux_filepath != NULL){
        free(sr_aux_filepath);
    }
    exit(return_code);
}

/*
Parse input arguments and check arguments validity (in length)
return 0 on success, -1 on unknown arguments, -2 on invalid argument
*/
static int parse_arg(int argc, char **argv, arguments_t *args){
    *args = (arguments_t) {NULL, NULL, NULL, 0, 0, 0};
    
    while(1){
        int option_index = 0;
        int c;
        static struct option long_options[] = {
            {"role",    required_argument, 0,   'r'},
            {"user",    required_argument, 0,   'u'},
            {"command", required_argument, 0,   'c'},
            {"no-root", no_argument,       0,   'n'},
            {"info",    no_argument,       0,   'i'},
            {"help",    no_argument,       0,   'h'},
            {0,         0,                 0,   0}
        };

        c = getopt_long(argc, argv, "r:u:c:nih", long_options, &option_index);
        if(c == -1) break;
    
        switch(c){
            case 'r':
                args->role = optarg;
                break;
            case 'u':
                args->user = optarg;
                break;
            case 'c':
                args->command = optarg;
                break;
            case 'n':
                args->noroot = 1;
                break;
            case 'i':
                args->info = 1;
                break;
            case 'h':
                args->help = 1;
                break;
            default:
                return -1;
        }
    }
    //If other unknown args
    if (optind < argc) {
        return -1;
    }
    //Check length of string
    if(args->role != NULL){
        if(strlen(args->role) > 64) return -2;
    }
    if(args->user != NULL){
        if(strlen(args->user) > 32) return -2;
    }
    if(args->command != NULL){
        if(strlen(args->command) > 256) return -2;
    }
    return 0;
}

/*
Print Help message
*/
static void print_help(int long_help){
    printf("Usage : sr -r role [-n] [-c command] [-u user] [-h]\n");
    if (long_help){
        printf("Use a role to provide capabilities to a shell or a command.\n");
        printf("Options:\n");
        printf(" -r, --role=role        the capabilities role to use.\n");
        printf(" -c, --command=command  launch the command instead of a bash shell.\n");
        printf(" -n, --no-root          execute the bash or the command without the possibility to increase privilege (e.g.: sudo).\n");
        printf(" -u, --user=user        substitue the user (reserved to administrators).\n");
        printf(" -i, --info             print the commands the user is able to process within the role and quit.\n");
        printf(" -h, --help             print this help and quit.\n");
    }
}

/* Authenticate / Check user or user_id
If *user is not NULL and different than the effective user, check that 
the process has set-uid and set-gid then set a copy of *user in *user,
set *user_id as the id of *user, set *group_id as the group of the *user 
and *change_required to 1.
If *user is NULL, authenticate the effective user of the process through PAM
if the user is not root, then set *user to that user, 
*user_id to the user id, *group_id to the user group id 
and *change_required to 0.
Return 0 on success, -1 on failure.
The user should be dealloced with free afterwards;
*/
static int verify_user(char **user, uid_t *user_id, gid_t *group_id, 
                        int *change_required){
    const char *given_user = *user;
    char *effective_user_name = NULL;
    uid_t effective_uid;
    
    //Init out params
    *user = NULL;
    *user_id = -1;
    *group_id = -1;
    
    //Retrieve effective user_id and username
    effective_uid = geteuid();
    if((effective_user_name = get_username(effective_uid)) == NULL){
        perror("Error retrieving effective username");
        goto free_rscs_on_error;
    }
    
    //If a user has been given and it is different than the user login, 
    //check if the current process has the capabilities to set uid and gid, 
    //then retrieve the user's id of the required user
	if (given_user != NULL && strncmp(given_user, effective_user_name, 
	                                    strlen(effective_user_name))){
        int has_setuid_gid_caps;
        int user_len;
        //We do not need effective username anymore
        free(effective_user_name);
        effective_user_name = NULL;
        //Check that setuid and setgid caps are effective
        has_setuid_gid_caps = check_effective_setuid_setgid();
        if(has_setuid_gid_caps < 0){
            perror("Error checking setuid and setgid capabilities");
            goto free_rscs_on_error;
        }else if(has_setuid_gid_caps == 0){
            fprintf(stderr, "Can't switch user, cap_setuid and cap_setgid are not set.\n");
            goto free_rscs_on_error;
        }else{
            //retrieve the user_id of the given user
            *user_id = get_user_id(given_user); 
            if(*user_id < 0){
                perror("Error retrieving id of the user.");
                goto free_rscs_on_error;
            }
        }
        //Create a copy of user for consistency with the other case
        user_len = strlen(given_user) + 1;
        if((*user = malloc(user_len * sizeof(char))) == NULL) return -1;
        strncpy(*user, given_user, user_len);
        //Set change required indicator 
	    *change_required = 1;
	}else{
	    //user is then the effective username and no change is required
	    *change_required = 0;
        *user = effective_user_name;
        effective_user_name = NULL;
        *user_id = effective_uid; 
        //If user is no root, request a PAM authentication
        if(*user_id != 0){
            int retval;
            printf("Authentication of %s...\n", *user);
            retval = pam_authenticate_user(*user);
            if(retval < 0){
                perror("Authentication failure");
                goto free_rscs_on_error;
            }else if(!retval){
                fprintf(stderr, "Authentication failed.\n");
                goto free_rscs_on_error;
            }
        }
	}
	
	//Eventualy for both cases, retrieve the id of the user group
	if((*group_id = get_group_id(*user_id)) == -1){
	    perror("Cannot retrieve user group id");
	    goto free_rscs_on_error;
	}
	//OK
	return 0;
    
  free_rscs_on_error:
    if(effective_user_name != NULL) free(effective_user_name);
    if(*user != NULL) free(*user);
    *user = NULL;
    return -1;
}

/* Create a user-role-capabilities  with the role, the user, the command.
Retrieve all the group the user belongs then retrieve the capabilities
the role provides if the user can apply for that role.
A root user can apply for any role.
The user-role must be deallocated by free_urc() afterwards.
Return the user-role pointer on success, or NULL on failure
*/
static user_role_capabilities_t *retrieve_urc(const char* role, 
        const char* user, const char *command, uid_t user_id, gid_t group_id,
        int print_urc_info){
    user_role_capabilities_t *urc = NULL;
    int nb_groups;
    char **groups_names = NULL;
    int ret_val;
    
    //Retrieve the user group names
    if(get_group_names(user, group_id, &nb_groups, &groups_names)){
        perror("Error retrieving user's group names");
        goto free_on_error;
    }
    
    //Retrieve the user capabilities from role
	if(init_urc_command(role, command, user, nb_groups, groups_names, &urc)){
        perror("Unable to init user role capabilities\n");
        goto free_on_error;
	}
	//Initialize the libxml parsing lib
	xmlInitParser();
	if(!print_urc_info){
	    //Retrieve capabilities
	    ret_val = get_capabilities(urc);
	}else{
	    //Print role info for the user
	    ret_val = print_capabilities(urc);
	}
	//Free the libxml parsing lib
	xmlCleanupParser();
	//Process returned value of get_capabilities
	switch(ret_val){
	    case 0:
	        goto free_rscs;
            break;
        case -2:
            perror("Missing given role or user");
            break;
        case -3:
            perror("Missing configuration file or syntax error in it");
            break;
        case -4:
            perror("Invalid configuration file");
            break;
        case -5:
            perror("The role does not exist");
            break;
        case -6:
            perror("This role cannot be used with your user or your groups");
            break;
        default:
            perror("An unmanaged error occured");
            break;
	}
	
  free_on_error:
    if(urc != NULL){
        free_urc(urc);
    }
    urc = NULL;
    
  free_rscs:
    if(groups_names != NULL){
        int i;
        for(i = 0; i < nb_groups; i++){
            free(groups_names[i]);
        }
        free(groups_names);
    }
    return urc;
}

/*
Mask/Unmasks signals to prevent stopping the father until the child is done
(Usefull when the user send eg ^C to stop the command runned under a role).
Unmask the signals if mask_signals is 0, mask them otherwise.
Return 0 on success, -1 on failure.
*/
static int mask_signals(int mask_signals){
    struct sigaction action;
    int ret = 0;
    
    if(mask_signals){
        action.sa_handler = SIG_IGN;
        action.sa_flags = SA_RESTART;
    }else{
        action.sa_handler = SIG_DFL;
        action.sa_flags = 0;
    }
    sigemptyset (&action.sa_mask);
    
    ret = sigaction(SIGINT, &action, NULL)
            | sigaction(SIGQUIT, &action, NULL)
            | sigaction(SIGABRT, &action, NULL)
            | sigaction(SIGTERM, &action, NULL)
            | sigaction(SIGUSR1, &action, NULL)
            | sigaction(SIGUSR2, &action, NULL)
            | sigaction(SIGTSTP, &action, NULL);
    if(ret){
        return -1;
    }else{
        return 0;
    }
}

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