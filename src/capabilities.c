/*
 * <capabilities.c>
 *
 * This file contains the definition of the capabilities management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#define _GNU_SOURCE
#include "capabilities.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/capability.h>
#include <cap-ng.h>
#include <sys/prctl.h>
#include <linux/securebits.h>

extern int errno;

/******************************************************************************
 *                      PRIVATE FUNCTIONS DECLARATION                         *
 ******************************************************************************/

/* 
Add or remove the capabilities in/from the effective set of the process.
Add the caps if enable is different than 0, remove them if enable is 0.
Return 0 on success, -1 on failure.
*/
static int caps_effective(int enable, int nb_caps, cap_value_t *cap_values);

/******************************************************************************
 *                      PUBLIC FUNCTIONS DEFINITION                           *
 ******************************************************************************/

/* 
Check if the current process has the setuid and the setgid capabilities
in its effective set.
Return 1 if the process has both setuid and setgid, 0 if not, -1 on failure.
*/
int check_effective_setuid_setgid(){
    cap_t caps;
	cap_flag_value_t setuid_f, setgid_f;

	caps = cap_get_proc();
	if (caps == NULL) return -1;
    
    if(cap_get_flag(caps, CAP_SETUID, CAP_EFFECTIVE, &setuid_f)
            || cap_get_flag(caps, CAP_SETGID, CAP_EFFECTIVE, &setgid_f)){
        cap_free(caps);
        return -1;
    }else{
        cap_free(caps);
        if(setuid_f == CAP_SET && setgid_f == CAP_SET){
            return 1;
        }else{
            return 0;
        }
    }
}

/* 
Add or remove the set_fcap capability in/from the effective set
of the process.
Return 0 on success, -1 on failure.
*/
int setfcap_effective(int enable){
	cap_value_t cap_value;

	//Compute the capvalue setfcap
	if(cap_from_name("cap_setfcap", &cap_value)) return -1;
	return caps_effective(enable, 1, &cap_value);
}

/* 
Add or remove the set_pcap capability in/from the effective set
of the process.
Return 0 on success, -1 on failure.
*/
int setpcap_effective(int enable){
	cap_value_t cap_value;

	//Compute the capvalue setfcap
	if(cap_from_name("cap_setpcap", &cap_value)) return -1;
	return caps_effective(enable, 1, &cap_value);
}

/*
Allocate an array of capabilities of the process that are in the permitted set.
The array *caps should be deallocated with free() afterwards.
Return 0 on success, -1 on failure.
*/
int get_permitted_caps(int *nb_caps, cap_value_t **caps){
    cap_t proc_caps = NULL; //capabilities state of the process
	cap_value_t c; //a capability candidate
	cap_flag_value_t fval_permitted; //Value of a cap's flag
	int ret_cap_get_flag;
	
	//Init out parameters
	*nb_caps = 0;
	*caps = NULL;
    //Retrieves the process capabilities, 
	if((proc_caps = cap_get_proc()) == NULL) goto on_error;
	//Allocate an array of caps
	*caps = (cap_value_t *) malloc((CAP_LAST_CAP + 1) * sizeof(cap_value_t));
	if(*caps == NULL) goto on_error;
	//As there is not parser so far, try each known capability from
	//0 to CAP_LAST_CAP (last defined cap by linux)
	for (c = 0; c <= CAP_LAST_CAP; c++){
		//test if the cap is supported by the system
		if(!CAP_IS_SUPPORTED(c)) continue;
		//Retrieve the flags for this cap in the permitted and inheritable
		//sets of the current process
		ret_cap_get_flag = cap_get_flag(proc_caps, c, CAP_PERMITTED, 
		                                &fval_permitted);
        if(ret_cap_get_flag == -1){
            if(errno == EINVAL){
                //fix bug on inconsistence btwn linux headers def and kernel
                continue;
            }else{
                goto on_error;	
            }
        }
		//check that the cap is in permitted set
		if(fval_permitted == CAP_SET){
		    *(*caps + (*nb_caps)++) = c;
		}
	}
	//Reshape the array of caps
	*caps = realloc(*caps, *nb_caps * sizeof(cap_value_t));
	if(*caps == NULL && *nb_caps > 0) goto on_error;
	cap_free(proc_caps);
    return 0;
    
  on_error:
    if (caps != NULL){
        cap_free(proc_caps);
    }
    if (*caps != NULL){
        free(*caps);
        *caps = NULL;
    }
    *nb_caps = 0;
	return -1;
}

/*
Allocate an array of capabilities of the process that are in both
inheritable and permitted sets.
The array *caps should be deallocated afterwards.
Return 0 on success, -1 on failure.
*/
int get_ambient_caps_candidates(int *nb_caps, cap_value_t **caps){
	cap_t proc_caps = NULL; //capabilities state of the process
	cap_value_t c; //a capability candidate
	cap_flag_value_t fval_inheritable, fval_permitted; //values of cap's flags
	int ret_cap_get_flag;
	
	//Init out parameters
	*nb_caps = 0;
	*caps = NULL;
    //Retrieves the process capabilities, 
	if((proc_caps = cap_get_proc()) == NULL) goto on_error;
	//Allocate an array of caps
	*caps = (cap_value_t *) malloc((CAP_LAST_CAP + 1) * sizeof(cap_value_t));
	if(*caps == NULL) goto on_error;
	//As there is not parser so far, try each known capability from
	//0 to CAP_LAST_CAP (last defined cap by linux)
	for (c = 0; c <= CAP_LAST_CAP; c++){
		//test if the cap is supported by the system
		if(!CAP_IS_SUPPORTED(c)) continue;
		//Retrieve the flags for this cap in the permitted and inheritable
		//sets of the current process
		ret_cap_get_flag = cap_get_flag(proc_caps, c, CAP_INHERITABLE, 
		                                &fval_inheritable);
        if(ret_cap_get_flag == -1){
            if(errno == EINVAL){
                //fix bug on inconsistence btwn linux headers def and kernel
                continue;
            }else{
                goto on_error;	
            }
        }
        ret_cap_get_flag = cap_get_flag(proc_caps, c, CAP_PERMITTED, 
		                                &fval_permitted);
        if(ret_cap_get_flag == -1){
            if(errno == EINVAL){
                //fix bug on inconsistence btwn linux headers def and kernel
                continue;
            }else{
                goto on_error;	
            }
        }	
		//check that the cap is in inheritable and permitted sets
		if(fval_inheritable == CAP_SET && fval_inheritable == CAP_SET){
		    *(*caps + (*nb_caps)++) = c;
		}
	}
	//Reshape the array of caps
	*caps = realloc(*caps, *nb_caps * sizeof(cap_value_t));
	if(*caps == NULL && *nb_caps > 0) goto on_error;
	cap_free(proc_caps);
    return 0;
    
  on_error:
    if (proc_caps != NULL){
        cap_free(proc_caps);
    }
    if (*caps != NULL){
        free(*caps);
        *caps = NULL;
    }
    *nb_caps = 0;
	return -1;
}

/* 
Add the capabilities into the ambient set of the process.
Return 0 on success, -1 on failure.
*/
int add_ambient_capabilities(int nb_caps, const cap_value_t *capabilities){
    const cap_value_t *c;
    for(c = capabilities; c < capabilities + nb_caps; c++){
        if (prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE, *c, 0, 0) == -1)
            return -1;
    }
    return 0;
}

/* 
Set the capabilities of the inheritable set of the current process.
All previous capabilities in that set will be cleared.
Return 0 on success, -1 on failure.
*/
int set_inheritable_capabilities(int nb_caps, const cap_value_t *capabilities){
	cap_t caps;

	//Get process' capabilities
	if ((caps = cap_get_proc()) == NULL) return -1;
	//Clear the inheritable set, then
	//Add the capabilities in the inheritable set, then
	//Update the caps of the process
	if (cap_clear_flag(caps, CAP_INHERITABLE)
	        || cap_set_flag(caps, CAP_INHERITABLE, nb_caps, capabilities, 
	                        CAP_SET)
	        || cap_set_proc(caps)){
		cap_free(caps);
		return -1;
    }else{
        cap_free(caps);
        return 0;
    }
}

/* 
Add the capabilities to the permitted set of an opened file fd 
Return 0 on success, -1 on failure.
*/
int add_permitted_capabilities_to_file(const int fd, int nb_caps, 
                                        const cap_value_t *capabilities){
    cap_t caps;

    //Init an empty capabilities state
	caps = cap_init();
	if (caps == NULL) return -1;
    
    //Add the capabilities in the permitted set, then
    //Set the caps of the file
    if (cap_set_flag(caps, CAP_PERMITTED, nb_caps, capabilities, CAP_SET)
                    || cap_set_fd(fd, caps)) {
		cap_free(caps);
		return -1;
	}else{
	    cap_free(caps);
	    return 0;
	}
}

/* 
Activate the securebits for the no-root option.
Return 0 on success, -1 on failure.
*/                                    
int activates_securebits(){
    //Enable effective set_fcap capability
    if(setpcap_effective(1)) return -1;
    //Set the securebits
    if(prctl(PR_SET_SECUREBITS, 
            SECBIT_KEEP_CAPS_LOCKED | 
            SECBIT_NO_SETUID_FIXUP |
            SECBIT_NO_SETUID_FIXUP_LOCKED |
            SECBIT_NOROOT |
            SECBIT_NOROOT_LOCKED) == -1){
        return -1;
    }
    //Disable effective set_fcap capability
    if(setpcap_effective(0)) return -1;
    return 0;
}

/* 
Activate the no-new-privileges for the no-root option.
Return 0 on success, -1 on failure.
*/                                    
int activates_no_new_privs(){
    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1){
        return -1;
    }else{
        return 0;
    }
}

/* 
Construct and return a textual representation of the given capabilities.
The textual representation should be deallocated with free() afterwards.
Return NULL if nb_caps = 0 or if an error occured.
*/
char *cap_list_to_text(int nb_caps, const cap_value_t *capabilities){
    const cap_value_t *c; //A capability value
    const size_t buf_size = 512; //Size of increments of the text array
	char * text = NULL; //Textual representation of the capabilitis
    long text_max_size = 0; //size of the text array
    long text_size = 0; //Length of the text
    char *cap_text; //A textual representation of a capability
	int cap_length; //Length of cap_text
	
	//Iterate over the list
	for (c = capabilities; c < capabilities + nb_caps; c++){
		//Get the textual representation of the current cap
		if((cap_text = cap_to_name(*c)) == NULL){
            if(text != NULL){
                free(text);
            }
            return NULL;
        }
		//Resize the text array to able able to fit at least the cap name 
		//and a comma and a space
		cap_length = strlen(cap_text);
		while(text_max_size - text_size - 3 < cap_length){
			text_max_size += buf_size;
            text = (char*) realloc(text, text_max_size * sizeof(char));
            if(text == NULL){
                cap_free(cap_text);
                return NULL;
            }
		}
		//Append (or set for the first time) the cap name to the text
		if(text_size > 0){
	        strncat(text, cap_text, cap_length + 1);
    	    text_size += cap_length;
    	}else{
    		strncpy(text, cap_text, cap_length + 1);
    		text_size = cap_length;
    	}
    	//deallocate the cap text
    	cap_free(cap_text);
    	//add a comma and a space if there is a next cap
    	if(c < capabilities + nb_caps - 1){
            text[text_size] = ',';
            text[++text_size] = ' ';
            text[++text_size] = '\0';
        }
	}
	//Reshape the text
	if((text = realloc(text, (text_size + 1) * sizeof(char))) == NULL){
	    return NULL;
	}
	return text;

}

/******************************************************************************
 *                              DEBUG FUNCTIONS                               *
 ******************************************************************************/
#ifdef SR_DEBUG

/* 
Print the process capabilities in all three sets to stdout 
*/
void print_process_cap(){
	cap_t caps;
	char *text;
    //Get process' capbilities
	caps = cap_get_proc(); 
	if (caps == NULL){
        perror("Error retrieving process capabilities");
		return;
    }
    //Convert caps into the textual representation
    if((text = cap_to_text(caps, NULL)) == NULL){
    	perror("Error converting caps to text");
    	cap_free(caps);
    }else{
    	printf("CAPS: %s\n", text);
    	cap_free(text);
    	cap_free(caps);
    }
}

/* 
Print a summary of process' attributes involved in no-root option
*/
void print_noroot_process_attributes(){
    int attrval;
    attrval = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    printf("- NO_NEW_PRIVS: %d\n", attrval);
    attrval = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    if(attrval == -1){
        perror("Error getting securebits");
        return;
    }
    printf("- SECBIT_KEEP_CAPS: %d\n", attrval & SECBIT_KEEP_CAPS);
    printf("- SECBIT_KEEP_CAPS_LOCKED: %d\n", 
            attrval & SECBIT_KEEP_CAPS_LOCKED ? 1 : 0);
    printf("- SECBIT_NO_SETUID_FIXUP: %d\n", 
            attrval & SECBIT_NO_SETUID_FIXUP ? 1 : 0);
    printf("- SECBIT_NO_SETUID_FIXUP_LOCKED: %d\n", 
            attrval & SECBIT_NO_SETUID_FIXUP_LOCKED ? 1 : 0);
    printf("- SECBIT_NOROOT: %d\n", 
            attrval & SECBIT_NOROOT ? 1 : 0);
    printf("- SECBIT_NOROOT_LOCKED: %d\n", 
            attrval & SECBIT_NOROOT_LOCKED ? 1 : 0);
}

/* 
Print user's IDs and group's IDs of the process
*/
void print_user_group_ids_info(){
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    
    if(getresuid(&ruid, &euid, &suid)
            ||getresgid(&rgid, &egid, &sgid)){
        perror("Error retrieving ids info");
    }else{
        printf("Real UID: %ld\nEffective UID: %ld\nSaved UID: %ld\n", 
                ruid, euid, suid);
        printf("Real GID: %ld\nEffective GID: %ld\nSaved GID: %ld\n", 
                rgid, egid, sgid);
    }
}

/* 
Print a full debug resume
*/
void print_debug_resume(){
    printf("\n----- DEBUG RESUME -----\n");
    printf("--- IDs Info ---\n");
    print_user_group_ids_info();
    printf("\n--- Process capabilities ---\n");
    print_process_cap();
    printf("\n--- No-root process attributes ---\n");
    print_noroot_process_attributes();
    printf("----- END DEBUG RESUME ------\n\n");
}

#endif //SR_DEBUG

/******************************************************************************
 *                      PRIVATE FUNCTIONS DEFINITION                          *
 ******************************************************************************/

/* 
Add or remove the capabilities in/from the effective set of the process.
Add the caps if enable is different than 0, remove them if enable is 0.
Return 0 on success, -1 on failure.
*/
static int caps_effective(int enable, int nb_caps, cap_value_t *cap_values){
	cap_t caps; //Capabilities state
	cap_flag_value_t cap_flag_value; //value of the caps' flag to use
	int return_code = -1; 
	
	//Define the value of the flag to use to enable or disable the caps
	cap_flag_value = enable ? CAP_SET : CAP_CLEAR;
	//Get process' capabilities state
	if ((caps = cap_get_proc()) == NULL) return return_code;
    //Set or clear the capabilities in the effective set
    if (cap_set_flag(caps, CAP_EFFECTIVE, nb_caps, cap_values, 
                    cap_flag_value)) goto free_rscs;
	//Update the process' capabilities
	if (cap_set_proc(caps)) goto free_rscs;
	//Treatment done
	return_code = 0;
  free_rscs:
    cap_free(caps);
    return return_code;
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
