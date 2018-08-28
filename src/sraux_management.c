/*
 * <sraux_management.c>
 *
 * This file contains the definitions of sr_aux management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#include "sraux_management.h"
#include "user.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "capabilities.h"

extern int errno;

/******************************************************************************
 *                      PRIVATE FUNCTIONS DECLARATION                         *
 ******************************************************************************/

/* 
Copy sr_aux file content to the opened file fd_to.
Return 0 on success, -1 on failure.
*/
static int copy_sr_aux(int fd_to);

/* 
Create the filepath for the temporary sr_aux.
The filepath should be deallocated with free() aftewards.
Return the filepath on succes or NULL on failure.
*/
static char *create_filepath(const char *user, const int change_user_required);

/******************************************************************************
 *                      PUBLIC FUNCTIONS DEFINITION                           *
 ******************************************************************************/

/* 
Create a temporary copy of sr_aux in the user folder, 
with the required capabilities in the file extensions.
Return the filepath of the file, or NULL on failure.
If change_user_required != 0, then the file will be put in /usr/bin 
instead of the user's home.
The returned filepath is a dynamic char array and should be deallocated afterward.
*/
char *create_sr_aux_temp(const char *user, const user_role_capabilities_t *urc, 
                        const int change_user_required){
    /*sr_aux will be used to fill the ambient set of the process and launch 
    the bash. But, if more than 1 user want to use Switch Role at the same 
    time, it's a problem. For this reason, the program make a copy of 
    sr_aux and it will work on it. 
    The copy has an unique name (sr_aux_userName_role). */
    char *filepath; //temporary filepath
    int filepath_fd = -1; //file descriptor of the temporary file
    mode_t file_permissions; //file permission

    //Create a temporary filepath pattern
    if((filepath=create_filepath(user, change_user_required)) == NULL){
        return NULL;
    }
    //Create the temporary file, open it
    if((filepath_fd = mkstemp(filepath)) < 0) goto clean_on_error;
    //Copy the sr_aux content
    if(copy_sr_aux(filepath_fd)) goto clean_on_error;
    //Add executable right to the file
    file_permissions = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP 
                        | S_IROTH | S_IXOTH;
    if(fchmod(filepath_fd, file_permissions)) goto clean_on_error;
    //Enable effective set_fcap capability
    if(setfcap_effective(1)) goto clean_on_error;
    //Add the capabilities to the file
    if(add_permitted_capabilities_to_file(filepath_fd, urc->caps.nb_caps, 
                            urc->caps.capabilities)) goto clean_on_error;
    //Disable effective set_fcap capability
    if(setfcap_effective(0)) goto clean_on_error;
    //close the file descriptor and return the filename
    close(filepath_fd);
    return filepath;

  clean_on_error:
    if(filepath_fd >= 0) close(filepath_fd);
    remove(filepath);
    free(filepath);
    return NULL;
}


/* 
Call sr_aux
Do an exeve on the temporary sr_aux file given in sr_aux_filepath,
with the given arguments set in urc and noroot.
Return -1 on failure, does not return on success.
*/
int call_sr_aux(const char *sr_aux_filepath, 
                const user_role_capabilities_t *urc, int noroot){
    char *noroot_arg = NULL;
    int return_code = -1;

    //Create noroot arg: "noroot" if 1, "root" otherwise
    if(noroot){
        if(!(noroot_arg = (char*) malloc(6 * sizeof(char)))) goto free_rscs;
        strncpy(noroot_arg, "noroot", 6);
    }else{
        if(!(noroot_arg = (char*) malloc(4 * sizeof(char)))) goto free_rscs;
        strncpy(noroot_arg, "root", 4);
    }
    //Exec sr_aux
    if(urc->command == NULL){
    	return_code = execl(sr_aux_filepath, sr_aux_filepath, urc->role, 
    	                    noroot_arg, NULL);
    }else{
	    return_code = execl(sr_aux_filepath, sr_aux_filepath, urc->role,
	                        noroot_arg, urc->command, NULL);
    }

  free_rscs:
    if(noroot_arg != NULL) free(noroot_arg);
    return return_code;
}

/******************************************************************************
 *                      PRIVATE FUNCTIONS DEFINITION                          *
 ******************************************************************************/

/* 
Copy sr_aux file content to the opened file fd_to.
Return 0 on success, -1 on failure.
*/
static int copy_sr_aux(int fd_dest){
    int fd_src;
    char buf[4096];
    ssize_t nread;
    int saved_errno;

    if((fd_src = open(SR_AUX_SOURCE, O_RDONLY)) < 0) return -1;

    while(nread = read(fd_src, buf, sizeof(buf)), nread > 0){
        char *out_ptr = buf;
        ssize_t nwritten;
        do{
            nwritten = write(fd_dest, out_ptr, nread);
            if(nwritten >= 0){
                nread -= nwritten;
                out_ptr += nwritten;
            }else if(errno != EINTR){
                goto out_error;
            }
        } while(nread > 0);
    }

    if(nread == 0){
        close(fd_src);
        return 0;
    }
	
  out_error:
	saved_errno = errno;
	close(fd_src);
	errno = saved_errno;
	return -1;
}

/* 
Create the filepath for the temporary sr_aux.
The filepath should be deallocated with free() aftewards.
Return the filepath on succes or NULL on failure.
*/
static char *create_filepath(const char *user, const int change_user_required){
    char *filepath; //temporary filepath
    int filepath_len; //temporary filepath len
    
    //Create a temporary filepath pattern
    if (change_user_required) {
        //current user is root and effective user is not: 
        //create the file in /usr/bin
        filepath_len = 9 + 7 + 6 + 1; //"/usr/bin/sr_aux_XXXXXX\0"
        if(!(filepath = (char*) malloc(filepath_len * sizeof(char)))) 
            return NULL;
        filepath[0] = '\0';
        strncat(filepath, "/usr/bin/", 9);
    }else{
        //we will store the program in current user home
        char *home;
        int len_home;
        if((home = get_home_directory(user)) == NULL){
            fprintf(stderr, "No home directory for user %s. Cannot create temporary file.\n", user);
            return NULL;
        }
        len_home = strlen(home);
        filepath_len = len_home + 1 + 7 + 6 + 1; //"home/sr_aux_XXXXXX\0"
        if(!(filepath = (char*) malloc(filepath_len * sizeof(char)))){
            free(home);
            return NULL;
        }
        filepath[0] = '\0';
        strncat(filepath, home, len_home);
        strncat(filepath, "/", 1);
        free(home);
    }
    strncat(filepath, "sr_aux_XXXXXX", 13);
    return filepath;
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
