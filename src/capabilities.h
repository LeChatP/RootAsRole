/*
 * <capabilities.h>
 *
 * This file contains the signatures of capabilities management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#ifndef CAPABILITIES_H_INCLUDED
#define CAPABILITIES_H_INCLUDED
#include "sr_constants.h"
#include <sys/capability.h>

/* 
Check if the current process has the setuid and the setgid capabilities
in its effective set.
Return 1 if the process has both setuid and setgid, 0 if not, -1 on failure. 
*/
int check_effective_setuid_setgid();

/* 
Add or remove the set_fcap capability in/from the effective set
of the process.
Return 0 on success, -1 on failure.
*/
int setfcap_effective(int enable);

/* 
Add or remove the set_pcap capability in/from the effective set
of the process.
Return 0 on success, -1 on failure.
*/
int setpcap_effective(int enable);

/*
Allocate an array of capabilities of the process that are in the permitted set.
The array *caps should be deallocated with free() afterwards.
Return 0 on success, -1 on failure.
*/
int get_permitted_caps(int *nb_caps, cap_value_t **caps);

/*
Allocate an array of capabilities of the process that are in both
inheritable and permitted sets.
The array *caps should be deallocated afterwards.
Return 0 on success, -1 on failure.
*/
int get_ambient_caps_candidates(int *nb_caps, cap_value_t **caps);

/* 
Add the capabilities into the ambient set of the process.
Return 0 on success, -1 on failure.
*/
int add_ambient_capabilities(int nb_caps, const cap_value_t *capabilities);

/* 
Set the capabilities of the inheritable set of the current process.
All previous capabilities in that set will be cleared.
Return 0 on success, -1 on failure.
*/
int set_inheritable_capabilities(int nb_caps, const cap_value_t *capabilities);

/* 
Add the capabilities to the permitted set of an opened file fd 
Return 0 on success, -1 on failure.
*/
int add_permitted_capabilities_to_file(const int fd, int nb_caps, 
                                        const cap_value_t *capabilities);
    
/* 
Activate the securebits for the no-root option.
Return 0 on success, -1 on failure.
*/                                    
int activates_securebits();

/* 
Activate the no-new-privileges for the no-root option.
Return 0 on success, -1 on failure.
*/                                    
int activates_no_new_privs();

/* 
Construct and return a textual representation of the given capabilities.
The textual representation should be deallocated with free() afterwards.
Return NULL if nb_caps = 0 or if an error occured.
*/
char *cap_list_to_text(int nb_caps, const cap_value_t *capabilities);


/******************************************************************************
 *                              DEBUG FUNCTIONS                               *
 ******************************************************************************/

#ifdef SR_DEBUG
/* 
Print the process capabilities in all three sets to stdout 
*/
void print_process_cap();

/* 
Print a summary of process' attributes involved in no-root option
*/
void print_noroot_process_attributes();

/* 
Print user's IDs and group's IDs of the process
*/
void print_user_group_ids_info();

/* 
Print a full debug resume
*/
void print_debug_resume();

#endif //SR_DEBUG


#endif // CAPABILITIES_H_INCLUDED

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
