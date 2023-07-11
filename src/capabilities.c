/*
 * <capabilities.c>
 *
 * This file contains the definition of the capabilities management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#define _GNU_SOURCE
#define __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
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
Add or remove the set_pcap capability in/from the effective set
of the process.
Return 0 on success, -1 on failure.
*/
int setpcap_effective(int enable)
{
	cap_value_t cap_value;

	//Compute the capvalue setfcap
	if (cap_from_name("cap_setpcap", &cap_value))
		return -1;
	return caps_effective(enable, 1, &cap_value);
}

/**
 * Set setuid capabilities in the effective set of the process.
 * Return 0 on success, -1 on failure.
 */
int setuid_effective(int enable)
{
	cap_value_t cap_value;

	//Compute the capvalue setfcap
	if (cap_from_name("cap_setuid", &cap_value))
		return -1;
	return caps_effective(enable, 1, &cap_value);
}

/**
 * Set setgid capabilities in the effective set of the process.
 * Return 0 on success, -1 on failure.
 */
int setgid_effective(int enable)
{
	cap_value_t cap_value;

	//Compute the capvalue setfcap
	if (cap_from_name("cap_setgid", &cap_value))
		return -1;
	return caps_effective(enable, 1, &cap_value);
}

int dac_read_effective(int enable)
{
	cap_value_t cap_value;

	//Compute the capvalue setfcap
	if (cap_from_name("cap_dac_read_search", &cap_value))
		return -1;
	return caps_effective(enable, 1, &cap_value);
}

/* 
Activate the securebits for the no-root option.
Return 0 on success, -1 on failure.
*/
int activates_securebits()
{
	//Enable effective set_fcap capability
	if (setpcap_effective(1))
		return -1;
	//Set the securebits
	if (prctl(PR_SET_SECUREBITS,
		  SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP |
			  SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT |
			  SECBIT_NOROOT_LOCKED) == -1) {
		return -1;
	}
	//Disable effective set_fcap capability
	if (setpcap_effective(0))
		return -1;
	return 0;
}

/* 
Activate the no-new-privileges for the no-root option.
Return 0 on success, -1 on failure.
*/
int activates_no_new_privs()
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		return -1;
	} else {
		return 0;
	}
}

int cap_get_bound(cap_value_t cap)
{
    int result;

    result = prctl(PR_CAPBSET_READ, (unsigned long) cap);
    if (result < 0) {
	errno = -result;
	return -1;
    }
    return result;
}

/**
 * Drop all the capabilities from the parent process bounding set.
*/
int drop_iab_from_current_bounding(cap_iab_t *dest)
{
	int ret = 1;
	cap_flag_value_t values[CAP_LAST_CAP+1];
	for (cap_value_t i = 0; i < CAP_LAST_CAP+1; i++) {
		values[i] = cap_get_bound(i);
		if (values[i] == 0) {
			cap_flag_value_t value =
				cap_iab_get_vector(*dest, CAP_IAB_BOUND, i);
			if (value == CAP_SET) {
				ret = 0;
			}
			cap_iab_set_vector(*dest, CAP_IAB_BOUND, i, CAP_CLEAR);
			cap_iab_set_vector(*dest, CAP_IAB_AMB, i, CAP_CLEAR);
			cap_iab_set_vector(*dest, CAP_IAB_INH, i, CAP_CLEAR);
		}
	}
	return ret;
}

/******************************************************************************
 *                      PRIVATE FUNCTIONS DEFINITION                          *
 ******************************************************************************/

/* 
Add or remove the capabilities in/from the effective set of the process.
Add the caps if enable is different than 0, remove them if enable is 0.
Return 0 on success, -1 on failure.
*/
static int caps_effective(int enable, int nb_caps, cap_value_t *cap_values)
{
	cap_t caps; //Capabilities state
	cap_flag_value_t cap_flag_value; //value of the caps' flag to use
	int return_code = -1;

	//Define the value of the flag to use to enable or disable the caps
	cap_flag_value = enable ? CAP_SET : CAP_CLEAR;
	//Get process' capabilities state
	if ((caps = cap_get_proc()) == NULL)
		return return_code;
	//Set or clear the capabilities in the effective set
	if (cap_set_flag(caps, CAP_EFFECTIVE, nb_caps, cap_values,
			 cap_flag_value))
		goto free_rscs;
	//Update the process' capabilities
	if (cap_set_proc(caps))
		goto free_rscs;
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
