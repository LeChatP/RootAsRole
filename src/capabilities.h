/*
 * <capabilities.h>
 *
 * This file contains the signatures of capabilities management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#ifndef CAPABILITIES_H_INCLUDED
#define CAPABILITIES_H_INCLUDED
#include <sys/capability.h>

/* 
Add or remove the set_pcap capability in/from the effective set
of the process.
Return 0 on success, -1 on failure.
*/
int setpcap_effective(int enable);

/*
Set setuid capabilities in the effective set of the process.
*/
int setuid_effective(int enable);

/*
Set setgid capabilities in the effective set of the process.
*/
int setgid_effective(int enable);

/*
Set dac_read capabilities in the effective set of the process.
*/
int dac_read_effective(int enable);

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
