/*
 * <sraux_management.h>
 *
 * This file contains the signatures of sr_aux management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#ifndef SRAUX_MANAGEMENT_H_INCLUDED
#define SRAUX_MANAGEMENT_H_INCLUDED
#include "sr_constants.h"
#include "roles.h"

#define SR_AUX_SOURCE "/usr/bin/sr_aux"

/* 
Create a temporary copy of sr_aux in the user folder, 
with the required capabilities in the file extensions.
Return the filepath of the file, or NULL on failure.
If change_user_required != 0, then the file will be put in /usr/bin 
instead of the user's home.
The returned filepath is a dynamic char array and should be deallocated afterward.
*/
char *create_sr_aux_temp(const char *user, const user_role_capabilities_t *urc, 
                        const int change_user_required);

/* 
Call sr_aux
Do an exeve on the temporary sr_aux file given in sr_aux_filepath,
with the given arguments set in urc and noroot.
Return -1 on failure, does not return on success.
*/
int call_sr_aux(const char *sr_aux_filepath, 
                const user_role_capabilities_t *urc, int noroot);

#endif // SRAUX_MANAGEMENT_H_INCLUDED

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
