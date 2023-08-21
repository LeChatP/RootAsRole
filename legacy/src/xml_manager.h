#ifndef XML_MANAGER_H
#define XML_MANAGER_H

#include <sys/capability.h>
#include "params.h"

#define XML_FILE "/etc/security/rootasrole.xml"

#ifndef DEBUG
#define DEBUG 0
#endif

#define RESTRICTED 1
#define UNRESTRICTED 0

/**
 * @brief load xml file and validate it
 * @param xml_file the xml file
 * @return the document, or NULL on error
*/
xmlDocPtr load_xml(char *xml_file);

/**
 * @brief free the options
*/
void free_options(settings_t *options);

/**
 * @brief retrieve all execution settings from xml document matching user, groups and command 
 * @param doc the document
 * @param user the user
 * @param nb_groups the number of groups
 * @param groups the groups
 * @param command the command
 * @param options the output settings
 * @return 1 on success, or 0 on error
*/
int get_settings_from_doc_by_partial_order(xmlDocPtr doc, user_t *user, cmd_t *command, settings_t *p_options);

/**
 * @brief retrieve all execution settings from xml document matching user, groups and command 
 * @param doc the document
 * @param user the user
 * @param nb_groups the number of groups
 * @param groups the groups
 * @param command the command
 * @param settings the output settings
 * @return 1 on success, or 0 on error
*/
int get_settings_from_doc_by_role(char *role, xmlDocPtr doc, user_t *user,
				  cmd_t *cmd, settings_t *settings);

/**
 * @brief Print informations of a role
*/
void print_full_role(char *role);

/**
 * @brief Print all roles
*/
void print_full_roles();

/**
 * @brief Print the rights of all accessible roles for a user
 * @param user The user to check
 * @param nb_groups The number of groups of the user
 * @param groups The groups of the user
*/
void print_rights(user_t *user);

/**
 * @brief Print the rights of a role if user is in the role
 * @param role The role to print
 * @param user The user to check
 * @param nb_groups The number of groups of the user
 * @param groups The groups of the user
*/
void print_rights_role(char *role, user_t *user);

/**
 * @brief Get document version
 * @param doc The document to check
 * @return The version of the document, to be freed
*/
xmlChar *get_doc_version(xmlDocPtr doc);

/**
 * @brief Get document timestamp timeout value
 * @param doc The document to check
 * @return The timeout value of the document
*/
u_int64_t get_doc_timestamp_timeout(xmlDocPtr doc);

#endif
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