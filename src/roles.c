/*
 * <roles.h>
 *
 * This file contains the definitions of roles management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#include "roles.h"
#include "capabilities.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h> //adding xpath for simplified finding

extern int errno;

/******************************************************************************
 *                      PRIVATE STRUCTURE DEFINITION                          *
 ******************************************************************************/

//Internal Chained list of commands (for printout only)
struct chained_command {
	xmlChar *command;
	struct chained_command *next;
};

typedef struct chained_command *chained_commands;

//Internal iterator on collections nodes
struct _xml_collection_iterator {
	xmlNodePtr col_node;
	xmlChar *element_name;
	xmlNodePtr cur_node;
};

typedef struct _xml_collection_iterator *xml_collection_iterator;

/******************************************************************************
 *                      PRIVATE FUNCTIONS DECLARATION                         *
 ******************************************************************************/
/*
Create a new iterator on collection nodes: an xml structure composed of a node
of name collection_name that includes nodes of name element_name. The
collection node is intended to be a child of node.
return the iterator on success, NULL on failure
*/
static xml_collection_iterator
new_xml_collection_iterator(xmlNodePtr node, const char *collection_name,
			    const char *element_name);

/**
 * Free an chained_command struct
 */
static void cc_free_it(chained_commands commands);

/*
Free an iterator on collection nodes
*/
static void xci_free_it(xml_collection_iterator it);

/*
return 1 if the iterator has a collection, 0 otherwise.
*/
static int xci_has_collection(xml_collection_iterator it);

/*
return 1 if the iterator still has element of collection to iterate on, 
0 otherwise.
*/
static int xci_has_next(xml_collection_iterator it);

/*
Retrieve the next element of collection. Return NULL if no element is to 
iterate.
*/
static xmlNodePtr xci_next(xml_collection_iterator it);

/*
Given a command, extract the program: do not take care of left spaces, neither
the right spaces and/or options related to the program.
Set begin_prg and len_prg and return 0 on success, or -1 on failure;
*/
static int extract_program_from_command(xmlChar *cmd, xmlChar **begin_prg,
					int *len_prg);

/*
Return 1 if the given command match the referenced command, 0 otherwise
If the ref command does not include any options, thus any option in the given
command is allowed. Otherwise, the given command must match both the program
name and the sequence of options (in the same order!)
*/
static int is_command_allowed(xmlChar *c_ref, xmlChar *c_given);

/**
 * replace string s in position start to length character of ct
 * return the new char*
 */
static char *str_replace(const char *s, unsigned int start, unsigned int length,
			 const char *ct);

/**
 * appends s2 to str with realloc, return new char*
 */
static char *concat(char *str, char *s2);

/**
 * Sanitize string, escape unwanted chars to their xml equivalent
 * @param str the string to encode, not modified
 * @param quot 
 * 		set to 1 will replace " to &quot; useful when your string is surrounded by " 
 * 		set to 0 will replace ' to &apos; useful when your string is surrounded by '
 * @return new string with escaped chars
 */
static char* encodeXml(const char* str, int quot);

/**
 * format groups to xpath OR expression to match every group of user
 * return xpath logical OR string of every group
 */
static char* xpath_format_groups(char** groups, int nb_groups);

/**
 * Return group formatted expression
 * this function will replace "not(@name)" string in tmpexpression to formatted group list
 * if nb_groups is empty, tmpexpression is returned
 * otherwise new string with formatted expression is returned
 */
static char * format_groups(char **groups,int nb_groups,char *tmpexpression);

/**
 * This function will replace key to value in str
 */
static char* sanitizeCharTo(char *str,char key,char *value);

/*
Find user role for command specified
Return 0 on success, -2 if role wasn't found,
-3 if an error has been found in the xml doc, -1 if an other error happened
*/
static int find_role_for_user(xmlXPathContextPtr context, char *user,const char *command,
			      xmlNodePtr *role_node);

/*
Find user role for command specified
Return 0 on success, -2 if role wasn't found,
-3 if an error has been found in the xml doc, -1 if an other error happened
*/
static int find_role_for_group(xmlXPathContextPtr context, char **groups, int nb_groups,
			      const char *command, xmlNodePtr *role_node);

/**
 * find the first role that matching command, user and group
 * @return -2 if the role wasn't found
 */
static int find_role_by_command(xmlXPathContextPtr context,
				user_role_capabilities_t *urc,
				xmlNodePtr *role_node);

/*
Get the role node matchin the role name from the xml configuration file
Return 0 on success, -2 if the role does not exist, 
-3 if an error has been found in the xml doc, -1 if an other error happened.
If an error occured, *role_node will be NULL.
*/
static int get_role(xmlDocPtr conf_doc, const char *role,
		    xmlNodePtr *role_node);

/**
 * Print every role informations
 */
static void print_roles(user_role_capabilities_t *urc,xmlXPathObjectPtr result);

/**
 * Print role informations from xmlNode
 */
static void print_role(user_role_capabilities_t *urc,xmlNodePtr role_node);

/**
 * If only role is specified then get role and print details of his informations
 */
static int print_match_RoleOnly(user_role_capabilities_t *urc, xmlDocPtr conf_doc);

/**
 * If command and role is specified in urc then print if user can perform this command
 */
static int print_match_commandAndRole(user_role_capabilities_t *urc, xmlDocPtr conf_doc);

/**
 * print capabilities from role_node
 */
static void print_role_caps(user_role_capabilities_t *urc,const xmlNodePtr role_node);

/*
For a given role node, check that the username or on of the groups are defined.
For those which are defined, if a set of commands are also present, check
that the commend given in the urc exists and is included in the configuration
definition.
Return 0 on success, -2 if no valid user/group have been found
-3 if an error has been found in the xml doc, -1 if an other error happened.
*/
static int check_urc_valid_for_role(user_role_capabilities_t *urc,
				    xmlNodePtr role_node);

/**
 * obtain right quote to handle XPath eval
 */
static char get_quote(const char* str);

/*
Find a user node that match user in a role_node, and whose command given
(or not) match the auhtorized command if needed.
Return 0 on success, -2 if no valid user have been found, -3 if an error
has been found in the xml doc, -4 if a user has been found but command invalid,
-1 if an other error happened.
*/
static int find_matching_user_node(user_role_capabilities_t *urc,
				   const xmlNodePtr role_node);

/*
From a list of group in urc, find a group node that match one of the groups 
defined in a role_node, and whose command given (or not) match the auhtorized 
commands of the group if needed.
Return 0 on success, -2 if no valid group have been found, -3 if an error
has been found in the xml doc, -1 if an other error happened.
*/
static int find_matching_group_node(user_role_capabilities_t *urc,
				    const xmlNodePtr role_node);

/*
Check if command in urc is valid regarding the command definition of 
the node.
Return 0 on success, -2 command invalid, -3 if an error
has been found in the xml doc, -1 if an other error happened.
A command is valid if urc->command is NULL and no command are defined in 
the node OR if urc->command is among the commands defined in the node.
*/
static int check_valid_command_from_commands(user_role_capabilities_t *urc,
					     xmlNodePtr matching_item_node);

/*
Complete the urc with the capabilities defined in the role node.
As the same time, validate capabilities: ensure they are defined in libcap 
and that the kernel can handle them.
Return 0 on success, -3 if an error has been found in the xml doc, 
-1 if an other error happened.
*/
static int complete_role_capabilities(user_role_capabilities_t *urc,
				      xmlNodePtr role_node);

/******************************************************
* Specific functions for printing information on role *
******************************************************/

/*
Copy a command to the list if it does not already belong to the list.
Return 0 on success, -1 if an error happened.
*/
static int add_unique_command_to_list(xmlChar *command,
				      chained_commands *chained_commands);

/*
For a given node, add the available commands to the list and set any_command to 0
if they are defined are set any_command to 1 if not.
Return 0 on success, -3 if an error has been found in the xml doc, 
or -1 if an other error happened.
*/
static int add_node_commands(const xmlNodePtr node, int *any_command,
			     chained_commands *commands);

/*
For the given user in urc, add the available commands to the list commands
if the user exist in the role node 
Return 0 on success, -2 if no valid user have been found, -3 if an error
has been found in the xml doc, -1 if an other error happened.
*/
static int add_user_commands(user_role_capabilities_t *urc,
			     const xmlNodePtr role_node, int *any_command,
			     chained_commands *commands);

/*
Add the available commands of the groups node that match one of groups 
in a role_node. If one of the matching group does not have any restriction on
commands, set any_command to 1 and stop as soon as possible. Otherwise,
set any_command to 0.
Return 0 on success, -2 if no valid group have been found, -3 if an error
has been found in the xml doc, -1 if an other error happened.
*/
static int add_groups_commands(user_role_capabilities_t *urc,
			       const xmlNodePtr role_node, int *any_command,
			       chained_commands *commands);

/******************************************************************************
 *                      PUBLIC FUNCTIONS DEFINITION                           *
 ******************************************************************************/

/* 
Initialize a user_role_capabilities_t for a given role role, and
for the given user and the groups.
Every entry in the struct is a copy in memory.
The structure must be deallocated with free_urc() afterwards.
Return 0 on success, -1 on failure.
*/
int init_urc(const char *role, const char *user, int nb_groups, char **groups,
	     user_role_capabilities_t **urc)
{
	return init_urc_command(role, NULL, user, nb_groups, groups, urc);
}

/* 
Initialize a user_role_capabilities_t for a given role role,
for a specific command command, and
for the given user and the groups.
Every entry in the struct is a copy in memory.
The structure must be deallocated with free_urc() afterwards.
Return 0 on success, -1 on failure.
*/
int init_urc_command(const char *role, const char *command, const char *user,
		     int nb_groups, char **groups,
		     user_role_capabilities_t **urc)
{
	int string_len;
	if ((*urc = malloc(sizeof(user_role_capabilities_t))) == NULL) {
		goto free_on_error;
	}
	//Copy non pointer values and init others
	(*urc)->nb_groups = nb_groups;
	(*urc)->caps.nb_caps = 0;
	(*urc)->caps.capabilities = NULL;
	(*urc)->role = NULL;
	(*urc)->command = NULL;
	(*urc)->user = NULL;
	(*urc)->groups = NULL;

	//Create copy of pointer values
	if (role != NULL) {
		string_len = strlen(role) + 1;
		if (((*urc)->role = malloc(string_len * sizeof(char))) == NULL)
			goto free_on_error;
		strncpy((*urc)->role, role, string_len);
	}
	if (command != NULL) {
		string_len = strlen(command) + 1;
		if (((*urc)->command = malloc(string_len * sizeof(char))) ==
		    NULL)
			goto free_on_error;
		strncpy((*urc)->command, command, string_len);
	}
	if (user != NULL) {
		string_len = strlen(user) + 1;
		if (((*urc)->user = malloc(string_len * sizeof(char))) == NULL)
			goto free_on_error;
		strncpy((*urc)->user, user, string_len);
	}
	if (nb_groups > 0) {
		char **ptrGpDst, **ptrGpSrc;
		if (((*urc)->groups = calloc(nb_groups, sizeof(char *))) ==
		    NULL)
			goto free_on_error;
		for (ptrGpDst = (*urc)->groups, ptrGpSrc = groups;
		     ptrGpDst < (*urc)->groups + nb_groups;
		     ptrGpDst++, ptrGpSrc++) {
			int gp_len = strlen(*ptrGpSrc) + 1;
			if ((*ptrGpDst = malloc(gp_len * sizeof(char))) == NULL)
				goto free_on_error;
			strncpy(*ptrGpDst, *ptrGpSrc, gp_len);
		}
	}
	return 0;

free_on_error:
	if (*urc != NULL)
		free_urc(*urc);
	return -1;
}

/* 
Deallocate a user_role_capabilities_t
Always return 0.
*/
int free_urc(user_role_capabilities_t *urc)
{
	if (urc == NULL) {
		return 0;
	}
	if (urc->role != NULL)
		free(urc->role);
	if (urc->command != NULL)
		free(urc->command);
	if (urc->user != NULL)
		free(urc->user);
	if (urc->nb_groups > 0 && urc->groups != NULL) {
		int i;
		for (i = 0; i < urc->nb_groups; i++) {
			if (urc->groups[i] != NULL)
				free(urc->groups[i]);
		}
		free(urc->groups);
	}
	if (urc->caps.nb_caps > 0) {
		free(urc->caps.capabilities);
	}
	free(urc);
	return 0;
}

/*
Given an urc (user/groups-role-command), check in the configuration if the
role can be used with that user or these groups (and the given command if
require). If true, set the capabilities provided by the role in the urc.
return :
0: success
-2 (EINVAL): missing mandatory parameter (either role or user)
-3 (EINVAL): missing configuration file or bad DTD
-4 (EINVAL): Invalid configuration file (XML not valid)
-4 (EINVAL): the configuration file is invalid
-5 (EINVAL): the role does not exists
-6 (EACCES): the role cannot be use with that user or his groups or with that command
-1 other error (errno will be set)
*/
int get_capabilities(user_role_capabilities_t *urc)
{
	int return_code = -1; //the return code of the function
	int ret_fct; //return of sub functions
	xmlParserCtxtPtr parser_ctxt = NULL; // the parser context
	int parser_options;
	xmlDocPtr conf_doc = NULL; // the configuration xml document tree
	xmlNodePtr role_node = NULL; //The role xml node

	//Check that urc contains at least a role (or a command) & a user
	if ((urc->role == NULL && urc->command == NULL) || urc->user == NULL) {
		errno = EINVAL;
		return_code = -2;
		goto free_rscs;
	}
	//Create a parser context
	if ((parser_ctxt = xmlNewParserCtxt()) == NULL) {
		return_code = -1;
		goto free_rscs;
	}
	//open and read the xml configuration file
	parser_options = XML_PARSE_DTDVALID;
#ifndef SR_DEBUG
	//When not on debug, inhibit warning and error printout from libxml
	parser_options |= XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
#endif
	if ((conf_doc = xmlCtxtReadFile(parser_ctxt, USER_CAP_FILE_ROLE, NULL,
					parser_options)) == NULL) {
		errno = EINVAL;
		return_code = -3;
		goto free_rscs;
	}
	//Check if the XML file is valid regarding the DTD
	if (parser_ctxt->valid == 0) {
		errno = EINVAL;
		return_code = -4;
		goto free_rscs;
	}
	//find the role node in the configuration file
	//(if the return is -2: role not found, otherwise: other error)
	if (urc->role == NULL) {
		xmlXPathContextPtr context = xmlXPathNewContext(conf_doc);
		ret_fct = find_role_by_command(context, urc, &role_node);
		xmlXPathFreeContext(context);
		int string_len;
		xmlChar *xrole;
		switch (ret_fct) {
		case 0:
			xrole = xmlNodeGetContent(
				role_node->properties->children);
			string_len = strlen((char *)xrole) + 1;
			if ((urc->role = malloc(string_len * sizeof(char))) ==
			    NULL)
				goto free_rscs;
			strncpy(urc->role, (char *)xrole, string_len);
			break;
		case -1:
			return_code = -7; // command not found/allowed
			goto free_rscs;
		case -2:
			errno = EACCES;
			return_code = -6;
			goto free_rscs;
		default:
			errno = EINVAL;
			return_code = -4;
			goto free_rscs;
		}
		xmlFree(xrole);
	} else {
		ret_fct = get_role(conf_doc, urc->role, &role_node);
		switch (ret_fct) {
		case 0:
			break;
		case -1:
			return_code = -1;
			goto free_rscs;
		case -2:
			errno = EINVAL;
			return_code = -5;
			goto free_rscs;
		default:
			errno = EINVAL;
			return_code = -4;
			goto free_rscs;
		}
	}
	//Attemp to match the user or one of the groups with the role
	//(and take also care of the command if needed)
	ret_fct = check_urc_valid_for_role(urc, role_node);
	switch (ret_fct) {
	case 0:
		break;
	case -1:
		return_code = -1;
		goto free_rscs;
	case -2:
		errno = EACCES;
		return_code = -6;
		goto free_rscs;
	default:
		errno = EINVAL;
		return_code = -4;
		goto free_rscs;
	}
	//Fill the urc structure with the roles capabilities
	ret_fct = complete_role_capabilities(urc, role_node);
	switch (ret_fct) {
	case 0:
		break;
	case -1:
		return_code = -1;
		goto free_rscs;
	default:
		errno = EINVAL;
		return_code = -4;
		goto free_rscs;
	}
	//Success
	return_code = 0;

free_rscs:
	if (conf_doc != NULL) {
		xmlFreeDoc(conf_doc);
	}
	xmlFreeParserCtxt(parser_ctxt);
	return return_code;
}

/*
Given an urc (user/groups-role), print if he/she can use the role 
(whatever the command is in urc). In this case, and if needed, 
also print the commands he/she can use with that role.
return :
0: success
-2 (EINVAL): missing mandatory parameter (either role or user)
-3 (ENOENT): missing configuration file
-4 (EINVAL): the configuration file is invalid
-5 (EINVAL): the role does not exists
-6 (EACCES): the role cannot be use with that user or his groups or with 
that command
-1 other error (errno will be set)
*/
int print_capabilities(user_role_capabilities_t *urc)
{
	int return_code = -1; //the return code of the function
	xmlParserCtxtPtr parser_ctxt = NULL; // the parser context
	int parser_options;
	xmlDocPtr conf_doc = NULL; // the configuration xml document tree
	xmlXPathContextPtr context = NULL;
	//Check that urc contains at least a user
	if (urc->user == NULL) {
		errno = EINVAL;
		return_code = -2;
		goto free_rscs;
	}
	//Create a parser context
	if ((parser_ctxt = xmlNewParserCtxt()) == NULL) {
		return_code = -1;
		goto free_rscs;
	}
	//open and read the xml configuration file
	parser_options = XML_PARSE_DTDVALID;
#ifndef SR_DEBUG
	//When not on debug, inhibit warning and error printout from libxml
	parser_options |= XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
#endif
	if ((conf_doc = xmlCtxtReadFile(parser_ctxt, USER_CAP_FILE_ROLE, NULL,
					parser_options)) == NULL) {
		errno = EINVAL;
		return_code = -3;
		goto free_rscs;
	}
	//Check if the XML file is valid regarding the DTD
	if (parser_ctxt->valid == 0) {
		errno = EINVAL;
		return_code = -4;
		goto free_rscs;
	}
	context = xmlXPathNewContext(conf_doc);
	//TODO: Refactoring
	if(urc->role != NULL && urc->command != NULL){ //command and role specified
		return_code = print_match_commandAndRole(urc,conf_doc);
		goto free_rscs;
	} else if(urc->role != NULL){ //role only
		return_code = print_match_RoleOnly(urc,conf_doc);
	}else if(urc->command != NULL){ //command only
		char *expressionBaseFormat = "//role[users/user[@name=%1$c%2$s%1$c] or groups/group[not(@name)]]%3$s";
		char *expressionExplicitFormat = "[users/user/commands/command/text()=%1$c%2$s%1$c or groups/group/commands/command/text()=%1$c%2$s%1$c]";
		char *expressionNonExplicitFormat = "[count(users/user/commands)=0 and count(groups/group/commands)=0]";

		char *tmpUser = encodeXml(urc->user,0);
		char *expressionGroupFormat = format_groups(urc->groups,urc->nb_groups,expressionBaseFormat);
		char *tmpCommand = encodeXml(urc->command,0);
		char *tmpexpressionExplicitFormat = (char*)malloc(strlen(expressionGroupFormat)+strlen(tmpUser)+strlen(expressionExplicitFormat)-3);
		char *expressionExplicit = (char*)malloc(strlen(expressionGroupFormat)-4+strlen(tmpUser)+strlen(expressionExplicitFormat)-8+strlen(tmpCommand)*2+1*sizeof(char));
		sprintf(tmpexpressionExplicitFormat,expressionGroupFormat,get_quote(urc->user),tmpUser,expressionExplicitFormat);
		sprintf(expressionExplicit,tmpexpressionExplicitFormat,get_quote(urc->command),tmpCommand);

		char *expressionNonExplicit = (char*)malloc(strlen(expressionGroupFormat)-4+strlen(tmpUser)+strlen(expressionNonExplicitFormat)+1*sizeof(char));
		sprintf(expressionNonExplicit,expressionGroupFormat,get_quote(urc->user),tmpUser,expressionNonExplicitFormat);
		xmlXPathObjectPtr resultExplicit = xmlXPathEvalExpression((xmlChar*)expressionExplicit,context);
		xmlXPathObjectPtr resultNonExplicit = xmlXPathEvalExpression((xmlChar*)expressionNonExplicit,context);
		if(resultExplicit != NULL && resultExplicit->nodesetval->nodeNr > 0){
			printf("As user \"%s\", you can execute this command :\n  sr -c \"%s\"\n",urc->user,urc->command);
			print_role_caps(urc,resultExplicit->nodesetval->nodeTab[0]);
		}else if(resultNonExplicit != NULL && resultNonExplicit->nodesetval->nodeNr > 0){
			printf("As user \"%s\" you can execute this command with these roles :",urc->user);
			print_roles(urc,resultNonExplicit);
		}else{
			printf("As user \"%s\" you can't execute this command\n",urc->user);
		}
		free(tmpUser);
		free(expressionGroupFormat);
		free(tmpCommand);
		free(tmpexpressionExplicitFormat);
		free(expressionExplicit);
		free(expressionNonExplicit);
		if(resultExplicit != NULL)xmlXPathFreeObject(resultExplicit);
		if(resultNonExplicit != NULL)xmlXPathFreeObject(resultNonExplicit);
	}else{ // no command, no role
		//user managing
		char *expressionRoleFormat="//role[%1$susers/user[@name=%2$c%3$s%2$c]%4$s]"; //arg 1 and 3 is for appending group conditions
		char *tmpUser = encodeXml(urc->user,1);
		char *expressionUser=(char*)malloc(strlen(expressionRoleFormat)-2+strlen(tmpUser)+1 * sizeof(char));
		sprintf(expressionUser,expressionRoleFormat,"",get_quote(urc->user),tmpUser,"");
		xmlXPathObjectPtr resultUser = xmlXPathEvalExpression((xmlChar*)expressionUser,context);

		//group managing, removing already user roles directly in query
		char *expressionGroupAppend="groups/group[not(@name)] and not("; // we append at argument 1 search roles that in group but not in user (remove duplicatas)
		char *expressionGroup = format_groups(urc->groups,urc->nb_groups,expressionGroupAppend);
		char *expression = malloc(strlen(expressionGroup)+strlen(expressionUser)+2*sizeof(char));
		sprintf(expression,expressionRoleFormat,expressionGroup,get_quote(urc->user),tmpUser,")");
		xmlXPathObjectPtr resultGroup = xmlXPathEvalExpression((xmlChar*)expression,context);

		int verifyUser = resultUser != NULL && resultUser->nodesetval->nodeNr > 0;
		int verifyGroup = resultGroup != NULL && resultGroup->nodesetval->nodeNr > 0;
		if(verifyUser||verifyGroup){
			printf("As user %s :",urc->user);
			if(verifyUser)print_roles(urc,resultUser); //print user roles
			if(verifyGroup)print_roles(urc,resultGroup); //print group without user roles
		}
		free(tmpUser);
		free(expressionUser);
		free(expressionGroup);
		free(expression);
		xmlXPathFreeObject(resultGroup);
		xmlXPathFreeObject(resultUser);
	}
	return_code = 0;
	free_rscs:
	if(context != NULL)xmlXPathFreeContext(context);
	if (conf_doc != NULL) {
		xmlFreeDoc(conf_doc);
	}
	if (parser_ctxt != NULL) {
		xmlFreeParserCtxt(parser_ctxt);
	}
	xmlCleanupParser();
	return return_code;
}

/**
 * If only role is specified then get role and print details of his informations
 */
static int print_match_RoleOnly(user_role_capabilities_t *urc, xmlDocPtr conf_doc){
	int return_code = -1;
	xmlNodePtr role_node = NULL; //The role xml node
	int ret_fct = get_role(conf_doc, urc->role, &role_node);
	switch (ret_fct) {
	case 0:
		break;
	case -1:
		return_code = -1;
		goto free_rscs;
	case -2:
		errno = EINVAL;
		return_code = -5;
		goto free_rscs;
	default:
		errno = EINVAL;
		return_code = -4;
		goto free_rscs;
	}
	printf("As user %s :",urc->user);
	print_role(urc,role_node);
	return_code = 0;
	free_rscs:
	return return_code;
}

/**
 * If command and role is specified in urc then print if user can perform this command
 */
static int print_match_commandAndRole(user_role_capabilities_t *urc, xmlDocPtr conf_doc){
	int return_code = -1;
	int any_command = 0;
	chained_commands commands = NULL;
	xmlNodePtr role_node = NULL; //The role xml node
	int ret_fct = get_role(conf_doc, urc->role, &role_node);
	switch (ret_fct) {
	case 0:
		break;
	case -1:
		return_code = -1;
		goto free_rscs;
	case -2:
		errno = EINVAL;
		return_code = -5;
		goto free_rscs;
	default:
		errno = EINVAL;
		return_code = -4;
		goto free_rscs;
	}
	add_user_commands(urc,role_node,&any_command,&commands);
	if(!any_command)add_groups_commands(urc,role_node,&any_command,&commands);
	switch(check_urc_valid_for_role(urc,role_node)){
		case 0:
			printf("As user \"%s\" you can execute \"%s\" with this simplified command :\n  sr -c \"%s\"\n",urc->user,urc->command,urc->command);
			goto free_rscs;
		case -1:
			return_code = -1;
			goto free_rscs;
		case -2:
			if(any_command){
				printf("As user \"%s\" you can execute \"%s\" with command :\n  sr -r \"%s\" -c \"%s\"\n",urc->user,urc->command,urc->role,urc->command);
			}else printf("As user \"%s\" you can't execute this command\n",urc->user);
			goto free_rscs;
		default:
			errno = EINVAL;
			return_code = -4;
			goto free_rscs;
	}
	return_code = 0;

	free_rscs:
	cc_free_it(commands);
	return return_code;
}

static void print_roles(user_role_capabilities_t *urc,xmlXPathObjectPtr result){
	xmlNodePtr role_node = NULL; //The role xml node
	for(int i = 0; i<result->nodesetval->nodeNr;i++){
		role_node = result->nodesetval->nodeTab[i]; 
		print_role(urc,role_node);
	}
}

static void print_role(user_role_capabilities_t *urc,xmlNodePtr role_node){
	chained_commands command_list = NULL, tmp = NULL; //The list of command
	int any_user_command=0, any_group_command=0;
	int ret_fct = -1;
	xmlChar *name=xmlGetProp(role_node,(xmlChar *)"name");
	switch(ret_fct = add_user_commands(urc,role_node,&any_user_command,&command_list)){
		case -2:
		case 0 : break;
		default: 
			perror("error occur");
			goto free_error;
		case -3:
			perror("error occur on xml parsing");
			goto free_error;
	}
	switch(add_groups_commands(urc,role_node,&any_group_command,&command_list)){
		case 0: break;
		case -2:
			if(ret_fct == -2){
				printf("\nYou can't use the role \"%s\"\n",name);
				goto free_error;
			}
			break;
		case -3:
			perror("error occur on xml parsing");
			goto free_error;
		default: 
			perror("error occur");
			goto free_error;
	}
	printf("\n- you can use the role \"%s\" ",(char*)name);
		if(any_user_command||any_group_command){
			printf("with any commands\n");
		}else if(command_list!=NULL){
			tmp = command_list;
			printf("only with these commands : \n");
			while(tmp != NULL){
				printf("  - %s\n",tmp->command);
				tmp = tmp->next;
			}
		}else {
			printf("without any commands");
		}
		print_role_caps(urc, role_node);
	free_error:
	free(name);
	cc_free_it(command_list);
	free(urc->caps.capabilities);
	urc->caps.nb_caps = 0;
}

static void print_role_caps(user_role_capabilities_t *urc,const xmlNodePtr role_node){
	switch(complete_role_capabilities(urc,role_node)){
	case 0:
		if(urc->caps.nb_caps-1 == CAP_LAST_CAP){
			printf("  and grants full privileges\n");
		}else if (urc->caps.nb_caps > 0){
			char *caps = cap_list_to_text(urc->caps.nb_caps,urc->caps.capabilities);
			printf("  and grants these privileges :\n  %s\n",caps);
			free(caps);
		}else
			printf("  and doesn't grant any privileges\n");
		break;
	case -3:
		perror("an error occured when reading configuration file");
		break;
	default:
		perror("an unkown error occured");
		break;
	}
}

/* 
Printout on stdout a user_role_capabilities_t
*/
void print_urc(const user_role_capabilities_t *urc)
{
	int i;
	char *cap_name;

	if (urc == NULL) {
		printf("URC NULL\n");
		return;
	}
	printf("--- BEGIN URC ---\n");
	printf("Role: ");
	if (urc->role == NULL) {
		printf("[None]\n");
	} else {
		printf("%s\n", urc->role);
	}

	printf("User: ");
	if (urc->user == NULL) {
		printf("[None]\n");
	} else {
		printf("%s\n", urc->user);
	}

	printf("Groups: ");
	if (urc->nb_groups == 0) {
		printf("[None]\n");
	} else {
		for (i = 0; i < urc->nb_groups; i++) {
			printf("%s ", urc->groups[i]);
		}
		printf("\n");
	}

	printf("Command: ");
	if (urc->command == NULL) {
		printf("[None]\n");
	} else {
		printf("%s\n", urc->command);
	}

	printf("Capabilities: ");
	if (urc->caps.nb_caps == 0) {
		printf("[None]\n");
	} else {
		for (i = 0; i < urc->caps.nb_caps; i++) {
			cap_name = cap_to_name(urc->caps.capabilities[i]);
			if (cap_name == NULL) {
				printf("Cannot have cap name for %d\n",
				       urc->caps.capabilities[i]);
			} else {
				printf("%d: %s\n", urc->caps.capabilities[i],
				       cap_name);
			}
			cap_free(cap_name);
		}
		printf("\n");
	}
	printf("--- END URC ---\n");
}

/******************************************************************************
 *                      PRIVATE FUNCTIONS DEFINITION                          *
 ******************************************************************************/

/*
Create a new iterator on collection nodes: an xml structure composed of a node
of name collection_name that includes nodes of name element_name. The
collection node is intended to be a child of node.
return the iterator on success, NULL on failure
*/
static xml_collection_iterator
new_xml_collection_iterator(xmlNodePtr node, const char *collection_name,
			    const char *element_name)
{
	xml_collection_iterator it;
	xmlChar *xml_col_name = NULL;
	//Allocate the iterator, the name of collection and the name of element
	if ((it = malloc(sizeof(struct _xml_collection_iterator))) == NULL ||
	    (xml_col_name = xmlCharStrdup(collection_name)) == NULL ||
	    (it->element_name = xmlCharStrdup(element_name)) == NULL) {
		goto free_rscs_on_error;
	}
	//Try to find the collection
	for (it->col_node = node->children; it->col_node != NULL;
	     it->col_node = it->col_node->next) {
		if (it->col_node->type == XML_ELEMENT_NODE &&
		    xmlStrEqual(it->col_node->name, xml_col_name)) {
			break;
		}
	}
	if (it->col_node != NULL) {
		//Try to find the first element of the collection
		for (it->cur_node = it->col_node->children;
		     it->cur_node != NULL; it->cur_node = it->cur_node->next) {
			if (it->cur_node->type == XML_ELEMENT_NODE &&
			    xmlStrEqual(it->cur_node->name, it->element_name)) {
				break;
			}
		}
	} else {
		it->cur_node = NULL;
	}
	goto free_rscs;

free_rscs_on_error:
	if (it != NULL) {
		if (it->element_name != NULL)
			free(it->element_name);
		free(it);
		it = NULL;
	}
free_rscs:
	if (xml_col_name != NULL)
		free(xml_col_name);
	return it;
}

/**
 * Free an chained_command struct
 */
static void cc_free_it(chained_commands commands){
	if(commands != NULL){
		struct chained_command *old_cmd_item;
		struct chained_command *cmd_item = commands;
		while (cmd_item != NULL) {
			old_cmd_item = cmd_item;
			cmd_item = cmd_item->next;
			if (old_cmd_item->command != NULL)
				free(old_cmd_item->command);
			free(old_cmd_item);
		}
	}
}

/*
Free an iterator on collection nodes
*/
static void xci_free_it(xml_collection_iterator it)
{
	if (it == NULL) {
		return;
	}
	if (it->element_name != NULL)
		free(it->element_name);
	free(it);
	return;
}

/*
return 1 if the iterator has a collection, 0 otherwise.
*/
static int xci_has_collection(xml_collection_iterator it)
{
	if (it->col_node != NULL) {
		return 1;
	} else {
		return 0;
	}
}

/*
return 1 if the iterator still has element of collection to iterate on, 
0 otherwise.
*/
static int xci_has_next(xml_collection_iterator it)
{
	if (it->cur_node != NULL) {
		return 1;
	} else {
		return 0;
	}
}

/*
Retrieve the next element of collection. Return NULL if no element is to 
iterate.
*/
static xmlNodePtr xci_next(xml_collection_iterator it)
{
	xmlNodePtr saved_node;
	if (it->cur_node == NULL) {
		return NULL;
	}
	saved_node = it->cur_node;
	for (it->cur_node = it->cur_node->next; it->cur_node != NULL;
	     it->cur_node = it->cur_node->next) {
		if (it->cur_node->type == XML_ELEMENT_NODE &&
		    xmlStrEqual(it->cur_node->name, it->element_name)) {
			break;
		}
	}
	return saved_node;
}

/*
Given a command, extract the program: do not take care of left spaces, neither
the right spaces and/or options related to the program.
Set begin_prg and len_prg and return 0 on success, or -1 on failure;
*/
static int extract_program_from_command(xmlChar *cmd, xmlChar **begin_prg,
					int *len_prg)
{
	//Strip left
	while (*cmd == ' ' && *cmd == '\t' && *cmd != '\0') {
		cmd++;
	}
	if (*cmd == '\0')
		return -1;
	*begin_prg = cmd;
	//Go until a space or the end is found
	while (*cmd != ' ' && *cmd != '\t' && *cmd != '\0') {
		cmd++;
	}
	*len_prg = cmd - *begin_prg;
	return 0;
}

/*
Return 1 if the given command match the referenced command, 0 otherwise
If the ref command does not include any options, thus any option in the given
command is allowed. Otherwise, the given command must match both the program
name and the sequence of options (in the same order!)
*/
static int is_command_allowed(xmlChar *c_ref, xmlChar *c_given)
{
	int len_c_ref;
	//program of commands relative variables
	xmlChar *b_p_ref, *b_p_given;
	int len_p_ref, len_p_given;

	//Extract c_ref's and c_given's programs
	if (extract_program_from_command(c_ref, &b_p_ref, &len_p_ref) ||
	    extract_program_from_command(c_given, &b_p_given, &len_p_given)) {
		return 0;
	}
	//Are c_ref c_given the same program?
	if (len_p_ref != len_p_given ||
	    xmlStrncmp(b_p_ref, b_p_given, len_p_ref)) {
		return 0;
	}
	//If c_ref only contains the command: any option is allowded
	len_c_ref = xmlStrlen(c_ref);
	if (b_p_ref + len_p_ref == c_ref + len_c_ref) {
		return 1;
	}
	//Otherwise, check that option sequence is EXACTLY the same
	//Length of ref seq of args is len_c_ref - len_p_ref - (b_p_ref - c_ref)
	if (xmlStrncmp(b_p_ref + len_p_ref, b_p_given + len_p_given,
		       len_c_ref - len_p_ref - (b_p_ref - c_ref))) {
		return 0;
	} else {
		return 1;
	}
}
/**
 * appends s2 to str with realloc, return new char*
 */
static char *concat(char *str, char *s2)
{
	int len = 0;
	char *s = NULL;
	if (str != NULL)
		len = strlen(str);
	len += strlen(s2) + 1 * sizeof(*s2);
	s = realloc(str, len);
	strcat(s, s2);
	return s;
}
/**
 * replace string s in position start to length character of ct
 * return the new char*
 */
static char *str_replace(const char *s, unsigned int start, unsigned int length,
			 const char *ct)
{
	char *new_s = NULL;
	size_t size = strlen(s);
	new_s = malloc(sizeof(*new_s) * (size - length + strlen(ct) + 1));
	if (new_s != NULL) {
		memmove(new_s, s, start);
		memmove(&new_s[start], ct, strlen(ct));
		memmove(&new_s[start + strlen(ct)], &s[start + length],
		       size - length - start + 1);
	}
	return new_s;
}

/**
 * obtain right quote to handle XPath eval
 */
static char get_quote(const char* str){
	if(strchr(str,'\'')!=NULL && strchr(str,'"')!=NULL)
		return -1;
	else if (strchr(str,'"')!=NULL)
		return '\'';
	else
		return '"';
}
/**
 * find right role with xpath searching for role user
 * return 0 if found, -1 if error, -2 if not found
 */
static int find_role_for_user(xmlXPathContextPtr context, char *user,const char *command,
			      xmlNodePtr *role_node)
{
	int return_code = -1;
	char *expressionFormatUser = expressionFormatUser = "//role[users/user[@name=%1$c%3$s%1$c]/commands/command/text()=%2$c%4$s%2$c]";
	char *tmpcommand = encodeXml(command,1);
	char *tmpuser = encodeXml(user,1);
	char *expression = (char *)malloc(strlen(expressionFormatUser) - 4 +
					  strlen(tmpuser) + strlen(tmpcommand) +
					  1 * sizeof(char));
	sprintf(expression, expressionFormatUser,get_quote(user),get_quote(command), tmpuser, tmpcommand);
	xmlXPathObjectPtr result = xmlXPathEvalExpression((xmlChar*)expression,context);
	if(result != NULL && result->nodesetval->nodeNr > 0){
		*role_node = result->nodesetval->nodeTab[0];
		return_code = 0;
	} else {
		return_code = -2;
	}
	xmlXPathFreeObject(result);
	if(tmpuser!=NULL)free(tmpuser);
	if(tmpcommand!=NULL)free(tmpcommand);
	free((xmlChar *)expression);
	return return_code;
}

/**
 * format groups to xpath OR expression to match every group of user
 * return xpath logical OR string of every group
 */
static char* xpath_format_groups(char** groups, int nb_groups){
	char *name = "@name = ";
	char *tmpgroups = calloc(strlen(name), sizeof(char));
	for (int i = 0; i < nb_groups; i++) {
		tmpgroups = concat(tmpgroups, name);
		char quote[2] = {get_quote(groups[i]),'\0'};
		tmpgroups = concat(tmpgroups,quote);
		char * xmlgroups =encodeXml(groups[i],1);
		tmpgroups = concat(tmpgroups, xmlgroups); //append group but encoding group name
		free(xmlgroups);
		tmpgroups = concat(tmpgroups,quote);
		if (i < nb_groups - 1)
			tmpgroups = concat(tmpgroups, " or ");
	}
	return tmpgroups;
}

/**
 * Return group formatted expression
 * this function will replace "not(@name)" string in tmpexpression to formatted group list
 * if nb_groups is empty, tmpexpression is returned
 * otherwise new string with formatted expression is returned
 */
static char *format_groups(char **groups,int nb_groups,char *tmpexpression){
	char* expression = NULL;
	if (nb_groups > 0) {
		char *tmpgroups = xpath_format_groups(groups,nb_groups);
		char *notname = "not(@name)";
		int position1 = strstr(tmpexpression, notname) -
				tmpexpression;
		expression = str_replace(tmpexpression, position1,
					    strlen(notname), tmpgroups);
		free(tmpgroups);
	}else return tmpexpression;
	return expression;
}

/**
 * This function will replace key to value in str
 */
static char* sanitizeCharTo(char *str,char key,char *value){
	char *position = strchr(str,key);
	if(position != NULL){
		int pos = position-str;
		char *new_command = NULL;
		while(position != NULL){
			new_command = str_replace(str,pos,1,value);
			free(str);
			str = new_command;
			position = strchr(&str[pos+strlen(value)],key);
			pos = position-str;
		}
	}
	return str;
}
/**
 * Sanitize string, escape unwanted chars to their xml equivalent
 * keep str same, return should be freed
 */
static char* encodeXml(const char* str, int quot){
	char *tmpstr = strdup(str);
	tmpstr = sanitizeCharTo(tmpstr,'&', "&amp;"); // check & before all
	tmpstr = sanitizeCharTo(tmpstr,'<',"&lt;");
	tmpstr = sanitizeCharTo(tmpstr,'>',"&gt;");
	return tmpstr;
}
/**
 * find right role with xpath searching for group user
 * return 0 if found, -1 if error, -2 if not found
 */
static int find_role_for_group(xmlXPathContextPtr context, char **groups, int nb_groups,
			       const char *command, xmlNodePtr *role_node)
{
	int return_code = -1;
	xmlXPathObjectPtr result;
	char *expression = NULL;
	char *expressionFormatGroup =
		"//role[groups/group[not(@name)]/commands/command/text()=%1$c%2$s%1$c]";
	char *tmpcommand = encodeXml(command,0); //escaping command
	char *tmpexpression = (char *)calloc(strlen(expressionFormatGroup) - 2 +
						     strlen(tmpcommand) + 1,
					     sizeof(char));
	if(get_quote(command) == -1){
		
	}
	sprintf(tmpexpression, expressionFormatGroup,get_quote(command), tmpcommand);
	expression = format_groups(groups,nb_groups,tmpexpression); //replace not(@name) to groups
	free(tmpexpression);
	result = xmlXPathEvalExpression((xmlChar *)expression,context);
	if (result != NULL && result->nodesetval->nodeNr > 0) {
		*role_node = result->nodesetval->nodeTab[0];
		return_code = 0;
	} else {
		return_code = -2;
	}
	if(tmpcommand!=NULL)free(tmpcommand);
	xmlXPathFreeObject(result);
	free((xmlChar *)expression);
	return return_code;
}
/**
 * find the first role that matching command, user and group
 * @return -2 if the role wasn't found
 */
static int find_role_by_command(xmlXPathContextPtr context,
				user_role_capabilities_t *urc,
				xmlNodePtr *role_node)
{
	int return_code = -1;
	*role_node = NULL;
	xmlXPathInit();
	//xpath for finding the right role, user and command easily
	return_code = find_role_for_user(context, urc->user, urc->command,
					 role_node);
	if (return_code) {
		return_code = find_role_for_group(context, urc->groups,
						  urc->nb_groups, urc->command,
						  role_node);
	}
	return return_code;
}

/*
Get the role node matchin the role name from the xml configuration file
Return 0 on success, -2 if the role does not exist, 
-3 if an error has been found in the xml doc, -1 if an other error happened.
If an error occured, *role_node will be NULL.
*/
static int get_role(xmlDocPtr conf_doc, const char *role, xmlNodePtr *role_node)
{
	int return_code = -1;
	xmlNodePtr root_element = NULL;
	xml_collection_iterator it_role;
	xmlChar *xml_name_attribute = NULL;
	xmlChar *xml_role = NULL;
	int role_found;

	//Init ou params
	*role_node = NULL;

	if ((xml_name_attribute = xmlCharStrdup("name")) == NULL ||
	    (xml_role = xmlCharStrdup(role)) == NULL) {
		goto free_rscs;
	}
	/*We do not need to verify the existence and name of the capabilityrole and 
    roles nodes as they are mandatory and the document has been validated*/
	root_element = xmlDocGetRootElement(conf_doc); //capabilityrole node
	//Create an iterator on roles-role collection
	if ((it_role = new_xml_collection_iterator(root_element, "roles",
						   "role")) == NULL) {
		goto free_rscs;
	}
	//Iterate to find role
	role_found = 0;
	while (xci_has_next(it_role) && !role_found) {
		*role_node = xci_next(it_role);
		xmlChar *name = xmlGetProp(*role_node, xml_name_attribute);
		if (name != NULL && xmlStrEqual(name, xml_role)) {
			role_found = 1;
		}
		free(name);
	}
	if (role_found) {
		return_code = 0;
	} else {
		*role_node = NULL;
		return_code = -2;
	}

free_rscs:
	if (it_role != NULL)
		xci_free_it(it_role);
	if (xml_name_attribute != NULL)
		free(xml_name_attribute);
	if (xml_role != NULL)
		free(xml_role);
	return return_code;
}

/*
For a given role node, check that the username or on of the groups are defined.
For those which are defined, if a set of commands are also present, check
that the commend given in the urc exists and is included in the configuration
definition.
Return 0 on success, -2 if no valid user/group have been found
-3 if an error has been found in the xml doc, -1 if an other error happened.
*/
static int check_urc_valid_for_role(user_role_capabilities_t *urc,
				    xmlNodePtr role_node)
{
	int return_fct;

	//Try to find a matching user node
	return_fct = find_matching_user_node(urc, role_node);
	switch (return_fct) {
	case -4: //user found, invalid command
		return -2;
	case -2: //no user found
		//find matching group node
		return find_matching_group_node(urc, role_node);
	default:
		return return_fct;
	}
}

/*
Find a user node that match user in a role_node, and whose command given
(or not) match the auhtorized command if needed.
Return 0 on success, -2 if no user have been found, -3 if an error
has been found in the xml doc, -4 if a user has been found but command invalid
-1 if an other error happened.
*/
static int find_matching_user_node(user_role_capabilities_t *urc,
				   const xmlNodePtr role_node)
{
	int return_code = -1;
	int user_found;
	xml_collection_iterator it_node;
	xmlChar *xml_item_name_attribute = NULL;
	xmlChar *xml_user = NULL;

	//Init xml char variables and user iterator
	if ((xml_item_name_attribute = xmlCharStrdup("name")) == NULL ||
	    (xml_user = xmlCharStrdup(urc->user)) == NULL ||
	    (it_node = new_xml_collection_iterator(role_node, "users",
						   "user")) == NULL) {
		goto free_rscs;
	}
	//If no collection of users: return -2
	if (!xci_has_collection(it_node)) {
		return_code = -2;
		goto free_rscs;
	}
	//Iterate over user nodes in users and try to find a matching one
	user_found = 0;
	while (xci_has_next(it_node) && !user_found) {
		xmlNodePtr user_node = xci_next(it_node);
		xmlChar *name = xmlGetProp(user_node, xml_item_name_attribute);
		if (name != NULL && xmlStrEqual(name, xml_user)) {
			user_found = 1;
			//for the user_node, check valid command if required
			return_code = check_valid_command_from_commands(
				urc, user_node);
		}
		free(name);
	}
	//If no matching user node: return -2 otherwise return_code is
	//already set with check_valid_command
	if (!user_found) {
		return_code = -2;
	} else if (return_code == -2) { //user found but command invalid
		return_code = -4;
	} //else nothing to do, return_code 0 or -1 already set by
	//check_valid_command

free_rscs:
	if (it_node != NULL)
		xci_free_it(it_node);
	if (xml_item_name_attribute != NULL)
		free(xml_item_name_attribute);
	if (xml_user != NULL)
		free(xml_user);
	return return_code;
}

/*
From a list of group in urc, find a group node that match one of the groups 
defined in a role_node, and whose command given (or not) match the auhtorized 
commands of the group if needed.
Return 0 on success, -2 if no valid group have been found, -3 if an error
has been found in the xml doc, -1 if an other error happened.
*/
static int find_matching_group_node(user_role_capabilities_t *urc,
				    const xmlNodePtr role_node)
{
	int return_code = -1;
	int i;
	int group_found;
	xml_collection_iterator it_node;
	xmlChar *xml_item_name_attribute = NULL;
	xmlChar **xml_groups = NULL;

	//First, test if there is any group to test
	if (urc->nb_groups <= 0) {
		return_code = -2;
		goto free_rscs;
	}

	//Init xml char variables and iterator
	if ((xml_item_name_attribute = xmlCharStrdup("name")) == NULL ||
	    (xml_groups = calloc(urc->nb_groups, sizeof(xmlChar *))) == NULL ||
	    (it_node = new_xml_collection_iterator(role_node, "groups",
						   "group")) == NULL) {
		goto free_rscs;
	}
	for (i = 0; i < urc->nb_groups; i++) {
		if ((xml_groups[i] = xmlCharStrdup(urc->groups[i])) == NULL) {
			goto free_rscs;
		}
	}
	//If no groups node: return -2
	if (!xci_has_collection(it_node)) {
		return_code = -2;
		goto free_rscs;
	}
	//Iterate over group nodes in groups and try to find a matching one
	group_found = 0;
	while (xci_has_next(it_node) && !group_found) {
		xmlNodePtr group_node = xci_next(it_node);
		xmlChar *name = xmlGetProp(group_node, xml_item_name_attribute);
		if (name != NULL) {
			//Iterate over groups to test
			for (i = 0; i < urc->nb_groups; i++) {
				if (xmlStrEqual(xml_groups[i], name)) {
					//Group found, now check if command is valid if required
					return_code =
						check_valid_command_from_commands(
							urc, group_node);
					switch (return_code) {
					case 0: //group match, command ok
						group_found = 1;
						break;
					case -2: //group match, command not ok
						break;
					default: //error happened
						goto free_rscs;
					}
					break; //group matched, quit the loop
				}
				//Group found, check valid command
			}
			free(name);
		}
	}
	//If no group found: return -2
	if (group_found == 0) {
		return_code = -2;
	} //Else, do nothing, return_code is already set with check_valid_command

free_rscs:
	if (it_node != NULL)
		xci_free_it(it_node);
	if (xml_item_name_attribute != NULL)
		free(xml_item_name_attribute);
	if (xml_groups != NULL) {
		for (i = 0; i < urc->nb_groups; i++) {
			if (xml_groups[i] != NULL)
				free(xml_groups[i]);
		}
		free(xml_groups);
	}
	return return_code;
}

/*
Check if command in urc is valid regarding the command definition of 
the node.
Return 0 on success, -2 command invalid, -3 if an error
has been found in the xml doc, -1 if an other error happened.
A command is valid if urc->command is NULL and no command are defined in 
the node OR if urc->command is among the commands defined in the node.
*/
static int check_valid_command_from_commands(user_role_capabilities_t *urc,
					     xmlNodePtr matching_item_node)
{
	int return_code = -1;
	xml_collection_iterator it_node;
	xmlChar *xml_given_command = NULL;
	int command_found;

	//Init iterator and xmlChar
	if ((it_node = new_xml_collection_iterator(
		     matching_item_node, "commands", "command")) == NULL) {
		goto free_rscs;
	}
	//If no commands node: return 0
	if (!xci_has_collection(it_node)) {
		return_code = 0;
		goto free_rscs;
	} else if (urc->command ==
		   NULL) { //commands are defined, but no given command
		return_code = -2;
		goto free_rscs;
	}
	//Here, commands are defined and a command is given: test it
	if ((xml_given_command = xmlCharStrdup(urc->command)) == NULL) {
		goto free_rscs;
	}
	//Iterate over command nodes in commands and try to find a matching one
	command_found = 0;
	while (xci_has_next(it_node) && !command_found) {
		xmlNodePtr cur_node = xci_next(it_node);
		xmlNodePtr textNode;
		//Retrieve the command text : should be in the first text child node
		for (textNode = cur_node->children;
		     textNode != NULL && !command_found;
		     textNode = textNode->next) {
			if (xmlNodeIsText(textNode)) {
				xmlChar *text = xmlNodeGetContent(textNode);
				//Is the given command allowed by the current one?
				command_found =
					is_command_allowed(text,
							   xml_given_command) ?
						1 :
						0;
				free(text);
			}
		}
	}
	//If the command was found return 0, -2 otherwise
	if (command_found) {
		return_code = 0;
	} else {
		return_code = -2;
	}

free_rscs:
	if (it_node != NULL)
		xci_free_it(it_node);
	if (xml_given_command != NULL)
		free(xml_given_command);
	return return_code;
}

/*
Complete the urc with the capabilities defined in the role node.
As the same time, validate capabilities: ensure they are defined in libcap 
and that the kernel can handle them.
Return 0 on success, -3 if an error has been found in the xml doc, 
-1 if an other error happened.
*/
static int complete_role_capabilities(user_role_capabilities_t *urc,
				      xmlNodePtr role_node)
{
	int return_code = -1;
	xml_collection_iterator it_node;
	int *capability_dict =
		NULL; //An array where index represent capabilities
		//and value if it is defined or not
	size_t i, k;
	int early_cap_stop; //indicator to stop looking for caps if "*" have been found
	xmlChar *all_cap_token = NULL;

	//Init output params
	urc->caps.nb_caps = 0;
	urc->caps.capabilities = NULL;

	//Init iterator
	if ((it_node = new_xml_collection_iterator(role_node, "capabilities",
						   "capability")) == NULL ||
	    (all_cap_token = xmlCharStrdup("*")) == NULL) {
		goto free_on_error;
	}
	//If no commands node: accepted (no caps) return 0
	if (!xci_has_collection(it_node)) {
		return_code = 0;
		goto free_rscs;
	}
	//Create an array of CAP_LAST_DEFINED capabilities to remove duplicates
	//and avoid multiple invocation
	if ((capability_dict = calloc(CAP_LAST_CAP + 1, sizeof(int))) == NULL) {
		goto free_on_error;
	}
	//Iterate over capability node in the capabilities node
	//Stop if all cap token has been found
	early_cap_stop = 0;
	while (xci_has_next(it_node) && !early_cap_stop) {
		xmlNodePtr cur_node = xci_next(it_node);
		xmlNodePtr textNode;
		for (textNode = cur_node->children;
		     textNode != NULL && !early_cap_stop;
		     textNode = textNode->next) {
			if (xmlNodeIsText(textNode)) {
				xmlChar *cap_text = xmlNodeGetContent(textNode);
				cap_value_t cap_val;
				//If cap_text is '*', the load all available caps
				if (xmlStrEqual(all_cap_token, cap_text)) {
					for (i = 0; i <= CAP_LAST_CAP; i++) {
						capability_dict[i] = 1;
					}
					//will stop looping as all caps have been set
					early_cap_stop = 1;
				} else {
					//Attempt to convert cap_text to cap_value
					//WARNING : cast should be safe so far..
					if (cap_from_name((char *)cap_text,
							  &cap_val)) {
						fprintf(stderr,
							"Warning: capability '%s' not handled by the system\n",
							cap_text);
					} else {
						//Set the cap in the dict to 1
						capability_dict[cap_val] = 1;
					}
				}
				free(cap_text);
			}
		}
	}
	//count the caps to alloc capabilities array in urc
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		if (capability_dict[i] == 1) {
			urc->caps.nb_caps++;
		}
	}
	//Alloc and fill the capabilities array
	if ((urc->caps.capabilities =
		     malloc(urc->caps.nb_caps * sizeof(cap_value_t))) == NULL) {
		goto free_on_error;
	}
	k = 0;
	for (i = 0; i <= CAP_LAST_CAP; i++) {
		if (capability_dict[i] == 1) {
			urc->caps.capabilities[k++] = i;
		}
	}
	return_code = 0;
	goto free_rscs;

free_on_error: //Free resources on failure specifially
	if (urc->caps.capabilities != NULL)
		free(urc->caps.capabilities);
	urc->caps.capabilities = NULL;
	urc->caps.nb_caps = 0;
free_rscs: //Free resources on success or failure
	if (it_node != NULL)
		xci_free_it(it_node);
	if (capability_dict != NULL)
		free(capability_dict);
	if (all_cap_token != NULL)
		free(all_cap_token);
	return return_code;
}

/******************************************************
* Specific functions for printing information on role *
******************************************************/

/*
Copy a command to the list if it does not already belong to the list.
Return 0 on success, -1 if an error happened.
*/
static int add_unique_command_to_list(xmlChar *command,
				      chained_commands *chained_commands)
{
	struct chained_command *cmd;

	//parse the existing list and try to find a duplicate of the command
	for (cmd = *chained_commands; cmd != NULL; cmd = cmd->next) {
		if (xmlStrEqual(cmd->command, command)) {
			return 0;
		}
	}
	//Create a new entry on the top of the list with a copy of the command
	if ((cmd = malloc(sizeof(struct chained_command))) == NULL) {
		return -1;
	}
	if ((cmd->command = xmlStrdup(command)) == NULL) {
		free(cmd);
		return -1;
	}
	cmd->next = *chained_commands;
	*chained_commands = cmd;
	return 0;
}

/*
For a given node, add the available commands to the list and set any_command to 0
if no command are defined the any_command is set to 1.
Return 0 on success, -3 if an error has been found in the xml doc, 
or -1 if an other error happened.
*/
static int add_node_commands(const xmlNodePtr node, int *any_command,
			     chained_commands *commands)
{
	int return_code = -1;
	xml_collection_iterator it_node;

	//Init iterator
	if ((it_node = new_xml_collection_iterator(node, "commands",
						   "command")) == NULL) {
		goto free_rscs;
	}
	//If no commands node: set any_command to 1 and return 0
	if (!xci_has_collection(it_node)) {
		*any_command = 1;
		return_code = 0;
		goto free_rscs;
	} else {
		*any_command = 0;
	}
	//Iterate over command nodes in commands and them to the list
	while (xci_has_next(it_node)) {
		xmlNodePtr cur_node = xci_next(it_node);
		xmlNodePtr textNode;
		int ret_fct = 0;
		//Retrieve the command text : should be in the first text child node
		for (textNode = cur_node->children; textNode != NULL;
		     textNode = textNode->next) {
			if (xmlNodeIsText(textNode)) {
				xmlChar *text = xmlNodeGetContent(textNode);
				//Add the text to the command list
				ret_fct = add_unique_command_to_list(text,
								     commands);
				free(text);
				if (ret_fct) {
					goto free_rscs;
				}
			}
		}
	}
	return_code = 0;

free_rscs:
	if (it_node != NULL)
		xci_free_it(it_node);
	return return_code;
}

/*
For the given user in urc, add the available commands to the list commands
if the user exist in the role node 
Return 0 on success, -2 if no valid user have been found, -3 if an error
has been found in the xml doc, -1 if an other error happened.
*/
static int add_user_commands(user_role_capabilities_t *urc,
			     const xmlNodePtr role_node, int *any_command,
			     chained_commands *commands)
{
	int return_code = -1;
	xml_collection_iterator it_node;
	int user_found;
	xmlChar *xml_item_name_attribute = NULL;
	xmlChar *xml_user = NULL;

	//Init output
	*any_command = 0;
	//Init xml char variables and iterator
	if ((it_node = new_xml_collection_iterator(role_node, "users",
						   "user")) == NULL ||
	    (xml_item_name_attribute = xmlCharStrdup("name")) == NULL ||
	    (xml_user = xmlCharStrdup(urc->user)) == NULL) {
		goto free_rscs;
	}
	//If no users node: return -2
	if (!xci_has_collection(it_node)) {
		return_code = -2;
		goto free_rscs;
	}
	//Iterate over user nodes in users and try to find a matching one
	user_found = 0;
	while (xci_has_next(it_node) && !user_found) {
		xmlNodePtr cur_node = xci_next(it_node);
		xmlChar *name = xmlGetProp(cur_node, xml_item_name_attribute);
		if (name != NULL && xmlStrEqual(name, xml_user)) {
			user_found = 1;
			//Add the command of user or set any_command
			return_code = add_node_commands(cur_node, any_command,
							commands);
		}
		free(name);
	}
	//If no matching user node: return -2
	if (!user_found) {
		return_code = -2;
		goto free_rscs;
	} //else return_code is already set with add_node_commands

free_rscs:
	if (it_node != NULL)
		xci_free_it(it_node);
	if (xml_item_name_attribute != NULL)
		free(xml_item_name_attribute);
	if (xml_user != NULL)
		free(xml_user);
	return return_code;
}

/*
Add the available commands of the groups node that match one of groups 
in a role_node. If one of the matching group does not have any restriction on
commands, set any_command to 1 and stop as soon as possible. Otherwise,
set any_command to 0.
Return 0 on success, -2 if no valid group have been found, -3 if an error
has been found in the xml doc, -1 if an other error happened.
*/
static int add_groups_commands(user_role_capabilities_t *urc,
			       const xmlNodePtr role_node, int *any_command,
			       chained_commands *commands)
{
	int return_code = -1;
	int i;
	int group_found;
	xml_collection_iterator it_node;
	xmlChar *xml_item_name_attribute = NULL;
	xmlChar **xml_groups = NULL;

	//Init output
	*any_command = 0;
	//First, test if there is any group to test
	if (urc->nb_groups <= 0) {
		return_code = -2;
		goto free_rscs;
	}
	//Init xml char variables and iterator
	if ((it_node = new_xml_collection_iterator(role_node, "groups",
						   "group")) == NULL ||
	    (xml_item_name_attribute = xmlCharStrdup("name")) == NULL ||
	    (xml_groups = calloc(urc->nb_groups, sizeof(xmlChar *))) == NULL) {
		goto free_rscs;
	}
	for (i = 0; i < urc->nb_groups; i++) {
		if ((xml_groups[i] = xmlCharStrdup(urc->groups[i])) == NULL) {
			goto free_rscs;
		}
	}
	//If no groups node: return -2
	if (!xci_has_collection(it_node)) {
		return_code = -2;
		goto free_rscs;
	}
	//Iterate over group nodes in groups and try to find a matching one
	group_found = 0;
	*any_command = 0; //Initialize any_command here
	while (xci_has_next(it_node)) {
		xmlNodePtr cur_node = xci_next(it_node);
		xmlChar *name = xmlGetProp(cur_node, xml_item_name_attribute);
		int a_group_found = 0;
		if (name != NULL) {
			//Iterate over group to test
			for (i = 0; i < urc->nb_groups; i++) {
				if (xmlStrEqual(xml_groups[i], name)) {
					//Group found, add commands to the list
					a_group_found = 1;
					return_code =
						add_node_commands(cur_node,
								  any_command,
								  commands);
					break;
				}
			}
			free(name);
		}
		//If group was found, break if return_code != 0 or update any_command
		if (a_group_found) {
			if (return_code) {
				break;
			} else {
				group_found = 1;
				if (*any_command) {
					break; //stop here: one group with any command was found
				}
			}
		}
	}
	//If no group found: reset group command indicator & return -2
	if (group_found == 0) {
		*any_command = 0;
		return_code = -2;
	} //Else, do nothing, return_code is already set

free_rscs:
	if (it_node != NULL)
		xci_free_it(it_node);
	if (xml_item_name_attribute != NULL)
		free(xml_item_name_attribute);
	if (xml_groups != NULL) {
		for (i = 0; i < urc->nb_groups; i++) {
			if (xml_groups[i] != NULL)
				free(xml_groups[i]);
		}
		free(xml_groups);
	}
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