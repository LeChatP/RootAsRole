/*
 * <roles.h>
 *
 * This file contains the definitions of roles management functions.
 *
 * Note, the copyright+license information is at end of file.
 */
#include "roles.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

extern int errno;

/******************************************************************************
 *                      PRIVATE STRUCTURE DEFINITION                          *
 ******************************************************************************/

//Internal Chained list of commands (for printout only)
struct chained_command{
    xmlChar *command;
    struct chained_command *next;
};

typedef struct chained_command *chained_commands;

//Internal iterator on collections nodes
struct _xml_collection_iterator{
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
static xml_collection_iterator new_xml_collection_iterator(xmlNodePtr node, 
        const char * collection_name, const char * element_name);

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
Get the role node matchin the role name from the xml configuration file
Return 0 on success, -2 if the role does not exist, 
-3 if an error has been found in the xml doc, -1 if an other error happened.
If an error occured, *role_node will be NULL.
*/
static int get_role(xmlDocPtr conf_doc, const char* role, 
                    xmlNodePtr *role_node);

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
static int check_valid_command(user_role_capabilities_t *urc, 
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
int init_urc(const char *role, const char *user, int nb_groups,
             char **groups, user_role_capabilities_t **urc){
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
                    user_role_capabilities_t **urc){
    int string_len;
    if((*urc = malloc(sizeof(user_role_capabilities_t))) == NULL){
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
    if(role != NULL){
        string_len = strlen(role) + 1;
        if(((*urc)->role = malloc(string_len * sizeof(char))) == NULL)
            goto free_on_error;
        strncpy((*urc)->role, role, string_len);
    }
    if(command != NULL){
        string_len = strlen(command) + 1;
        if(((*urc)->command = malloc(string_len * sizeof(char))) == NULL)
            goto free_on_error;
        strncpy((*urc)->command, command, string_len);
    }
    if(user != NULL){
        string_len = strlen(user) + 1;
        if(((*urc)->user = malloc(string_len * sizeof(char))) == NULL)
            goto free_on_error;
        strncpy((*urc)->user, user, string_len);
    }
    if(nb_groups > 0){
        char **ptrGpDst, **ptrGpSrc;
        if(((*urc)->groups = calloc(nb_groups, sizeof(char*))) == NULL)
            goto free_on_error;
        for (ptrGpDst = (*urc)->groups, ptrGpSrc = groups; 
                ptrGpDst < (*urc)->groups + nb_groups; ptrGpDst++, ptrGpSrc++){
            int gp_len = strlen(*ptrGpSrc) + 1;
            if((*ptrGpDst = malloc(gp_len * sizeof(char))) == NULL)
                goto free_on_error;
            strncpy(*ptrGpDst, *ptrGpSrc, gp_len);
        }
    }
    return 0;
    
  free_on_error:
    if(*urc != NULL)
        free_urc(*urc);
    return -1;
}

/* 
Deallocate a user_role_capabilities_t
Always return 0.
*/
int free_urc(user_role_capabilities_t *urc){
    if(urc == NULL){
        return 0;
    }
    if(urc->role != NULL)
        free(urc->role);
    if(urc->command != NULL)
        free(urc->command);
    if(urc->user != NULL)
        free(urc->user);
    if(urc->nb_groups > 0 && urc->groups != NULL){
        int i;
        for(i = 0; i < urc->nb_groups; i++){
            if(urc->groups[i] != NULL)
                free(urc->groups[i]);
        }
        free(urc->groups);
    }
    if(urc->caps.nb_caps > 0){
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
int get_capabilities(user_role_capabilities_t *urc){
    int return_code = -1; //the return code of the function
    int ret_fct; //return of sub functions
    xmlParserCtxtPtr parser_ctxt = NULL; // the parser context
    int parser_options;
    xmlDocPtr conf_doc = NULL; // the configuration xml document tree
    xmlNodePtr role_node = NULL; //The role xml node
    
    //Check that urc contains at least a role & a user
    if(urc->role == NULL || urc->user == NULL){
        errno = EINVAL;
        return_code = -2;
        goto free_rscs;
    }
    //Create a parser context
    if((parser_ctxt = xmlNewParserCtxt()) == NULL){
        return_code = -1;
        goto free_rscs;
    }
    //open and read the xml configuration file
    parser_options = XML_PARSE_DTDVALID;
    #ifndef SR_DEBUG
    //When not on debug, inhibit warning and error printout from libxml
    parser_options |= XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    #endif
    if((conf_doc = xmlCtxtReadFile(parser_ctxt, USER_CAP_FILE_ROLE, NULL, 
                                    parser_options)) == NULL){
        errno = EINVAL;
        return_code = -3;
        goto free_rscs;
    }
    //Check if the XML file is valid regarding the DTD
    if (parser_ctxt->valid == 0){ 
        errno = EINVAL;
        return_code = -4;
        goto free_rscs;
    }
    //find the role node in the configuration file
    //(if the return is -2: role not found, otherwise: other error)  
    ret_fct = get_role(conf_doc, urc->role, &role_node);
    switch(ret_fct){
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
    //Attemp to match the user or one of the groups with the role 
    //(and take also care of the command if needed)
    ret_fct = check_urc_valid_for_role(urc, role_node);
    switch(ret_fct){
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
    switch(ret_fct){
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
    if(conf_doc != NULL){
        xmlFreeDoc(conf_doc);
    }
    if(parser_ctxt != NULL){
        xmlFreeParserCtxt(parser_ctxt);
    }
    xmlCleanupParser();
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
int print_capabilities(user_role_capabilities_t *urc){
    int return_code = -1; //the return code of the function
    int ret_fct; //return of sub functions
    xmlParserCtxtPtr parser_ctxt = NULL; // the parser context
    int parser_options;
    xmlDocPtr conf_doc = NULL; // the configuration xml document tree
    xmlNodePtr role_node = NULL; //The role xml node
    int no_user; //user not found
    int any_user_command, any_group_command = 0;
    chained_commands commands_list = NULL; //The list of command
    
    
    //Check that urc contains at least a role & a user
    if(urc->role == NULL || urc->user == NULL){
        errno = EINVAL;
        return_code = -2;
        goto free_rscs;
    }
    //Create a parser context
    if((parser_ctxt = xmlNewParserCtxt()) == NULL){
        return_code = -1;
        goto free_rscs;
    }
    //open and read the xml configuration file
    parser_options = XML_PARSE_DTDVALID;
    #ifndef SR_DEBUG
    //When not on debug, inhibit warning and error printout from libxml
    parser_options |= XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    #endif
    if((conf_doc = xmlCtxtReadFile(parser_ctxt, USER_CAP_FILE_ROLE, NULL, 
                                    parser_options)) == NULL){
        errno = EINVAL;
        return_code = -3;
        goto free_rscs;
    }
    //Check if the XML file is valid regarding the DTD
    if (parser_ctxt->valid == 0){ 
        errno = EINVAL;
        return_code = -4;
        goto free_rscs;
    }
    //find the role node in the configuration file
    //(if the return is -2: role not found, otherwise: other error)    
    ret_fct = get_role(conf_doc, urc->role, &role_node);
    switch(ret_fct){
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
    //Add commands to the list from user and remember if the user does not match
    ret_fct = add_user_commands(urc, role_node, &any_user_command, 
                                &commands_list);
    switch(ret_fct){
        case 0:
            no_user = 0;
            break;
        case -2:
            no_user = 1;
            break;
        default:
            errno = EINVAL;
            return_code = -4;
            goto free_rscs;
    }
    //If user was not defined for the role, load group command definition
    if(no_user){
        //Add commands to the list form groups
        ret_fct = add_groups_commands(urc, role_node, &any_group_command, 
                                        &commands_list);
        switch(ret_fct){
            case 0:
                break;
            case -2:
                //no user and no group were found, return error
                errno = EACCES;
                return_code = -6;
                goto free_rscs;
            default:
                errno = EINVAL;
                return_code = -4;
                goto free_rscs;
        }
        
    }
    //Printout
    if(any_user_command || any_group_command){
        printf("As user %s, you can use the role %s with any command (or a bash, without the -c option)\n", urc->user, urc->role);
    }else if(commands_list == NULL){
        //Wierd case, but can happen
        printf("As user %s, you cannot use the role %s since you have restriction on commands but do not have any command authorized.\n" , urc->user, urc->role);
    }else{
        struct chained_command *cmd_item;
        printf("As user %s, you can use the role %s with the following commands:\n", urc->user, urc->role);
        for(cmd_item = commands_list; cmd_item != NULL; cmd_item = cmd_item->next){
            printf("\t- %s\n", cmd_item->command);
        }
    }
    return_code = 0;
    
  free_rscs:
    if(commands_list != NULL){
        struct chained_command *old_cmd_item;
        struct chained_command *cmd_item = commands_list;
        while(cmd_item != NULL){
            old_cmd_item = cmd_item;
            cmd_item = cmd_item->next;
            if(old_cmd_item->command != NULL) free(old_cmd_item->command);
            free(old_cmd_item);
        }
    }
    if(conf_doc != NULL){
        xmlFreeDoc(conf_doc);
    }
    if(parser_ctxt != NULL){
        xmlFreeParserCtxt(parser_ctxt);
    }
    xmlCleanupParser();
    return return_code;
}

/* 
Printout on stdout a user_role_capabilities_t
*/
void print_urc(const user_role_capabilities_t *urc){
    int i;
    char *cap_name;

    if(urc == NULL){
        printf("URC NULL\n");
        return;
    }
    printf("--- BEGIN URC ---\n");
    printf("Role: ");
    if(urc->role == NULL){
        printf("[None]\n");
    }else{
        printf("%s\n", urc->role);
    }

    printf("User: ");
    if(urc->user == NULL){
        printf("[None]\n");
    }else{
        printf("%s\n", urc->user);
    }

    printf("Groups: ");
    if(urc->nb_groups == 0){
        printf("[None]\n");
    }else{
        for (i=0; i < urc->nb_groups; i++){
            printf("%s ", urc->groups[i]);
        }
        printf("\n");
    }

    printf("Command: ");
    if(urc->command == NULL){
        printf("[None]\n");
    }else{
        printf("%s\n", urc->command);
    }

    printf("Capabilities: ");
    if(urc->caps.nb_caps == 0){
        printf("[None]\n");
    }else{
        for (i=0; i < urc->caps.nb_caps; i++){
            cap_name = cap_to_name(urc->caps.capabilities[i]);
            if(cap_name == NULL){
                printf("Cannot have cap name for %d\n", urc->caps.capabilities[i]);
            }else{
                printf("%d: %s\n", urc->caps.capabilities[i], cap_name);
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
static xml_collection_iterator new_xml_collection_iterator(xmlNodePtr node, 
        const char * collection_name, const char * element_name){
    xml_collection_iterator it;
    xmlChar *xml_col_name = NULL;
    //Allocate the iterator, the name of collection and the name of element
    if((it = malloc(sizeof(struct _xml_collection_iterator))) == NULL
        || (xml_col_name = xmlCharStrdup(collection_name)) == NULL
        || (it->element_name = xmlCharStrdup(element_name)) == NULL){
        goto free_rscs_on_error;
    }
    //Try to find the collection
    for(it->col_node = node->children; it->col_node != NULL; 
            it->col_node = it->col_node->next){
        if(it->col_node->type == XML_ELEMENT_NODE 
                && xmlStrEqual(it->col_node->name, xml_col_name)){
            break;
        }   
    }
    if(it->col_node != NULL){
        //Try to find the first element of the collection
        for(it->cur_node = it->col_node->children; it->cur_node != NULL;
                it->cur_node = it->cur_node->next){
            if(it->cur_node->type == XML_ELEMENT_NODE
                    && xmlStrEqual(it->cur_node->name, it->element_name)){
                break;
            }
        }
    }else{
        it->cur_node = NULL;
    }
    goto free_rscs;
    
  free_rscs_on_error:
    if(it != NULL){
        if(it->element_name != NULL) free(it->element_name);
        free(it);
        it = NULL;
    }
  free_rscs:
    if(xml_col_name != NULL) free(xml_col_name); 
    return it;
    
}

/*
Free an iterator on collection nodes
*/
static void xci_free_it(xml_collection_iterator it){
    if(it == NULL){
        return;
    }
    if(it->element_name != NULL) free(it->element_name);
    free(it);
    return;
}

/*
return 1 if the iterator has a collection, 0 otherwise.
*/
static int xci_has_collection(xml_collection_iterator it){
    if(it->col_node != NULL){
        return 1;
    }else{
        return 0;
    }
}

/*
return 1 if the iterator still has element of collection to iterate on, 
0 otherwise.
*/
static int xci_has_next(xml_collection_iterator it){
    if(it->cur_node != NULL){
        return 1;
    }else{
        return 0;
    }
}

/*
Retrieve the next element of collection. Return NULL if no element is to 
iterate.
*/
static xmlNodePtr xci_next(xml_collection_iterator it){
    xmlNodePtr saved_node;
    if(it->cur_node == NULL){
        return NULL;
    }
    saved_node = it->cur_node;
    for(it->cur_node = it->cur_node->next; it->cur_node != NULL;
            it->cur_node = it->cur_node->next){
        if(it->cur_node->type == XML_ELEMENT_NODE
                && xmlStrEqual(it->cur_node->name, it->element_name)){
            break;
        }
    }
    return saved_node;
}
 
/*
Get the role node matchin the role name from the xml configuration file
Return 0 on success, -2 if the role does not exist, 
-3 if an error has been found in the xml doc, -1 if an other error happened.
If an error occured, *role_node will be NULL.
*/
static int get_role(xmlDocPtr conf_doc, const char* role, 
                    xmlNodePtr *role_node){
    int return_code = -1;
    xmlNodePtr root_element = NULL;
    xml_collection_iterator it_role;
    xmlChar *xml_name_attribute = NULL;
    xmlChar *xml_role = NULL;
    int role_found;
    
    //Init ou params
    *role_node = NULL;
    
    if((xml_name_attribute = xmlCharStrdup("name")) == NULL
        || (xml_role = xmlCharStrdup(role)) == NULL){
        goto free_rscs;
    }
    /*We do not need to verify the existence and name of the capabilityrole and 
    roles nodes as they are mandatory and the document has been validated*/
    root_element = xmlDocGetRootElement(conf_doc); //capabilityrole node
    //Create an iterator on roles-role collection
    if((it_role = new_xml_collection_iterator(root_element, "roles", 
                                            "role")) == NULL){
        goto free_rscs;
    }
    //Iterate to find role
    role_found = 0;
    while(xci_has_next(it_role) && !role_found){
        *role_node = xci_next(it_role);
        xmlChar * name = xmlGetProp(*role_node, xml_name_attribute);
        if(name != NULL &&  xmlStrEqual(name, xml_role)){
            role_found = 1;
        }
        free(name);
    }
    if(role_found){
        return_code = 0;
    }else{
        *role_node = NULL;
        return_code = -2;
    }
    
  free_rscs:
    if(it_role != NULL) xci_free_it(it_role);
    if(xml_name_attribute != NULL) free(xml_name_attribute);
    if(xml_role != NULL) free(xml_role);
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
									xmlNodePtr role_node){
	int return_fct;  
    
    //Try to find a matching user node
    return_fct = find_matching_user_node(urc, role_node);
    switch(return_fct){
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
        const xmlNodePtr role_node){
    int return_code = -1;
    int user_found;
    xml_collection_iterator it_node;
    xmlChar *xml_item_name_attribute = NULL;
    xmlChar *xml_user = NULL;
    
    //Init xml char variables and user iterator
    if((xml_item_name_attribute = xmlCharStrdup("name")) == NULL
            || (xml_user = xmlCharStrdup(urc->user)) == NULL
            || (it_node = new_xml_collection_iterator(role_node, "users", 
                                            "user")) == NULL){
        goto free_rscs;
    }
    //If no collection of users: return -2
    if(!xci_has_collection(it_node)){
        return_code = -2;
        goto free_rscs;
    }
    //Iterate over user nodes in users and try to find a matching one
    user_found = 0;
    while(xci_has_next(it_node) && !user_found){
        xmlNodePtr user_node = xci_next(it_node);
        xmlChar * name = xmlGetProp(user_node, xml_item_name_attribute);
        if(name != NULL &&  xmlStrEqual(name, xml_user)){
            user_found = 1;
            //for the user_node, check valid command if required
            return_code = check_valid_command(urc, user_node);
        }
        free(name);
    }
    //If no matching user node: return -2 otherwise return_code is
    //already set with check_valid_command
    if(!user_found){
        return_code = -2;
    }else if(return_code == -2){ //user found but command invalid
        return_code = -4;
    }//else nothing to do, return_code 0 or -1 already set by 
    //check_valid_command
    
  free_rscs:	
    if(it_node != NULL) xci_free_it(it_node);
    if(xml_item_name_attribute != NULL) free(xml_item_name_attribute);
    if(xml_user != NULL) free(xml_user);
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
        const xmlNodePtr role_node){
    int return_code = -1;
    int i;
    int group_found;
	xml_collection_iterator it_node;
    xmlChar *xml_item_name_attribute = NULL;
    xmlChar **xml_groups = NULL;
    
    //First, test if there is any group to test
    if(urc->nb_groups <= 0){
        return_code = -2;
        goto free_rscs;
    }
    
    //Init xml char variables and iterator
    if((xml_item_name_attribute = xmlCharStrdup("name")) == NULL
            || (xml_groups = calloc(urc->nb_groups, sizeof(xmlChar*))) == NULL
            || (it_node = new_xml_collection_iterator(role_node, "groups", 
                                            "group")) == NULL){
        goto free_rscs;
    }
    for(i = 0; i < urc->nb_groups; i++){
        if((xml_groups[i] = xmlCharStrdup(urc->groups[i])) == NULL){
            goto free_rscs;
        }
    }
    //If no groups node: return -2
    if(!xci_has_collection(it_node)){
        return_code = -2;
        goto free_rscs;
    }
    //Iterate over group nodes in groups and try to find a matching one
    group_found = 0;
    while(xci_has_next(it_node) && !group_found){
        xmlNodePtr group_node = xci_next(it_node);
        xmlChar * name = xmlGetProp(group_node, xml_item_name_attribute);
        if(name != NULL){
            //Iterate over groups to test
            for(i = 0; i < urc->nb_groups; i++){
                if(xmlStrEqual(xml_groups[i], name)){
                    //Group found, now check if command is valid if required
                    return_code = check_valid_command(urc, group_node);
                    switch(return_code){
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
    if(group_found == 0){
        return_code = -2;
    }//Else, do nothing, return_code is already set with check_valid_command
    
  free_rscs:	
    if(it_node != NULL) xci_free_it(it_node);
    if(xml_item_name_attribute != NULL) free(xml_item_name_attribute);
    if(xml_groups != NULL){
        for(i = 0; i < urc->nb_groups; i++){
            if(xml_groups[i] != NULL) free(xml_groups[i]);
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
static int check_valid_command(user_role_capabilities_t *urc, 
                                xmlNodePtr matching_item_node){
    int return_code = -1;
    xml_collection_iterator it_node;
    xmlChar *xml_given_command = NULL;
    int command_found;
    
    //Init iterator and xmlChar
    if((it_node = new_xml_collection_iterator(matching_item_node, 
                        "commands", "command")) == NULL){
        goto free_rscs;
    }
    //If no commands node: return 0
    if(!xci_has_collection(it_node)){
        return_code = 0;
        goto free_rscs;
    }else if(urc->command == NULL){ //commands are defined, but no given command
        return_code = -2;
        goto free_rscs;
    }
    //Here, commands are defined and a command is given: test it
    if((xml_given_command = xmlCharStrdup(urc->command)) == NULL){
        goto free_rscs;
    }
    //Iterate over command nodes in commands and try to find a matching one
    command_found = 0;
    while(xci_has_next(it_node) && !command_found){
        xmlNodePtr cur_node = xci_next(it_node);
        xmlNodePtr textNode;
        //Retrieve the command text : should be in the first text child node
        for(textNode = cur_node->children; textNode != NULL && !command_found; 
                textNode = textNode->next){
            if(xmlNodeIsText(textNode)){
                xmlChar *text = xmlNodeGetContent(textNode);
                command_found = xmlStrEqual(xml_given_command, text) ? 1 : 0;
                free(text);
            }
        }
    }
    //If the command was found return 0, -2 otherwise
    if(command_found){
        return_code = 0;
    }else{
        return_code = -2;
    }
    
  free_rscs:	
    if(it_node != NULL) xci_free_it(it_node);
    if(xml_given_command != NULL) free(xml_given_command);
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
										xmlNodePtr role_node){
	int return_code = -1;  
    xml_collection_iterator it_node;
    int *capability_dict = NULL; //An array where index represent capabilities 
                        //and value if it is defined or not
    size_t i,k;
    int early_cap_stop; //indicator to stop looking for caps if "*" have been found
    xmlChar *all_cap_token = NULL;
                        
    //Init output params
    urc->caps.nb_caps = 0;
    urc->caps.capabilities = NULL;
    
    //Init iterator
    if((it_node = new_xml_collection_iterator(role_node, 
                        "capabilities", "capability")) == NULL
        ||(all_cap_token = xmlCharStrdup("*")) == NULL){
        goto free_on_error;
    }
    //If no commands node: accepted (no caps) return 0
    if(!xci_has_collection(it_node)){
        return_code = 0;
        goto free_rscs;
    }
    //Create an array of CAP_LAST_DEFINED capabilities to remove duplicates
    //and avoir multiple invocation
    if((capability_dict = calloc(CAP_LAST_CAP + 1, sizeof(int))) == NULL){
        goto free_on_error;
    }
    //Iterate over capability node in the capabilities node
    //Stop if all cap token has been found
    early_cap_stop = 0;
    while(xci_has_next(it_node) && !early_cap_stop){
        xmlNodePtr cur_node = xci_next(it_node);
        xmlNodePtr textNode;
        for(textNode = cur_node->children; textNode != NULL && !early_cap_stop; 
                textNode = textNode->next){
            if(xmlNodeIsText(textNode)){
                xmlChar *cap_text = xmlNodeGetContent(textNode);
                cap_value_t cap_val;
                //If cap_text is '*', the load all available caps
                if(xmlStrEqual(all_cap_token, cap_text)){
                    for(i = 0; i <= CAP_LAST_CAP; i++){
                        capability_dict[i] = 1;
                    }
                    //will stop looping as all caps have been set
                    early_cap_stop = 1;
                }else{
                    //Attempt to convert cap_text to cap_value
                    //WARNING : cast should be safe so far..
                    if(cap_from_name((char *)cap_text, &cap_val)){
                        fprintf(stderr, "Warning: capability '%s' not handled by the system\n", cap_text);
                    }else{
                        //Set the cap in the dict to 1
                        capability_dict[cap_val] = 1;
                    }
                }
                free(cap_text);
            }
        }
    }
    //count the caps to alloc capabilities array in urc
    for(i = 0; i <= CAP_LAST_CAP; i++){
        if(capability_dict[i] == 1){
            urc->caps.nb_caps++;
        }
    }
    //Alloc and fill the capabilities array
    if((urc->caps.capabilities = 
            malloc(urc->caps.nb_caps * sizeof(cap_value_t))) == NULL){
        goto free_on_error;
    }
    k = 0;
    for(i = 0; i <= CAP_LAST_CAP; i++){
        if(capability_dict[i] == 1){
            urc->caps.capabilities[k++] = i;
        }
    }
    return_code = 0;
    goto free_rscs;
     
  free_on_error: //Free resources on failure specifially
    if(urc->caps.capabilities != NULL) free(urc->caps.capabilities);
    urc->caps.capabilities = NULL;
    urc->caps.nb_caps = 0;
  free_rscs: //Free resources on success or failure
    if(it_node != NULL) xci_free_it(it_node);
    if(capability_dict != NULL) free(capability_dict);
    if(all_cap_token != NULL) free(all_cap_token);
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
                                    chained_commands *chained_commands){
    struct chained_command* cmd;
    
    //parse the existing list and try to find a duplicate of the command
    for(cmd = *chained_commands; cmd != NULL; cmd = cmd->next){
        if(xmlStrEqual(cmd->command, command)){
            return 0;
        }
    }
    //Create a new entry on the top of the list with a copy of the command
    if((cmd = malloc(sizeof(struct chained_command))) == NULL){
        return -1;
    }
    if((cmd->command = xmlStrdup(command)) == NULL){
        free(cmd);
        return -1;
    }
    cmd->next = *chained_commands;
    *chained_commands = cmd;
    return 0;
}

/*
For a given node, add the available commands to the list and set any_command to 0
if they are defined are set any_command to 1 if not.
Return 0 on success, -3 if an error has been found in the xml doc, 
or -1 if an other error happened.
*/
static int add_node_commands(const xmlNodePtr node, int *any_command, 
                            chained_commands *commands){
    int return_code = -1;
    xml_collection_iterator it_node;
    
    //Init iterator
    if((it_node = new_xml_collection_iterator(node, 
                        "commands", "command")) == NULL){
        goto free_rscs;
    }
    //If no commands node: set any_command to 1 and return 0
    if(!xci_has_collection(it_node)){
        *any_command = 1;
        return_code = 0;
        goto free_rscs;
    }else{
        *any_command = 0;
    }
    //Iterate over command nodes in commands and them to the list
    while(xci_has_next(it_node)){
        xmlNodePtr cur_node = xci_next(it_node);
        xmlNodePtr textNode;
        int ret_fct = 0;
        //Retrieve the command text : should be in the first text child node
        for(textNode = cur_node->children; textNode != NULL; 
                    textNode = textNode->next){
            if(xmlNodeIsText(textNode)){
                xmlChar *text = xmlNodeGetContent(textNode);
                //Add the text to the command list
                ret_fct = add_unique_command_to_list(text, commands);
                free(text);
                if(ret_fct){
                    goto free_rscs;
                }
            }
        }
    }
    return_code = 0;
    
  free_rscs:	
    if(it_node != NULL) xci_free_it(it_node);
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
        chained_commands *commands){
    int return_code = -1;
    xml_collection_iterator it_node;
    int user_found;
    xmlChar *xml_item_name_attribute = NULL;
    xmlChar *xml_user = NULL;
    
    //Init output
    *any_command = 0;
    //Init xml char variables and iterator
    if((it_node = new_xml_collection_iterator(role_node, 
                        "users", "user")) == NULL
            || (xml_item_name_attribute = xmlCharStrdup("name")) == NULL
            || (xml_user = xmlCharStrdup(urc->user)) == NULL){
        goto free_rscs;
    }
    //If no users node: return -2
    if(!xci_has_collection(it_node)){
        return_code = -2;
        goto free_rscs;
    }
    //Iterate over user nodes in users and try to find a matching one
    user_found = 0;
    while(xci_has_next(it_node) && !user_found){
        xmlNodePtr cur_node = xci_next(it_node);
        xmlChar * name = xmlGetProp(cur_node, xml_item_name_attribute);
        if(name != NULL &&  xmlStrEqual(name, xml_user)){
            user_found = 1;
            //Add the command of user or set any_command
            return_code = add_node_commands(cur_node, any_command, commands);
        }
        free(name);
    }
    //If no matching user node: return -2
    if(!user_found){
        return_code = -2;
        goto free_rscs;
    }//else return_code is already set with add_node_commands
    
  free_rscs:	
    if(it_node != NULL) xci_free_it(it_node);
    if(xml_item_name_attribute != NULL) free(xml_item_name_attribute);
    if(xml_user != NULL) free(xml_user);
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
        chained_commands *commands){
    int return_code = -1;
    int i;
    int group_found;
    xml_collection_iterator it_node;
    xmlChar *xml_item_name_attribute = NULL;
    xmlChar **xml_groups = NULL;
    
    //Init output
    *any_command = 0;
    //First, test if there is any group to test
    if(urc->nb_groups <= 0){
        return_code = -2;
        goto free_rscs;
    }
    //Init xml char variables and iterator
    if((it_node = new_xml_collection_iterator(role_node, 
                        "groups", "group")) == NULL
            || (xml_item_name_attribute = xmlCharStrdup("name")) == NULL
            || (xml_groups = calloc(urc->nb_groups, sizeof(xmlChar*))) == NULL){
        goto free_rscs;
    }
    for(i = 0; i < urc->nb_groups; i++){
        if((xml_groups[i] = xmlCharStrdup(urc->groups[i])) == NULL){
            goto free_rscs;
        }
    }
    //If no groups node: return -2
    if(!xci_has_collection(it_node)){
        return_code = -2;
        goto free_rscs;
    }
    //Iterate over group nodes in groups and try to find a matching one
    group_found = 0;
    *any_command = 0; //Initialize any_command here
    while(xci_has_next(it_node)){
        xmlNodePtr cur_node = xci_next(it_node);
        xmlChar * name = xmlGetProp(cur_node, xml_item_name_attribute);
        int a_group_found = 0;
        if(name != NULL){
            //Iterate over group to test
            for(i = 0; i < urc->nb_groups; i++){
                if(xmlStrEqual(xml_groups[i], name)){
                    //Group found, add commands to the list
                    a_group_found = 1;
                    return_code = add_node_commands(cur_node, any_command, 
                                                    commands);
                    break;
                }
            }
            free(name);
        }
        //If group was found, break if return_code != 0 or update any_command
        if(a_group_found){
            if(return_code){
                break;
            }else{
                group_found = 1;
                if(*any_command){
                    break; //stop here: one group with any command was found
                }
            }
        }
    }
    //If no group found: reset group command indicator & return -2
    if(group_found == 0){
        *any_command = 0;
        return_code = -2;
    }//Else, do nothing, return_code is already set
    
  free_rscs:	
    if(it_node != NULL) xci_free_it(it_node);
    if(xml_item_name_attribute != NULL) free(xml_item_name_attribute);
    if(xml_groups != NULL){
        for(i = 0; i < urc->nb_groups; i++){
            if(xml_groups[i] != NULL) free(xml_groups[i]);
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