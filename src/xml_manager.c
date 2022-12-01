#include "xml_manager.h"

#include <libxml/xpath.h>
#include <sys/types.h>
#include <string.h>

/**
 * @brief sanitize string with concat xpath function
*/
char *sanitize_quotes_xpath(const char *str){
    char *split = "',\"'\",'";
    char *format = strchr(str,'\'') ? "concat('%s')" : "'%s'";
    char *tmp = malloc(strlen(str) * strlen(split) + strlen(format)+1);
    *tmp = '\0';
    if(tmp == NULL){
        return NULL;
    }
    char *tok = strtok((char *)str, "'");
    tmp = xmlStrcat(tmp, tok);
    tok = strtok(NULL, "'");
    while (tok != NULL) {
        tmp = xmlStrcat(tmp, split);
        tmp = xmlStrcat(tmp, tok);
        tok = strtok(NULL, "'");
    }
    int len = strlen(tmp) + 11;
    char *ret = malloc(len * sizeof(char));
    if(ret == NULL){
        free(tmp);
        return NULL;
    }
    snprintf(ret, len, format, tmp);
    free(tmp);
    return ret;

}

/**
 * @brief return the xpath expression to find a role by name
*/
xmlChar *expr_search_role_by_name(char *role)
{
    int err;
    int size = 0;
    xmlChar *expression = NULL;

    size = 20 + (int)strlen(role);

    expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
    if (!expression) {
        fputs("Error malloc\n", stderr);
        goto ret_err;
    }

    err = xmlStrPrintf(expression, size, "//role[@name='%s'][1]", role);
    if (err == -1) {
        fputs("Error xmlStrPrintf()\n", stderr);
        free(expression);
    }

    ret_err:

    return expression;
}

int __expr_user_or_groups(xmlChar **expr, char *user,char **groups, int nb_groups){
    int err = 0;
    char *expr_format = "user[@name='%s'] or group[%s]";
    int size = 26 + (int)strlen(user);
    xmlChar *groups_str = (xmlChar *)xmlMalloc((nb_groups*57) * sizeof(xmlChar));
    if (!groups_str) {
        fputs("Error malloc\n", stderr);
        return NULL;
    }
    xmlChar *str_ptr = groups_str;
    for (int i = 0; i < nb_groups; i++) {
        int contains_size = (int)strlen(groups[i])+21;
        if (i == 0) {
            err = xmlStrPrintf(str_ptr, contains_size, "contains(@names, '%s')", groups[i]);
        } else {
            contains_size = contains_size + 4;
            err = xmlStrPrintf(str_ptr, contains_size, " or contains(@names, '%s')", groups[i]);
        }
        if (err == -1) {
            fputs("Error xmlStrPrintf()\n", stderr);
            free(groups_str);
            return NULL;
        }
        str_ptr += contains_size-1;
        size += contains_size;
    }
    *expr = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
    int ret = xmlStrPrintf(*expr,size,expr_format,user,groups_str);
    free(groups_str);
    return ret+1;

}

/**
 * @brief return the xpath expression to find a role by username or group combined with a command
*/
xmlChar *expr_search_role_by_usergroup_command(char *user, char **groups, int nb_groups, char *command)
{
    int err;
    int size = 0;
    xmlChar *expression = NULL;
    xmlChar *user_groups_char = NULL;
    char *sanitized_str = sanitize_quotes_xpath(command);
    if (sanitized_str == NULL) {
        return NULL;
    }
    int user_groups_size = __expr_user_or_groups(&user_groups_char, user, groups, nb_groups);
    size = 70 + (int)strlen(sanitized_str) + user_groups_size;

    expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
    if (!expression) {
        fputs("Error malloc\n", stderr);
        goto ret_err;
    }
    
    // //role[(user[@name='lechatp'] or group[contains(@names,'lechatp') or contains(@names,'group1')]) and (commands/command[text()='%s'] or commands[not(command)])]
    err = xmlStrPrintf(expression, size, "//role[(%s) and (commands/command[text()=%s] or commands[not(command)])]", user_groups_char, sanitized_str);
    printf("expr : %s\n",expression);
    if (err == -1) {
        fputs("Error xmlStrPrintf()\n", stderr);
        xmlFree(expression);
    }

    ret_err:
    free(sanitized_str);
    xmlFree(user_groups_char);
    return expression;
}

/**
 * @brief find all roles matching the user or groups and command 
*/
xmlNodeSetPtr find_role_by_usergroup_command(xmlDocPtr doc, char *user, char **groups, int nb_groups, char *command)
{
    xmlXPathContextPtr context = NULL;
    xmlXPathObjectPtr result = NULL;
    xmlNodeSetPtr nodeset = NULL;
    xmlChar *expression = NULL;

    expression = expr_search_role_by_usergroup_command(user, groups, nb_groups, command);
    if (!expression) {
        fputs("Error expr_search_role_by_usergroup_command()\n", stderr);
        goto ret_err;
    }

    context = xmlXPathNewContext(doc);
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        goto ret_err;
    }

    result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        goto ret_err;
    }
    

    nodeset = result->nodesetval;

    ret_err:
    xmlXPathFreeContext(context);
    xmlFree(expression);
    return nodeset;
}

/**
 * @brief remove roles if group combination is not matching the executor
*/
xmlNodeSetPtr filter_wrong_roles(xmlNodeSetPtr set, char **groups, int nb_groups){
    int newNr = 0;
    for(int i = 0; i < set->nodeNr; i++){
        xmlNodePtr node = set->nodeTab[i];
        xmlNodePtr group = node->children;
        while(group != NULL){
            if(xmlStrcmp(group->name, (const xmlChar *)"group") == 0){
                xmlChar *names = xmlGetProp(group, (const xmlChar *)"names");
                if(names != NULL){
                    char *names_str = (char *)names;
                    char *token = strtok(names_str, ",");
                    int found = 0;
                    int all = 0;
                    while(token != NULL){
                        for(int j = 0; j < nb_groups; j++){
                            if(!strcmp(token, groups[j])){
                                found += 1;
                                break;
                            }
                        }
                        token = strtok(NULL, ",");
                        all += 1;
                    }
                    if(found == 0 || found != all){
                        xmlUnlinkNode(node);
                        xmlFreeNode(node);
                        if(i < set->nodeNr-1){
                            set->nodeTab[i] = set->nodeTab[i+1];
                        } else{
                            set->nodeTab[i] = NULL;
                        }
                        set->nodeNr --;
                        break;
                    }
                }
            }
            group = group->next;
        }
    }
    return set;
}

/**
 * @brief perform quick sort algorithm on roles by priority
*/
xmlNodeSetPtr sort_element_by_priorities(xmlNodeSetPtr set){
    if(set->nodeNr > 1){
        int pivot = 0;
        int i = 0;
        int j = set->nodeNr-1;
        xmlNodePtr tmp = NULL;
        xmlNodePtr pivot_node = set->nodeTab[pivot];
        xmlChar *priority = xmlGetProp(pivot_node, (const xmlChar *)"priority");
        int pivot_priority = strtol((char *)priority,NULL,10);
        while(i < j){
            xmlNodePtr node = set->nodeTab[i];
            xmlChar *priority = xmlGetProp(node, (const xmlChar *)"priority");
            int node_priority = strtol((char *)priority,NULL,10);
            if(node_priority > pivot_priority){
                tmp = set->nodeTab[i];
                set->nodeTab[i] = set->nodeTab[j];
                set->nodeTab[j] = tmp;
                j--;
            } else{
                i++;
            }
        }
        xmlNodeSetPtr set1 = xmlXPathNodeSetCreate(NULL);
        xmlNodeSetPtr set2 = xmlXPathNodeSetCreate(NULL);
        for(int k = 0; k < set->nodeNr; k++){
            if(k < i){
                set1->nodeTab[k] = set->nodeTab[k];
            } else{
                set2->nodeTab[k-i] = set->nodeTab[k];
            }
        }
        set1->nodeNr = i;
        set2->nodeNr = set->nodeNr-i;
        xmlNodeSetPtr set1_sorted = sort_element_by_priorities(set1);
        xmlNodeSetPtr set2_sorted = sort_element_by_priorities(set2);
        for(int k = 0; k < set1_sorted->nodeNr; k++){
            set->nodeTab[k] = set1_sorted->nodeTab[k];
        }
        for(int k = 0; k < set2_sorted->nodeNr; k++){
            set->nodeTab[k+set1_sorted->nodeNr] = set2_sorted->nodeTab[k];
        }
        set->nodeNr = set1_sorted->nodeNr + set2_sorted->nodeNr;
        xmlXPathFreeNodeSet(set1);
        xmlXPathFreeNodeSet(set2);
        xmlXPathFreeNodeSet(set1_sorted);
        xmlXPathFreeNodeSet(set2_sorted);
    }
    return set;
}

xmlNodePtr find_max_element_by_priority(xmlNodeSetPtr set){
    xmlNodePtr max = NULL;
    int max_priority = INT_MIN;
    for(int i = 0; i < set->nodeNr; i++){
        xmlNodePtr node = set->nodeTab[i];
        xmlChar *priority = xmlGetProp(node, (const xmlChar *)"priority");
        int node_priority = strtol((char *)priority,NULL,10);
        if(node_priority > max_priority){
            max = node;
            max_priority = node_priority;
        }
    }
    return max;
}

/**
 * @brief create expression to find all commands containing the given command in a role
 * @param command command to search
 * @return expression like .//commands[contains(command, 'thecommand')]
*/
xmlChar *expr_search_command_block_from_role(char *command){
    // .//commands[contains(command, '%s')]
    xmlChar *expr = NULL; 
    char *sanitized_command = sanitize_quotes_xpath(command);
    if(sanitized_command == NULL){
        return NULL;
    }
    xmlChar *command_block = ".//commands[contains(command, %s)]";
    int len = strlen((char *)command_block) + strlen(sanitized_command) + 1;
    expr = (xmlChar *)malloc(len);
    if(expr == NULL){
        return NULL;
    }
    xmlStrPrintf(expr, len, command_block, sanitized_command);
    free(sanitized_command);
    return expr;
}

/**
 * @brief find commands matching the command on the role with xpath
*/
xmlNodePtr find_commands_block_from_role(xmlNodePtr role_node, char *command){
    xmlNodePtr node = role_node->children;
    xmlXPathContextPtr context = xmlXPathNewContext(role_node->doc);
    context->node = role_node;
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        return NULL;
    }
    xmlChar *expression = expr_search_command_block_from_role(command);
    if (!expression) {
        fputs("Error expr_search_command_block_from_role()\n", stderr);
        return NULL;
    }
    xmlXPathObjectPtr result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        return NULL;
    }
    xmlNodeSetPtr nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        return NULL;
    }
    return *(nodeset->nodeTab);
}

xmlNodePtr find_empty_commands_block_from_role(xmlNodePtr role_node) {
    xmlNodePtr node = role_node->children;
    xmlXPathContextPtr context = xmlXPathNewContext(role_node->doc);
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        return NULL;
    }
    context->node = role_node;
    xmlChar *expression = (xmlChar *)"./commands[not(command)]";
    if (!expression) {
        fputs("Error expr_search_command_block_from_role()\n", stderr);
        return NULL;
    }
    xmlXPathObjectPtr result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        return NULL;
    }
    xmlNodeSetPtr nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        return NULL;
    }
    free_rscs:
    //xmlXPathFreeObject(result);
    xmlXPathFreeContext(context);
    return *(nodeset->nodeTab);
}

/**
 * @brief retireve capabilities from commands matching user, groups and command 
*/
int *get_capabilities_from_command(xmlDocPtr doc, char *user, int nb_groups, char **groups, char *command, cap_iab_t *caps){
    int res = 0;
    xmlNodeSetPtr set = find_role_by_usergroup_command(doc,user, groups, nb_groups, command);
    if(set == NULL){
        return res;
    }
    xmlNodePtr node = find_max_element_by_priority(set);
    if(node == NULL){
        xmlXPathFreeNodeSet(set);
        return res;
    }

    xmlNodePtr commands = find_commands_block_from_role(node, command);
    if(commands == NULL){
        commands = find_empty_commands_block_from_role(node);
        if(commands == NULL){
            
            return res;
        }
    }
    xmlChar *capabilities = xmlGetProp(commands, (const xmlChar *)"capabilities");
    if (xmlStrcasecmp(capabilities, (const xmlChar *)"all") == 0){
        capabilities = (xmlChar *)"=i";
    }else{
        xmlChar *s_capabilities = xmlMalloc(xmlStrlen(capabilities)+3);
        xmlStrPrintf(s_capabilities, xmlStrlen(capabilities)+3, "%s=i", capabilities);
        capabilities = s_capabilities;
    }
    cap_t cap = cap_from_text(capabilities);
    *caps = cap_iab_init();
    cap_iab_fill(*caps, CAP_IAB_AMB,cap, CAP_INHERITABLE);
    if (xmlStrcmp(xmlGetProp(node, (const xmlChar *)"bounding"), "restrict") == 0){
        cap_iab_fill(*caps, CAP_IAB_BOUND,cap, CAP_INHERITABLE);
    }
    res = 1;
    free_rscs:
    xmlXPathFreeNodeSet(set);
    return res;
}

xmlDocPtr load_xml(char *xml_file)
{
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc;

    ctxt = xmlNewParserCtxt();
    if (!ctxt) {
        fputs("Failed to allocate parser context\n", stderr);
        return NULL;
    }

    doc = xmlCtxtReadFile(ctxt, xml_file, NULL, XML_PARSE_DTDVALID|XML_PARSE_NOBLANKS);
    if (!doc) {
        fprintf(stderr, "Failed to parse %s\n", XML_FILE);
        goto ret_err;
    }
    if (!ctxt->valid) {
        fprintf(stderr, "Failed to validate %s\n", XML_FILE);
        xmlFreeDoc(doc);
        goto ret_err;
    }

    xmlFreeParserCtxt(ctxt);

    return doc;

ret_err:
    xmlFreeParserCtxt(ctxt);
    return NULL;
}

/**
 * @brief load the xml file and retrieve capabilities matching the criterions
*/
cap_iab_t get_capabilities_from_config(char *user, int nb_groups, char **groups, char *command)
{
    xmlDocPtr doc;
    cap_iab_t caps = NULL;

    doc = load_xml(XML_FILE);
    if (!doc)
        return NULL;

    int res = get_capabilities_from_command(doc, user, nb_groups, groups, command, &caps);

    xmlFreeDoc(doc);

    return caps;
}

xmlNodePtr get_role_node(xmlDocPtr doc, char *role){
    xmlNodePtr node = xmlDocGetRootElement(doc);
    xmlXPathContextPtr context = xmlXPathNewContext(doc);
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        return NULL;
    }
    context->node = node;
    xmlChar *expression = expr_search_role_by_name(role);
    if (!expression) {
        fputs("Error expr_search_role()\n", stderr);
        return NULL;
    }
    xmlXPathObjectPtr result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        return NULL;
    }
    xmlNodeSetPtr nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        return NULL;
    }
    return nodeset->nodeTab[0];
}

xmlChar *expr_has_access(char *role, char *user, int nb_groups, char **groups){
    int err;
    int size = 0;
    xmlChar *expression = NULL;
    xmlChar *user_groups_char = NULL;
    int user_groups_size = __expr_user_or_groups(&user_groups_char, user, groups, nb_groups);
    size = strlen(role) + 24 + user_groups_size;

    expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
    if (!expression) {
        fputs("Error malloc\n", stderr);
        goto ret_err;
    }
    
    // //role[(user[@name='lechatp'] or group[contains(@names,'lechatp') or contains(@names,'group1')]) and (commands/command[@name='%s'] or commands[not(command)])]
    err = xmlStrPrintf(expression, size, "//role[@name='%s' and (%s)]",role, user_groups_char);
    if (err == -1) {
        fputs("Error xmlStrPrintf()\n", stderr);
        xmlFree(expression);
    }

    ret_err:
    xmlFree(user_groups_char);
    return expression;
}

xmlNodePtr get_role_if_access(xmlDocPtr doc, char *role, char *user, int nb_groups, char **groups){
    xmlXPathContextPtr context = xmlXPathNewContext(doc);
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        return NULL;
    }
    xmlChar *expression = expr_has_access(role, user, nb_groups, groups);
    if (!expression) {
        fputs("Error expr_search_role()\n", stderr);
        return NULL;
    }
    xmlXPathObjectPtr result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        return NULL;
    }
    xmlNodeSetPtr nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        return NULL;
    }
    return nodeset->nodeTab[0];
}

xmlChar *expr_search_access_roles(char *user, int nb_groups, char **groups){
    int err;
    int size = 0;
    xmlChar *expression = NULL;
    xmlChar *user_groups_char = NULL;
    int user_groups_size = __expr_user_or_groups(&user_groups_char, user, groups, nb_groups);
    size = 24 + user_groups_size;

    expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
    if (!expression) {
        fputs("Error malloc\n", stderr);
        goto ret_err;
    }
    
    // //role[user[@name='lechatp'] or group[contains(@names,'lechatp') or contains(@names,'group1')]]
    err = xmlStrPrintf(expression, size, "//role[%s]", user_groups_char);
    if (err == -1) {
        fputs("Error xmlStrPrintf()\n", stderr);
        xmlFree(expression);
    }

    ret_err:
    xmlFree(user_groups_char);
    return expression;
}

xmlNodeSetPtr get_right_roles(xmlDocPtr doc, char *user, int nb_groups, char **groups){
    xmlXPathContextPtr context = xmlXPathNewContext(doc);
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        return NULL;
    }
    xmlChar *expression = expr_search_access_roles(user, nb_groups, groups);
    if (!expression) {
        fputs("Error expr_search_role()\n", stderr);
        return NULL;
    }
    xmlXPathObjectPtr result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        return NULL;
    }
    xmlNodeSetPtr nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        return NULL;
    }
    return filter_wrong_roles(nodeset,groups,nb_groups);
}

xmlChar *expr_search_element_in_role(char *element){
    int err;
    int size = 0;
    xmlChar *expression = NULL;
    size = strlen(element) + 4;

    expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
    if (!expression) {
        fputs("Error malloc\n", stderr);
        goto ret_err;
    }
    
    // //commands
    err = xmlStrPrintf(expression, size, ".//%s",element);
    if (err == -1) {
        fputs("Error xmlStrPrintf()\n", stderr);
        xmlFree(expression);
    }

    ret_err:
    return expression;
}

xmlNodeSetPtr search_element_in_role(xmlNodePtr role, char *element){
    xmlXPathContextPtr context = xmlXPathNewContext(role->doc);
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        return NULL;
    }
    context->node = role;
    xmlChar *expression = expr_search_element_in_role(element);
    if (!expression) {
        fputs("Error expr_search_element_in_role()\n", stderr);
        return NULL;
    }
    xmlXPathObjectPtr result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        return NULL;
    }
    xmlNodeSetPtr nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        return NULL;
    }
    return nodeset;
}

void print_commands(xmlNodeSetPtr nodeset, int restricted){
    char *vertical = "│  ";
	char *element = "├─ ";
	char *end = "└─ ";
    char *space = "   ";
    
    for (int i = 0; i < nodeset->nodeNr; i++) {
        xmlNodePtr node = nodeset->nodeTab[i];
        if(!restricted){
            if(xmlHasProp(node, (const xmlChar *)"capabilities")){
                printf("%sCommands with capabilities: %s\n",i+1 < nodeset->nodeNr ? element : end, xmlGetProp(node, (const xmlChar *)"capabilities"));
            }else{
                printf("%sCommands without capabilities:\n",i+1 < nodeset->nodeNr ? element : end);
            }
        }else if(i == 0) {
            printf("%sCommands:\n",end);
        }
        
        if(node->children)
            for (xmlNodePtr command = node->children; command; command = command->next) {
                printf("%s%s%s\n",restricted || i+1 >= nodeset->nodeNr ? space : vertical,i+1 < nodeset->nodeNr ? element : end, command->children->content);
            }
        else{
            printf("%s%sAny command\n",restricted || i+1 >= nodeset->nodeNr ? space : vertical,i+1 < nodeset->nodeNr ? element : end);
        }
    }
}

void print_xml_role(xmlNodePtr role){
    char *vertical = "│  ";
	char *element = "├─ ";
	char *end = "└─ ";
    char *space = "   ";
    printf("Role \"%s\"\n", xmlGetProp(role, (const xmlChar *)"name"));
    xmlAttrPtr priority = xmlHasProp(role, (const xmlChar *)"priority");
    xmlAttrPtr bounding = xmlHasProp(role, (const xmlChar *)"bounding");
    xmlAttrPtr noroot = xmlHasProp(role, (const xmlChar *)"root");
    xmlAttrPtr keepenv = xmlHasProp(role, (const xmlChar *)"keep-env");
    if(priority || bounding || noroot || keepenv){
        printf("%sProperties:\n", role->children ? element:end);
        if (priority) {
            printf("%s%sPriority %s", vertical, bounding || noroot || keepenv ? element : end, priority->children->content);
        }
        if (bounding){
            printf("%s%sBounding \"%s\"\n", vertical, noroot || keepenv ? element : end, bounding->children->content);
        }
        if(noroot){
            printf("%s%sNo Root \"%s\"\n", vertical, keepenv ? element : end, noroot->children->content);
        }
        if(keepenv){
            printf("%s%sKeep-env \"%s\"\n",vertical,end, keepenv->children->content);
        }
    }
    xmlNodeSetPtr users = search_element_in_role(role,"user");
    xmlNodeSetPtr groups = search_element_in_role(role,"group");
    xmlNodeSetPtr commands = search_element_in_role(role,"commands");
    if (users->nodeNr + groups->nodeNr > 0){
        char *side = commands->nodeNr ? element:space;
        printf("%sActors:\n", commands->nodeNr ? element:end);
        for (int i = 0; i < users->nodeNr; i++) {
            xmlNodePtr user = users->nodeTab[i];
            printf("%s%s%s\n", side, i+1 < (users->nodeNr + groups->nodeNr) ? element : end, xmlGetProp(user, (const xmlChar *)"name"));
        }
        for (int i = 0; i < groups->nodeNr; i++) {
            xmlNodePtr group = groups->nodeTab[i];
            printf("%s%s%s\n", side, i+1 < groups->nodeNr ? element : end, xmlGetProp(group, (const xmlChar *)"names"));
        }
    }
    print_commands(commands,0);
}

void print_full_role(char *role){
    xmlDocPtr doc;
    cap_iab_t *caps = NULL;

    doc = load_xml(XML_FILE);
    if (doc){
        xmlNodePtr role_node = get_role_node(doc, role);
        if(role_node){
            print_xml_role(role_node);
        }else{
            printf("Role \"%s\" not found\n", role);
        }
    }else{
        printf("Error loading XML file\n");
    }

}

void print_full_roles(){
    xmlDocPtr doc;
    cap_iab_t *caps = NULL;

    doc = load_xml(XML_FILE);
    if (doc)
        for(xmlNodePtr role = doc->children->children; role; role = role->next){
            print_full_role(role);
        }
    else{
        printf("Error loading XML file\n");
    }
}

void print_rights(char *user, int nb_groups, char **groups, int restricted)
{
    xmlDocPtr doc;
    cap_iab_t *caps = NULL;

    doc = load_xml(XML_FILE);
    if (doc){
        xmlNodeSetPtr roles = get_right_roles(doc, user, nb_groups, groups);
        if(roles){
            for (int i = 0; i < roles->nodeNr; i++) {
                xmlNodePtr role = roles->nodeTab[i];
                if(restricted){
                    xmlNodeSetPtr commands = search_element_in_role(role,"commands");
                    printf("Role \"%s\"\n", xmlGetProp(role, (const xmlChar *)"name"));
                    print_commands(commands,RESTRICTED);
                }else{
                    print_xml_role(role);
                }
            }
        }else{
            printf("Permission denied\n");
        }
    }else{
        printf("Error loading XML file\n");
    }
}

void print_rights_role(char *role, char *user, int nb_groups, char **groups, int restricted){
    xmlDocPtr doc;
    cap_iab_t *caps = NULL;

    doc = load_xml(XML_FILE);
    if (doc){
        xmlNodePtr role_node = get_role_node(doc, role);
        if(role_node){
            if(restricted){
                xmlNodeSetPtr commands = search_element_in_role(role_node,"commands");
                printf("Role \"%s\"\n", xmlGetProp(role_node, (const xmlChar *)"name"));
                print_commands(commands,RESTRICTED);
            }else{
                print_xml_role(role_node);
            }
        }else{
            printf("Role \"%s\" not found\n", role);
        }
    }else{
        printf("Error loading XML file\n");
    }
}