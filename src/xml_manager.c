#include "xml_manager.h"

#include <libxml/xpath.h>
#include <sys/types.h>
#include <string.h>

/*******************************************
 ***            FIND OPTIONS             ***
********************************************/

char *d_keep_vars[] = { "HOME","USER","LOGNAME","COLORS","DISPLAY","HOSTNAME","KRB5CCNAME","LS_COLORS","PS1","PS2","XAUTHORY","XAUTHORIZATION","XDG_CURRENT_DESKTOP" };
char *d_check_vars[] = { "COLORTERM","LANG","LANGUAGE","LC_*","LINGUAS","TERM","TZ" };
char d_path[] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin";

static options_t options = &(struct s_options) {
    .env_keep = d_keep_vars,
    .env_check = d_check_vars,
    .path = d_path,
    .no_root = 1,
    .bounding = 1
};

static cap_iab_t iab = NULL;

xmlXPathObjectPtr result = NULL;

/**
 * @brief split a string into an array of strings
 * @param str the string to split
 * @param delimiter the delimiter to split the string
 * @return an array of strings, or NULL on error, to free at end of usage
*/
static char** split_string(xmlChar *str, char *delimiter){
    if (str == NULL){
        return NULL;
    }
    char **array = NULL;
    int i = 0;
    char *token = strtok((char *)str, delimiter);
    while(token != NULL){
        char **re_array = realloc(array, sizeof(char*) * (i + 2));
        if (re_array == NULL){
            goto error;
        }
        array = re_array;
        array[i] = token;
        array[i + 1] = NULL;
        i++;
        token = strtok(NULL, delimiter);
    }
    return (char **) array;

    error:
    if (array != NULL){
        free(array);
    }
    return NULL;
}

int option_enforced(xmlNodePtr option){
    xmlChar *prop = xmlGetProp(option,(xmlChar*)"enforce");
    if(!xmlStrcmp(prop, (const xmlChar *)"true"))
        return 1;
    xmlFree(prop);
    return 0;
}

void set_options_from_node(xmlNodePtr options_node){
    for(xmlNodePtr node = options_node->children; node; node = node->next){
        if(node->type == XML_ELEMENT_NODE){
            if(!xmlStrcmp(node->name, (const xmlChar *)"allow-root") && option_enforced(node)){
                options->no_root = 0;
            }else if(!xmlStrcmp(node->name, (const xmlChar *)"allow-bounding") && option_enforced(node)){
                options->bounding = 0;
            } else if(!xmlStrcmp(node->name, (const xmlChar *)"path")){
                if(options->path != d_path)
                    xmlFree(options->path);
                options->path = (char*) xmlNodeGetContent(node);
            } else if(!xmlStrcmp(node->name, (const xmlChar *)"env-keep")){
                if(options->env_keep != d_keep_vars){
                    xmlFree(*(options->env_keep));
                    free(options->env_keep);
                }
                options->env_keep = split_string(xmlNodeGetContent(node),",");
            } else if(!xmlStrcmp(node->name, (const xmlChar *)"env-check")){
                if(options->env_check != d_check_vars){
                    xmlFree(*(options->env_check));
                    free(options->env_check);
                }
                options->env_check = split_string(xmlNodeGetContent(node),",");
            }
        }
    }
}

void find_and_set_options_in_node(xmlNodePtr p_node){
    for(xmlNodePtr node = p_node->children; node; node = node->next){
        if(!xmlStrncmp(node->name, (const xmlChar *)"options",7)){
            set_options_from_node(node);
        }
    }
}

/**
 * @brief retrieve the options from the commands node
 * @param commands_node the edging node where options could be found
 * @return the options structure
 * @note This function is checking from the most specific to the most general and applies defaults if nothing is found
*/
void get_options_from_config(xmlNodePtr commands_node){
    find_and_set_options_in_node(commands_node);
    find_and_set_options_in_node(commands_node->parent);
    find_and_set_options_in_node(commands_node->doc->children->next);
}

void free_options(options_t options){
    if(options->env_keep != d_keep_vars){
        xmlFree(*(options->env_keep));
        free(options->env_keep);
    }
    if(options->env_check != d_check_vars){
        xmlFree(*(options->env_check));
        free(options->env_check);
    }
    if(options->path != d_path){
        free(options->path);
    }
}

/*******************************************
 ***            FIND ROLES               ***
********************************************/

/**
 * @brief sanitize string with concat xpath function
*/
char *sanitize_quotes_xpath(const char *str){
    char *split = "',\"'\",'";
    const char *format = strchr(str,'\'') ? "concat('%s')" : "'%s'";
    char *tmp = malloc(strlen(str) * strlen(split) + strlen(format)+1);
    if(tmp == NULL){
        return NULL;
    }
    tmp[0] = '\0';
    char *tok = strtok((char *)str, "'");
    tmp = strcat(tmp, tok);
    tok = strtok(NULL, "'");
    while (tok != NULL) {
        tmp = strcat(tmp, split);
        tmp = strcat(tmp, tok);
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
        return NULL;
    }

    ret_err:
    return expression;
}

int __expr_user_or_groups(xmlChar **expr, char *user,char **groups, int nb_groups){
    char *expr_format = "user[@name='%s'] or group[%s]";
    int size = 26 + (int)strlen(user);
    xmlChar *groups_str = (xmlChar *)xmlMalloc((nb_groups*57) * sizeof(xmlChar));
    if (!groups_str) {
        fputs("Error malloc\n", stderr);
        return -1;
    }
    xmlChar *str_ptr = groups_str;
    for (int i = 0; i < nb_groups; i++) {
        int contains_size = (int)strlen(groups[i])+21;
        int err = -1;
        if (i == 0) {
            err = xmlStrPrintf(str_ptr, contains_size, "contains(@names, '%s')", groups[i]);
        } else {
            contains_size = contains_size + 4;
            err = xmlStrPrintf(str_ptr, contains_size, " or contains(@names, '%s')", groups[i]);
        }
        if (err == -1) {
            fputs("Error xmlStrPrintf()\n", stderr);
            free(groups_str);
            return err;
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
    if(user_groups_size == -1) {
        free(sanitized_str);
        return NULL;
    }
    size = 70 + (int)strlen(sanitized_str) + user_groups_size;

    expression = (xmlChar *)xmlMalloc(size * sizeof(xmlChar));
    if (!expression) {
        fputs("Error malloc\n", stderr);
        goto ret_err;
    }
    
    // //role[(user[@name='lechatp'] or group[contains(@names,'lechatp') or contains(@names,'group1')]) and (commands/command[text()='%s'] or commands[not(command)])]
    err = xmlStrPrintf(expression, size, "//role[(%s) and (commands/command[text()=%s] or commands[not(command)])]", user_groups_char, sanitized_str);
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
    if(result != NULL){
        xmlXPathFreeObject(result);
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
        xmlFree(priority);
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
    char *command_block = ".//commands[contains(command, %s)]";
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
    xmlNodeSetPtr nodeset = NULL;
    xmlXPathContextPtr context = xmlXPathNewContext(role_node->doc);
    context->node = role_node;
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        goto free_error;
    }
    xmlChar *expression = expr_search_command_block_from_role(command);
    if (!expression) {
        fputs("Error expr_search_command_block_from_role()\n", stderr);
        goto free_error;
    }
    if(result != NULL){
        xmlXPathFreeObject(result);
    }
    result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        goto free_error;
    }
    nodeset = result->nodesetval;
    free_error:
    xmlXPathFreeContext(context);
    xmlFree(expression);
    if(nodeset == NULL || nodeset->nodeNr == 0){
        return NULL;
    }
    return *(nodeset->nodeTab);
}

xmlNodePtr find_empty_commands_block_from_role(xmlNodePtr role_node) {
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
    if(result != NULL){
        xmlXPathFreeObject(result);
    }
    result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        return NULL;
    }
    xmlNodeSetPtr nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        return NULL;
    }
    xmlXPathFreeContext(context);
    return *(nodeset->nodeTab);
}

/**
 * @brief retireve capabilities from document matching user, groups and command 
*/
int get_settings_from_doc(xmlDocPtr doc, char *user, int nb_groups, char **groups, char *command){
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
        *capabilities = '\0';
    }
    xmlChar *s_capabilities = xmlMalloc(xmlStrlen(capabilities)+5);
    xmlStrPrintf(s_capabilities, xmlStrlen(capabilities)+3, "%s=i", capabilities);
    xmlFree(capabilities);
    capabilities = s_capabilities;
    cap_t eff = cap_from_text((char*)capabilities);
    iab = cap_iab_init();
    
    cap_iab_fill(iab, CAP_IAB_AMB,eff, CAP_INHERITABLE);
    get_options_from_config(commands);
    if (options->bounding){
        cap_iab_fill(iab, CAP_IAB_BOUND,eff, CAP_INHERITABLE);
    }
    res = 1;
    cap_free(eff);
    xmlFree(capabilities);
    xmlXPathFreeObject(result);
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
int get_settings_from_config(char *user, int nb_groups, char **groups, char *command, cap_iab_t *p_iab, options_t *p_options)
{
    xmlDocPtr doc;
    doc = load_xml(XML_FILE);
    if (!doc)
        return 0;
    int res = get_settings_from_doc(doc, user, nb_groups, groups, command);
    *p_iab = iab;
    *p_options = options;
    xmlFreeDoc(doc);
    return res;
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
    if(result != NULL){
        xmlXPathFreeObject(result);
    }
    result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        return NULL;
    }
    xmlNodeSetPtr nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        return NULL;
    }
    xmlFree(expression);
    xmlXPathFreeContext(context);
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
/**
 * Unused
*/
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
    if(result != NULL){
        xmlXPathFreeObject(result);
    }
    result = xmlXPathEvalExpression(expression, context);
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



/************************************************************************
 ***                        PRINT FUNCTIONS                           ***
*************************************************************************/

xmlNodeSetPtr xmlNodeSetDup(xmlNodeSetPtr cur){
    xmlNodeSetPtr ret = malloc(sizeof(xmlNodeSet));
    int i;
    ret->nodeNr = cur->nodeNr;
    ret->nodeMax = cur->nodeMax;
    ret->nodeTab = malloc(sizeof(xmlNodePtr) * cur->nodeNr);
    for(i = 0; i < cur->nodeNr; i++){
        ret->nodeTab[i] = cur->nodeTab[i];
    }
    return ret;
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
    }

    ret_err:
    xmlFree(user_groups_char);
    return expression;
}

xmlNodeSetPtr get_right_roles(xmlDocPtr doc, char *user, int nb_groups, char **groups){
    xmlXPathContextPtr context = xmlXPathNewContext(doc);
    xmlNodeSetPtr nodeset = NULL;
    xmlNodeSetPtr filtered = NULL;
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        goto free_error;
    }
    xmlChar *expression = expr_search_access_roles(user, nb_groups, groups);
    if (!expression) {
        fputs("Error expr_search_role()\n", stderr);
        goto free_error;
    }
    if(result != NULL){
        xmlXPathFreeObject(result);
    }
    result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        goto free_error;
    }
    nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        goto free_error;
    }
    filtered = filter_wrong_roles(nodeset,groups,nb_groups);
    free_error:
    if(context != NULL)
        xmlXPathFreeContext(context);
    if(expression != NULL)
        xmlFree(expression);
    return filtered;
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
    xmlNodeSetPtr nodeset = NULL;
    xmlXPathContextPtr context = xmlXPathNewContext(role->doc);
    if (context == NULL) {
        fputs("Error in xmlXPathNewContext\n", stderr);
        goto ret_err;
    }
    context->node = role;
    xmlChar *expression = expr_search_element_in_role(element);
    if (!expression) {
        fputs("Error expr_search_element_in_role()\n", stderr);
        goto ret_err;
    }
    if(result != NULL){
        xmlXPathFreeObject(result);
    }
    result = xmlXPathEvalExpression(expression, context);
    if (result == NULL) {
        fputs("Error in xmlXPathEvalExpression\n", stderr);
        goto ret_err;
    }
    nodeset = result->nodesetval;
    if(nodeset->nodeNr == 0){
        nodeset = NULL;
        goto ret_err;
    }
    ret_err:
    xmlXPathFreeContext(context);
    xmlFree(expression);
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
    xmlChar * name = xmlGetProp(role, (const xmlChar *)"name");
    printf("Role \"%s\"\n", name);
    xmlFree(name);
    xmlAttrPtr priority = xmlHasProp(role, (const xmlChar *)"priority");
    xmlAttrPtr bounding = xmlHasProp(role, (const xmlChar *)"bounding");
    xmlAttrPtr noroot = xmlHasProp(role, (const xmlChar *)"root");
    xmlAttrPtr keepenv = xmlHasProp(role, (const xmlChar *)"keep-env");
    
    if(priority || bounding || noroot || keepenv){
        printf("%sProperties:\n", role->children ? element:end);
        if (priority) {
            printf("%s%sPriority %s", vertical, bounding || noroot || keepenv ? element : end, priority->children->content);
        }
    }
    xmlNodeSetPtr users = xmlNodeSetDup(search_element_in_role(role,"user"));
    xmlNodeSetPtr groups = xmlNodeSetDup(search_element_in_role(role,"group"));
    xmlNodeSetPtr commands = search_element_in_role(role,"commands");
    if (users->nodeNr + groups->nodeNr > 0){
        char *side = commands->nodeNr ? element:space;
        printf("%sActors:\n", commands->nodeNr ? element:end);
        for (int i = 0; i < users->nodeNr; i++) {
            xmlNodePtr user = users->nodeTab[i];
            xmlChar *username = xmlGetProp(user, (const xmlChar *)"name");
            printf("%s%s%s\n", side, i+1 < (users->nodeNr + groups->nodeNr) ? element : end, username);
            xmlFree(username);
        }
        for (int i = 0; i < groups->nodeNr; i++) {
            xmlNodePtr group = groups->nodeTab[i];
            xmlChar *groupname = xmlGetProp(group, (const xmlChar *)"names");
            printf("%s%s%s\n", side, i+1 < groups->nodeNr ? element : end, groupname);
            xmlFree(groupname);
        }
    }
    print_commands(commands,0);
    xmlXPathFreeObject(result);
    xmlXPathFreeNodeSet(users);
    xmlXPathFreeNodeSet(groups);
}

void print_full_role(char *role){
    xmlDocPtr doc;

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
    xmlFreeDoc(doc);

}

void print_full_roles(){
    xmlDocPtr doc;

    doc = load_xml(XML_FILE);
    if (doc)
        for(xmlNodePtr role = doc->children->children; role; role = role->next){
            print_xml_role(role);
        }
    else{
        printf("Error loading XML file\n");
    }
    xmlFreeDoc(doc);
}

void print_rights(char *user, int nb_groups, char **groups, int restricted)
{
    xmlDocPtr doc;

    doc = load_xml(XML_FILE);
    if (doc){
        xmlNodeSetPtr roles = get_right_roles(doc, user, nb_groups, groups);
        xmlNodeSetPtr tmp = xmlNodeSetDup(roles);
        if(roles){
            for (int i = 0; i < tmp->nodeNr; i++) {
                xmlNodePtr role = tmp->nodeTab[i];
                if(restricted){
                    xmlNodeSetPtr commands = search_element_in_role(role,"commands");
                    xmlChar *rolename = xmlGetProp(role, (const xmlChar *)"name");
                    printf("Role \"%s\"\n", rolename);
                    xmlFree(rolename);
                    print_commands(commands,RESTRICTED);
                    xmlXPathFreeNodeSet(commands);
                }else{
                    print_xml_role(role);
                }
            }
        }else{
            printf("Permission denied\n");
        }
        xmlXPathFreeNodeSet(tmp);
    }else{
        printf("Error loading XML file\n");
    }
    xmlFreeDoc(doc);
}

/**
 * @brief Check if user has rights to print role
 * @param role Role to check
 * @param user User to check
 * @param nb_groups Number of groups of user
 * @param groups Groups of user
 * @return >0 if user has rights, 0 otherwise
*/
int check_rights(xmlNodePtr role, char *user, int nb_groups, char **groups){
    xmlNodeSetPtr users = search_element_in_role(role,"user");
    xmlNodeSetPtr groups_node = NULL;
    int found = 0;
    for (int i = 0; i < users->nodeNr; i++) {
        xmlNodePtr user_node = users->nodeTab[i];
        xmlChar *username = xmlGetProp(user_node, (const xmlChar *)"name");
        if(!xmlStrcmp((xmlChar*)user, username)){
            found = 1;
            xmlFree(username);
            goto result;
        }
        xmlFree(username);
    }
    groups_node = search_element_in_role(role,"group");
    for (int i = 0; i < groups_node->nodeNr; i++) {
        xmlNodePtr group_node = groups_node->nodeTab[i];
        xmlChar *group = xmlGetProp(group_node, (const xmlChar *)"names");
        int j = 0;
        for (; j < nb_groups; j++) {
            if(!xmlStrcmp(group, (xmlChar*)groups[j])){
                found++;
            }
        }
        xmlFree(group);
        if(found == j){
            goto result;
        }
        found = 0;
    }
    result:
    return found;
}

void print_rights_role(char *role, char *user, int nb_groups, char **groups, int restricted){
    xmlDocPtr doc;

    doc = load_xml(XML_FILE);
    if (doc){
        xmlNodePtr role_node = get_role_node(doc, role);
        if(role_node && check_rights(role_node, user, nb_groups, groups)){
            if(restricted){
                xmlNodeSetPtr commands = search_element_in_role(role_node,"commands");
                xmlChar *rolename = xmlGetProp(role_node, (const xmlChar *)"name");
                printf("Role \"%s\"\n", rolename);
                xmlFree(rolename);
                print_commands(commands,RESTRICTED);
            }else{
                print_xml_role(role_node);
            }
        }else{
            printf("Permission denied\n");
        }
        xmlXPathFreeObject(result);
    }else{
        printf("Error loading XML file\n");
    }
    xmlFreeDoc(doc);
}