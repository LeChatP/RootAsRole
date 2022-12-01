#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <stdio.h>
#include <string.h>
#include <sys/capability.h>
#include "xml_manager.h"

xmlChar *expr_search_role_by_name(char *role, char *elem);

/* @role_node is optionnal. NULL for not use
 * @return : -1 to error | 0 if role doesn't exist | 1 if role exists
 */
int role_verifier(xmlDocPtr doc, xmlNodePtr *role_node, char *role){
    xmlChar *expression = NULL;
    int ret;

    if (!strcmp(role, "")) {
        fputs("Role is empty\n", stderr);
        return -1;
    }
    if (strchr(role, '\'') != NULL && strchr(role, '"') != NULL) {
        fputs("You cannot set quote and apostrophe in a parameter due to XML restrictions\n", stderr);
        return -1;
    }

    expression = expr_search_role_by_name(role, NULL);
    if (!expression)
        return -1;

    ret = researchNode(doc, expression, role_node, NULL);

    free(expression);
    return ret;
}

/* Doit on valider la DTD avant de valider le document par la DTD ?
 * https://stackoverflow.com/questions/4594049/dtd-validation-with-libxml2
 * https://www.julp.fr/articles/1-4-validation-d-un-document-xml.html
 * Si oui, cela implique de mapper la mémoire avec la vrai DTD,
 * pour ensuite la comparer avec la DTD du fichier, ou bien retirer
 * la DTD du fichier pour ne laisser que la DTD en mémoire effectuer
 * les vérifications.
 *
 * @return : NULL to error | doc to success
 */
xmlDocPtr xml_verifier(void)
{
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc;

    ctxt = xmlNewParserCtxt();
    if (!ctxt) {
        fputs("Failed to allocate parser context\n", stderr);
        return NULL;
    }

    doc = xmlCtxtReadFile(ctxt, XML_FILE, NULL, XML_PARSE_DTDVALID|XML_PARSE_NOBLANKS);
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
 * This function will replace key to value in str
 */
static xmlChar* sanitizeCharTo(xmlChar *str,xmlChar key,xmlChar *value);

/**
 * replace string s in position start to length character of ct
 * return the new char*
 */
static char *str_replace(const char *s, unsigned int start, unsigned int length,
			 const char *ct);

/* @parent is optionnal. NULL for not use
 * @text is optionnal. NULL for not use
 * @return : -1 to error | 0 to success
 */
xmlNodePtr addContentNode(xmlNodePtr parent,xmlChar *type, xmlChar *content){
    return xmlNewChild(parent,NULL,type,content);
}

xmlNodePtr addNamedNode(xmlNodePtr parent, xmlChar *element, xmlChar *name){
    xmlNodePtr node = xmlNewChild(parent, NULL, element, NULL);
    xmlNewProp(node, (xmlChar *)"name", name);
    return node;
}

xmlNodePtr addContainerNode(xmlNodePtr parent, xmlChar *label){
    return xmlNewChild(parent,NULL,label,NULL);
}


/**
 * This function will replace key to value in str
 * will free str
 */
static xmlChar* sanitizeCharTo(xmlChar *str,xmlChar key,xmlChar *value){
	const xmlChar *position = xmlStrchr(str,key);
	if(position != NULL){
		int pos = position-str;
		xmlChar *new_command = NULL;
		while(position != NULL){
			new_command = (xmlChar *)str_replace((char *)str,pos,1,(char *) value);
			xmlFree(str);
			str = new_command;
			position = xmlStrchr(&str[pos+xmlStrlen(value)],key);
			pos = position-str;
		}
	}
	return str;
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
 * Sanitize string, escape unwanted chars to their xml equivalent
 * keep str same, return should be freed
 */
xmlChar* encodeXml(const char* str){
	xmlChar *tmpstr = xmlCharStrndup(str, strlen(str));
	tmpstr = sanitizeCharTo(tmpstr,(xmlChar) '&',(xmlChar*) "&amp;"); // check & before all
	tmpstr = sanitizeCharTo(tmpstr,(xmlChar) '\'',(xmlChar*) "&apos;");
	tmpstr = sanitizeCharTo(tmpstr,(xmlChar) '\"',(xmlChar*) "&quot;");
	tmpstr = sanitizeCharTo(tmpstr,(xmlChar) '<',(xmlChar*) "&lt;");
	tmpstr = sanitizeCharTo(tmpstr,(xmlChar) '>',(xmlChar*) "&gt;");
	return tmpstr;
}


void print_role(xmlNodePtr role_node){
	char *role_pattern = "As \'%s\' role, with \'%s\' capabilities:\n";
	char *actor_pattern = "%s%s \'%s\' can execute ";
	char *vertical = "│  ";
	char *element = "├─ ";
	char *end = "└─ ";
	char *role_delim = "-----------------------\n";

    printf("%s",role_delim);
	for(xmlNodePtr container = role_node->children;container != NULL; container = container->next){
		if(!xmlStrcmp(container->name,(xmlChar*)"capabilities")){
			char capabilities[2048] = "";
			for(xmlNodePtr capability = container->children;capability != NULL; capability = capability->next){
				
				if(capability->children->content[0] == (xmlChar)L'*'){
					strcpy(capabilities,"all");
					break;
				}else{
					int cap_size = strlen((const char *)capability->children->content);
					strncat(capabilities,(char*)capability->children->content,cap_size);
					if(capability->next){
						strncat(capabilities,",",2);
					}
				}
			}
			printf(role_pattern,role_node->name,capabilities);
			break;
		}
	}
	for(xmlNodePtr container = role_node->children;container != NULL; container = container->next){
	  	if(xmlStrcmp(container->name,(xmlChar*)"capabilities")){
			for(xmlNodePtr actor = container->children;actor != NULL; actor = actor->next){
				
				const xmlChar *actor_type = actor->name;
				const xmlChar *actor_name = xmlGetProp(actor,(xmlChar*)"name");
				printf(actor_pattern,actor->next || container->next ? element : end,actor_type,actor_name);
				
				if(actor->children !=NULL){
					printf(":\n");
					for(xmlNodePtr command = actor->children->children;command != NULL; command = command->next){
						printf("%s%s%s\n",actor->next || container->next ? vertical : "   ",command->next ? element:end,command->children->content);
					}
				} else {
					printf("any command\n");
				}
			}
		}
		
	}
    printf("%s",role_delim);
}

u_int64_t get_xml_caps(xmlNodePtr xmlCaps){
	u_int64_t caps = 0UL;
	for(xmlNodePtr xcap = xmlCaps->children; xcap !=NULL; xcap = xcap->next){
		cap_value_t capVal;
		if(xcap->children->content[0] == '*') return ((u_int64_t) -1)>>(64-cap_max_bits());
		cap_from_name((char *)xcap->children->content, &capVal);
		caps |= 1UL<<capVal;
	}
	return caps;
}

CMD *get_xml_cmds(xmlNodePtr xmlCmds){
	CMD *root_cmds = (CMD *)malloc(sizeof(CMD));
	CMD *cmds = root_cmds;
	for(xmlNodePtr xmlCmd = xmlCmds->children; xmlCmd !=NULL; xmlCmd = xmlCmd->next){
		int str_size = xmlStrlen(xmlCmd->children->content);
		cmds->name = malloc(str_size+1*sizeof(xmlChar));
		strncpy(cmds->name,(char*)xmlCmd->children->content,str_size);
		cmds->name[str_size] = '\0';
		if(xmlCmd->next){
			cmds->next = (CMD *)malloc(sizeof(CMD));
			cmds = cmds->next;
		}else cmds->next = NULL;
	}
	return root_cmds;
}

ACTOR *get_xml_actors(xmlNodePtr xmlActors){
	ACTOR *root_actor = (ACTOR*) malloc(sizeof(ACTOR));
	ACTOR *actor = root_actor;
	for(xmlNodePtr subcontainer = xmlActors->children; subcontainer!=NULL;subcontainer = subcontainer->next){
		actor->name = (char*)xmlStrdup(xmlGetProp(subcontainer,(xmlChar*)"name"));
		if(subcontainer->children && subcontainer->children->children)
			actor->cmds = get_xml_cmds(subcontainer->children);
		else actor->cmds = NULL;
		if(subcontainer->next){
			actor->next = (ACTOR*) malloc(sizeof(ACTOR));
			actor = actor->next;
		}else{
			actor->next = NULL;
		}
	}
	return root_actor;
}

int get_role_node(xmlNodePtr *role_node, char *role){
	xmlDocPtr doc;
    if (!(doc = xml_verifier()))
        return 0;

    if(!role_verifier(doc, role_node, role)){
		fputs("Role doesn't exists\n",stderr);
		return 0;
	}
	return 1;
}

int get_role(ROLE *role_struct, char *role){
	role_struct->capabilities = 0;
	role_struct->groups = NULL;
	role_struct->users = NULL;
	LIBXML_TEST_VERSION

	xmlNodePtr role_node = NULL;
	int ret = get_role_node(&role_node,role);
	if(ret){
        role_struct->name = (char*)xmlStrdup(xmlGetProp(role_node,(xmlChar*)"name"));
		for(xmlNodePtr container = role_node->children;container !=NULL;container = container->next){
			if(!xmlStrcmp(container->name,(xmlChar*)"capabilities")){
				role_struct->capabilities = get_xml_caps(container);
			}else {
				ACTOR *actor = get_xml_actors(container);
				if(container->name[0] == 'u' || container->name[0] == 'U'){
					role_struct->users = actor;
				}else{
					role_struct->groups = actor;
				}
			}
		}
		xmlDocPtr doc = role_node->doc;
		xmlFreeDoc(doc);
	}
	return ret;
}

int delete_role(char *role){
	xmlNodePtr role_node = NULL;
	int ret = get_role_node(&role_node,role);
	if(ret){
		xmlDocPtr doc = role_node->doc;
		xmlUnlinkNode(role_node);
		xmlFreeNode(role_node);
		xmlSaveFormatFileEnc(XML_FILE, doc, "UTF-8", 1);
		xmlFreeDoc(doc);
	}
	return ret;
}

int save_role_to_file(ROLE *role){
	xmlDocPtr doc;
	if (!(doc = xml_verifier()))
		return 0;

	xmlNodePtr role_node = NULL;
	if(!role_verifier(doc, &role_node, role->name)){
		fputs("Role doesn't exists\n",stderr);
		return 0;
	}
	xmlNodePtr container = role_node->children;
	while(container != NULL){
		xmlNodePtr next = container->next;
		xmlUnlinkNode(container);
		xmlFreeNode(container);
		container = next;
	}
	xmlNodePtr caps_node = xmlNewNode(NULL,(xmlChar*)"capabilities");
	xmlAddChild(role_node,caps_node);
	for(int i = 0; i < cap_max_bits(); i++){
		if(role->capabilities & (1UL<<i)){
			xmlNodePtr cap_node = xmlNewNode(NULL,(xmlChar*)"capability");
			xmlNodePtr cap_name = xmlNewText((xmlChar*)cap_to_name(i));
			xmlAddChild(cap_node,cap_name);
			xmlAddChild(caps_node,cap_node);
		}
	}
    xmlFreeNode(caps_node);
	xmlNodePtr users_node = xmlNewNode(NULL,(xmlChar*)"users");
	xmlAddChild(role_node,users_node);
	for(ACTOR *actor = role->users; actor != NULL; actor = actor->next){
		xmlNodePtr user_node = xmlNewNode(NULL,(xmlChar*)"user");
		xmlSetProp(user_node,(xmlChar*)"name",(xmlChar*)actor->name);
		xmlAddChild(users_node,user_node);
		xmlNodePtr cmds_node = xmlNewNode(NULL,(xmlChar*)"commands");
		xmlAddChild(user_node,cmds_node);
		for(CMD *cmd = actor->cmds; cmd != NULL; cmd = cmd->next){
			xmlNodePtr cmd_node = xmlNewNode(NULL,(xmlChar*)"command");
			xmlNodePtr cmd_name = xmlNewText((xmlChar*)cmd->name);
			xmlAddChild(cmd_node,cmd_name);
			xmlAddChild(cmds_node,cmd_node);
            xmlFreeNode(cmd_node);
            xmlFreeNode(cmd_name);
		}
	}
    xmlFreeNode(users_node);
	xmlNodePtr groups_node = xmlNewNode(NULL,(xmlChar*)"groups");
	xmlAddChild(role_node,groups_node);
	for(ACTOR *actor = role->groups; actor != NULL; actor = actor->next){
		xmlNodePtr group_node = xmlNewNode(NULL,(xmlChar*)"group");
		xmlSetProp(group_node,(xmlChar*)"name",(xmlChar*)actor->name);
		xmlAddChild(groups_node,group_node);
		xmlNodePtr cmds_node = xmlNewNode(NULL,(xmlChar*)"commands");
		xmlAddChild(group_node,cmds_node);
		for(CMD *cmd = actor->cmds; cmd != NULL; cmd = cmd->next){
			xmlNodePtr cmd_node = xmlNewNode(NULL,(xmlChar*)"command");
			xmlNodePtr cmd_name = xmlNewText((xmlChar*)cmd->name);
			xmlAddChild(cmd_node,cmd_name);
			xmlAddChild(cmds_node,cmd_node);
            xmlFreeNode(cmd_node);
            xmlFreeNode(cmd_name);
		}
        xmlFreeNode(cmds_node);
        xmlFreeNode(group_node);
	}
    xmlFreeNode(groups_node);
	xmlSaveFormatFileEnc(XML_FILE, doc, "UTF-8", 1);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return 1;
}


void deleteNode(xmlNodePtr elem)
{
    xmlUnlinkNode(elem);
    xmlFreeNode(elem);
}


xmlChar *expr_search_role_by_name(char *role, char *elem)
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


int researchNode(xmlDocPtr doc, xmlChar *expression, xmlNodePtr *node,
                 xmlXPathObjectPtr *xobject)
{
    xmlXPathObjectPtr result = NULL;
    xmlXPathContextPtr context = NULL;
    int ret;

    context = xmlXPathNewContext(doc);
    if(!context) {
        fputs("Error: unable to create new XPath context\n", stderr);
        return -1;
    }

    result = xmlXPathEval(expression, context);
    if (!result) {
        fprintf(stderr,"Error: unable to evaluate xpath expression %s\n", (char *)expression);
        xmlXPathFreeContext(context);
        return -1;
    }

    ret = 0;
    if (result->nodesetval->nodeNr > 0) {
        ret = 1;
        if (xobject) {
            *xobject = result;
            goto ret_xobject;
        }
        if (node)
            *node = result->nodesetval->nodeTab[0];
    }

    xmlXPathFreeObject(result);
ret_xobject:
    xmlXPathFreeContext(context);

    return ret;
}
