#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <sys/capability.h>
#include "role_manager.h"

extern int errno;

xmlDocPtr xml_verifier(void)
{
    int error = 0;
    xmlParserCtxtPtr ctxt;
    xmlDocPtr doc;
    xmlNodePtr cur_node;

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        fputs("Failed to allocate parser context\n", stderr);
        return NULL;
    }

    doc = xmlCtxtReadFile(ctxt, XML_FILE, NULL, XML_PARSE_DTDVALID);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse %s\n", XML_FILE);
        error = 1;
    }
    else {
        if (ctxt->valid == 0) {
            fprintf(stderr, "Failed to validate %s\n", XML_FILE);
            error = 1;
        }
        xmlFreeDoc(doc);
    }

    xmlFreeParserCtxt(ctxt);
    if (error)
        return NULL;

    xmlKeepBlanksDefault(0);
    doc = xmlParseFile("./file.xml");
    //doc = xmlReadFile(XML_FILE, NULL, 0);
    cur_node = xmlDocGetRootElement(doc);

    if (xmlStrcmp(cur_node->name, BAD_CAST "capabilityrole") != 0) {
        fputs("Root element would be <capabilityrole>\n", stderr);
        error = 1;
        goto ret_gt;
    }

    if (cur_node->children == NULL) {
        fputs("Root element must have <roles> child !\n", stderr);
        error = 1;
        goto ret_gt;
    }

    cur_node = cur_node->children;

    if (xmlStrcmp(cur_node->name, BAD_CAST "roles") != 0) {
        fprintf(stderr, "Child element would be <roles> but not <%s>\n", (char*)cur_node->name);
        error = 1;
    }

ret_gt:
    if (error) {
        xmlFreeDoc(doc);
        return NULL;
    }
    return(doc);
}


int role_verifier(xmlDocPtr doc, xmlNodePtr *role_node, char *role)
{
    xmlNodePtr root_node = NULL;
    xmlNodePtr cur_node = NULL;

    if (!strcmp(role, "")) {
        fputs("Role is empty\n", stderr);
        return -1;
    }
    if (strlen(role) >= MAX_ROLE_LEN) {
        fprintf(stderr, "Role is too long : %d charchters max\n", MAX_ROLE_LEN);
        return -1;
    }
    if (strchr(role, '\'') != NULL && strchr(role, '"') != NULL) {
        fputs("You cannot set quote and apostrophe in a parameter due to XML restrictions\n", stderr);
        return -1;
    }

    root_node = xmlDocGetRootElement(doc);
    cur_node = root_node;

    do {
        cur_node = cur_node->children;
        if (cur_node->type == XML_ELEMENT_NODE && !xmlStrcmp(cur_node->name, BAD_CAST "roles"))
            root_node = cur_node;
        if (cur_node->type == XML_ELEMENT_NODE && !xmlStrcmp(cur_node->name, BAD_CAST "role")) {
            for (;cur_node; cur_node = cur_node->next) {
                *role_node = cur_node;
                if (cur_node->type == XML_ELEMENT_NODE && !xmlStrcmp(xmlGetProp(cur_node, BAD_CAST "name"), BAD_CAST role)) {
                    return 1;
                }
            }
        }
    } while(cur_node != NULL);

    *role_node = root_node;

    return 0;
}


int capability_verifier(char *cap_text, args_struct *args)
{
    char *token;
    cap_value_t capVal;

    token = strtok(cap_text, ",");
    do {
        if (!strcmp(token, "*")) {
            args->capability[42] = true;
            return 0;
        }
        if (cap_from_name(token, &capVal) == -1) {
            fprintf(stderr, "\"%s\" : Invalid Capability\n", token);
            return -1;
        }

        args->capability[capVal] = true;
    } while ( (token = strtok(NULL, ",")) != NULL);

    return 0;
}


int user_verifier(char *users, args_struct *args)
{
    char *token;

    token = strtok(users, ",");

    do {
        if (args->uc == 10) {
            fputs("10 users max can be added\n", stderr);
            return -1;
        }
        if (strlen(token) >= MAX_NAME_LEN) {
            fprintf(stderr, "Username is too long -> %d characters max\n", MAX_NAME_LEN);
            return -1;
        }

        errno = 0;
        if (getpwnam(token) == NULL) {
            if (errno != 0)
                perror("getpwnam()");
            else
                fprintf(stderr, "\"%s\" : Username doesn't exist\n", token);
            return -1;
            }

            args->uc++;
    } while ( (token = strtok(NULL, ",")) != NULL);

    return 0;
}


int group_verifier(char *groups, args_struct *args)
{
    char *token;

    token = strtok(groups, ",");

    do {
        if (args->gc == 10) {
            fputs("10 groups max can be added\n", stderr);
            return -1;
        }
        if (strlen(token) >= MAX_NAME_LEN) {
            fprintf(stderr, "Group is too long -> %d characters max\n", MAX_NAME_LEN);
            return -1;
        }

        errno = 0;
        if (getgrnam(token) == NULL) {
            if (errno != 0)
                perror("getgrnam()");
            else
                fprintf(stderr, "\"%s\" : Group doesn't exist\n", token);
            return -1;
        }

        args->gc++;
    } while ( (token = strtok(NULL, ",")) != NULL);

    return 0;
}


int command_verifier(char *command)
{
    if (strlen(command) >= MAX_COMMAND_LEN) {
        fprintf(stderr, "Comand is too long -> %d characters max\n", MAX_COMMAND_LEN);
        return -1;
    }
    if (!strcmp(command, "")) {
        fputs("Command is empty\n", stderr);
        return -1;
    }
    if (strchr(command, '\'') != NULL && strchr(command, '"') != NULL) {
        fputs("You cannot set quote and apostrophe in a parameter due to XML restrictions\n", stderr);
        return -1;
    }

    return 0;
}
