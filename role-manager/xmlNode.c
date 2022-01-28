#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <stdio.h>
#include <string.h>

#include "xmlNode.h"


/* @parent is optionnal. NULL for not use
 * @text is optionnal. NULL for not use
 * @return : -1 to error | 0 to success
 */
int addNode(xmlNodePtr *elem, char *parent, char *text)
{
    xmlNodePtr node = *elem;

    if (parent != NULL) {
        if (!strcmp(parent, "role")) {
            *elem = xmlNewChild(*elem, NULL, BAD_CAST "role", NULL);
            xmlNewProp(*elem, BAD_CAST "name", BAD_CAST text);
            return 0;
        }

        if (!strcmp(parent, "capabilities")
            || !strcmp(parent, "users")
            || !strcmp(parent, "groups")
            || !strcmp(parent, "commands")) {

                *elem = xmlNewChild(*elem, NULL, BAD_CAST parent, NULL);
            }

        else {
            fputs ("Parent argument is wrong\n", stderr);
            return -1;
        }
    }

    if (text != NULL) {
        if (!xmlStrcmp(node->name, BAD_CAST "capabilities")) {
            xmlNewChild(node, NULL, BAD_CAST "capability", BAD_CAST text);
            return 0;
        }
        if (!xmlStrcmp(node->name, BAD_CAST "users")) {
            node = xmlNewChild(node, NULL, BAD_CAST "user", NULL);
            xmlNewProp (node, BAD_CAST "name", BAD_CAST text);
            return 0;
        }
        if (!xmlStrcmp(node->name, BAD_CAST "groups")) {
            node = xmlNewChild(node, NULL, BAD_CAST "group", NULL);
            xmlNewProp (node, BAD_CAST "name", BAD_CAST text);
            return 0;
        }
        if (!xmlStrcmp(node->name, BAD_CAST "commands")) {
            xmlNewChild(node, NULL, BAD_CAST "command", BAD_CAST text);
            return 0;
        }

        fputs("Bad cursor\n", stderr);
        return -1;
    }

    return 1;
}


/* @return : -1 to error | 0 to success */
int editNode(xmlNodePtr elem, char *text)
{
    if (!xmlStrcmp(elem->name, BAD_CAST "capability") ||
        !xmlStrcmp(elem->name, BAD_CAST "command")) {

        xmlNodeSetContent(elem, BAD_CAST text);
        return 1;
    }
    if (!xmlStrcmp(elem->name, BAD_CAST "user") ||
        !xmlStrcmp(elem->name, BAD_CAST "group")) {

        xmlSetProp(elem, BAD_CAST "name", BAD_CAST text);
        return 1;
    }

    fputs("Bad cursor\n", stderr);
    return -1;
}


void deleteNode(xmlNodePtr elem)
{
    xmlUnlinkNode(elem);
    xmlFreeNode(elem);
}


char *string(int mode, int choice)
{
    /* Mode
     * 0 = String mode 1
     * 1 = String singular Mode 2
     * * = Plural mode
     */
    if (!mode) {
        switch (choice) {
        case 1:
            return "add";
        case 2:
            return "edit";
        default:
            return "delete";
        }
    }
    else {
        switch (choice) {
        case CAP:
            if (mode == 1)
                return "capability";
            else
                return "capabilities";
        case USER:
            if (mode == 1)
                return "user";
            else
                return "users";
        case GROUP:
            if (mode == 1)
                return "group";
            else
                return "groups";
        case COMMAND:
            if (mode == 1)
                return "command";
            else
                return "commands";
        case USERCOMMAND:
            if (mode == 1)
                return "user command";
            else
                return "users";
        default:
            if (mode == 1)
                return "group command";
            else
                return "groups";
        }
    }
}


xmlChar *newXPression(char *role, int elemDef, char *elem)
{
    int err;
    int size = 0;
    xmlChar *expression = NULL;

    size = 20 + (int)strlen(role);

    if (elemDef > 0)
        size += (int)strlen(string(2, elemDef)+1);
    if (elem)
        size += (int)strlen(elem);

    expression = (xmlChar *)malloc(size * sizeof(xmlChar));
    if (!expression) {
        fputs("Error malloc\n", stderr);
        goto ret_err;
    }

    if (elemDef == 0) {
        err = xmlStrPrintf(expression, size, "//role[@name='%s'][1]", role);
        if (err == -1) {
            fputs("Error xmlStrPrintf()\n", stderr);
            free(expression);
            goto ret_err;
        }
    }
    else {
        err = xmlStrPrintf(expression, size, "//role[@name='%s'][1]/%s", role, string(2, elemDef));
        if (err == -1) {
            fputs("Error xmlStrPrintf()\n", stderr);
            free(expression);
            goto ret_err;
        }
    }


    if (elem) {
        xmlStrncat(expression, BAD_CAST elem, strlen(elem));
    }

    return expression;

ret_err:

    return NULL;
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
