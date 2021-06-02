#include "role_manager.h"
#include <stdio.h>
#include <string.h>

xmlNodePtr researchNode(xmlNodePtr role_node, int elem, char *text)
{
    xmlNodePtr cur_node = role_node;
    int pos = 0;

    while(cur_node != NULL){

		if (cur_node->type == XML_ELEMENT_NODE) {
            switch (elem) {
            case CAP :
                if (text == NULL && !xmlStrcmp(cur_node->name, BAD_CAST "capabilities"))
                    return cur_node;
                if (!xmlStrcmp(cur_node->name, BAD_CAST "capability") && !xmlStrcmp(xmlNodeGetContent(cur_node), BAD_CAST text))
                    return cur_node;

                break;
            case USER :
                if (!xmlStrcmp(cur_node->name, BAD_CAST "users")) {
                    if (text == NULL)
                        return cur_node;
                    pos = 1;
                }
                if (xmlStrcmp(cur_node->name, BAD_CAST "user") && !xmlStrcmp(xmlGetProp(cur_node, BAD_CAST "name"), BAD_CAST text))
                    return cur_node;

                break;
            case GROUP :
                if (!xmlStrcmp(cur_node->name, BAD_CAST "groups")) {
                    if (text == NULL)
                        return cur_node;
                    pos = 2;
                }
                if (xmlStrcmp(cur_node->name, BAD_CAST "group") && !xmlStrcmp(xmlGetProp(cur_node, BAD_CAST "name"), BAD_CAST text))
                    return cur_node;

                break;
            case USERCOM :
                if (pos == 1) {
                    if (text == NULL && !xmlStrcmp(cur_node->name, BAD_CAST "commands"))
                        return cur_node;
                    if (!xmlStrcmp(cur_node->name, BAD_CAST "command") && !xmlStrcmp(xmlNodeGetContent(cur_node), BAD_CAST text))
                        return cur_node;
                }

                break;
            case GROUPCOM :
                if (pos == 2) {
                    if (text == NULL && !xmlStrcmp(cur_node->name, BAD_CAST "commands"))
                        return cur_node;
                    if (!xmlStrcmp(cur_node->name, BAD_CAST "command") && !xmlStrcmp(xmlNodeGetContent(cur_node), BAD_CAST text))
                        return cur_node;
                }

                break;
            default :
                fputs("Bad elem argument\n", stderr);
                return NULL;
            }

            if (cur_node->children != NULL) {
                xmlNodePtr node =  researchNode(cur_node->children, elem, text);
                if(node != NULL)
                    return node;
            }
        }

        cur_node = cur_node->next;
    }

    return NULL;
}

int addNode(xmlNodePtr *elem, char *parent, char *text)
{
    xmlNodePtr node = *elem;

    if (parent != NULL) {
        if (!strcmp(parent, "role")) {
            *elem = xmlNewChild(*elem, NULL, BAD_CAST "role", NULL);
            xmlNewProp(*elem, BAD_CAST "name", BAD_CAST text);
            return 1;
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
            return 1;
        }
        if (!xmlStrcmp(node->name, BAD_CAST "users")) {
            node = xmlNewChild(node, NULL, BAD_CAST "user", NULL);
            xmlNewProp (node, BAD_CAST "name", BAD_CAST text);
            return 1;
        }
        if (!xmlStrcmp(node->name, BAD_CAST "groups")) {
            node = xmlNewChild(node, NULL, BAD_CAST "group", NULL);
            xmlNewProp (node, BAD_CAST "name", BAD_CAST text);
            return 1;
        }
        if (!xmlStrcmp(node->name, BAD_CAST "commands")) {
            xmlNewChild(node, NULL, BAD_CAST "command", BAD_CAST text);
            return 1;
        }

        fputs("Bad cursor\n", stderr);
        return -1;
    }

    return 1;
}

void deleteNode(xmlNodePtr elem)
{
    xmlUnlinkNode(elem);
    xmlFreeNode(elem);
}
