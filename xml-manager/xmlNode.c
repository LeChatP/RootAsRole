#include "xml_manager.h"

xmlNodePtr xmlAddRole(xmlNodePtr root_node, char *role)
{
    xmlNodePtr node;

    node = xmlNewChild(root_node, NULL, BAD_CAST "role", NULL);
    xmlNewProp(node, BAD_CAST "name", BAD_CAST role);

    return node;
}


void xmlAddCapability(xmlNodePtr role_node, char *cap_text)
{
    xmlNodePtr node;
    bool flag = false;

    node = role_node;
    node = node->children;

    while(node != NULL) {
        if (node->type == XML_ELEMENT_NODE && !xmlStrcmp(node->name, BAD_CAST "capabilities")) {
            flag = true;
            break;
        }
        node = node->next;
    }

    if (!flag) {
        node = xmlNewChild(role_node, NULL, BAD_CAST "capabilities", NULL);
    }
    xmlNewChild(node, NULL, BAD_CAST "capability", BAD_CAST cap_text);
}


void xmlAddUser(xmlNodePtr role_node, char *username)
{
    xmlNodePtr node;
    bool flag = false;

    node = role_node;
    node = node->children;

    while(node != NULL) {
        if (node->type == XML_ELEMENT_NODE && !xmlStrcmp(node->name, BAD_CAST "users")) {
            flag = true;
            break;
        }
        node = node->next;
    }

    if (!flag) {
        node = xmlNewChild(role_node, NULL, BAD_CAST "users", NULL);
    }

    node = xmlNewChild(node, NULL, BAD_CAST "user", NULL);
    xmlNewProp (node, BAD_CAST "name", BAD_CAST username);
}


void xmlAddGroup(xmlNodePtr role_node, char *groupname)
{
    xmlNodePtr node;
    bool flag = false;

    node = role_node;
    node = node->children;

    while(node != NULL) {
        if (node->type == XML_ELEMENT_NODE && !xmlStrcmp(node->name, BAD_CAST "groups")) {
            flag = true;
            break;
        }
        node = node->next;
    }

    if (!flag) {
        node = xmlNewChild(role_node, NULL, BAD_CAST "groups", NULL);
    }

    node = xmlNewChild(node, NULL, BAD_CAST "group", NULL);
    xmlNewProp (node, BAD_CAST "name", BAD_CAST groupname);
}


void xmlAddUserCommand(xmlNodePtr role_node, char *command)
{
    xmlNodePtr node;
    bool flag = false;

    node = role_node;
    node = node->children;

    while (node != NULL) {
        if (node->type == XML_ELEMENT_NODE && !xmlStrcmp(node->name, BAD_CAST "users")) {
            node = node->last->prev;
            if (node->type == XML_ELEMENT_NODE && !xmlStrcmp(node->name, BAD_CAST "user")) {
                node = node->children;
                if (node != NULL) {
                    node = node->next;
                    flag = true;
                }
                break;
            }
        }
        node = node->next;
    }

    if (!flag) {
        node = xmlNewChild(node, NULL, BAD_CAST "commands", NULL);
    }

    node = xmlNewChild(node, NULL, BAD_CAST "command", BAD_CAST command);
}


void xmlAddGroupCommand(xmlNodePtr role_node, char *command)
{
    xmlNodePtr node;
    bool flag = false;

    node = role_node;
    node = node->children;

    while(node != NULL) {
        if (node->type == XML_ELEMENT_NODE && !xmlStrcmp(node->name, BAD_CAST "groups")) {
            while(node->next->next != NULL) {
                node = node->next->next;
            }

            if (node->children->next->type == XML_ELEMENT_NODE && !xmlStrcmp(node->children->next->name, BAD_CAST "commands")) {
                node = node->children->next;
                flag = true;
            }
            break;
        }

        node = node->next;
    }

    if (!flag) {
        node = xmlNewChild(node, NULL, BAD_CAST "commands", NULL);
    }

    node = xmlNewChild(node, NULL, BAD_CAST "command", BAD_CAST command);
}
