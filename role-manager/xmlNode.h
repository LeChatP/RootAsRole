#ifndef XMLNODE_H
#define XMLNODE_H

#define ROLE 0
#define CAP 1
#define USER 2
#define GROUP 3
#define COMMAND 4
#define USERCOMMAND 5
#define GROUPCOMMAND 6

int addNode(xmlNodePtr *elem, char *parent, char *text);
int editNode(xmlNodePtr elem, char *text);
void deleteNode(xmlNodePtr elem);

char *string(int mode, int choice);

xmlChar *newXPression(char *role, int elemDef, char *elem);
int researchNode(xmlDocPtr doc, xmlChar *expression, xmlNodePtr *node,
                 xmlXPathObjectPtr *xobject);

#endif
