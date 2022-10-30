#ifndef XMLNODE_H
#define XMLNODE_H

#define ROLE 0
#define CAP 1
#define USER 2
#define GROUP 3
#define COMMAND 4
#define USERCOMMAND 5
#define GROUPCOMMAND 6

/**
 * Sanitize string, escape unwanted chars to their xml equivalent
 * @param str the string to encode, not modified
 * @param quot 
 * 		set to 1 will replace " to &quot; useful when your string is surrounded by " 
 * 		set to 0 will replace ' to &apos; useful when your string is surrounded by '
 * @return new string with escaped chars
 */
xmlChar* encodeXml(const char* str);

xmlNodePtr addContentNode(xmlNodePtr parent,xmlChar *type, xmlChar *content);
xmlNodePtr addNamedNode(xmlNodePtr parent, xmlChar *label, xmlChar *name);
xmlNodePtr addContainerNode(xmlNodePtr parent, xmlChar *label);
int addNode(xmlNodePtr *elem, char *parent, char *text);
int editNode(xmlNodePtr elem, char *text);
void deleteNode(xmlNodePtr elem);

char *string(int mode, int choice);

xmlChar *newXPression(char *role, int elemDef, char *elem);
int researchNode(xmlDocPtr doc, xmlChar *expression, xmlNodePtr *node,
                 xmlXPathObjectPtr *xobject);

#endif
