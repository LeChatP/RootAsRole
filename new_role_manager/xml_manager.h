#ifndef XMLMANAGER_H
#define XMLMANAGER_H

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <sys/types.h>

#define XML_FILE "/etc/security/capabilityRole.xml"

#define E_ROLE 0
#define E_CAP 1
#define E_USER 2
#define E_GROUP 3
#define E_COMMAND 4
#define E_USERCOMMAND 5
#define E_GROUPCOMMAND 6

typedef struct _cmd CMD;
typedef struct _actor ACTOR;
typedef struct _context CONTEXT;

struct _cmd {
	CMD *next;
	char *name;
};
struct _actor {
	int type;
	ACTOR *next;
	char *name;
	CMD *cmds;
};

typedef struct _role {
	u_int64_t capabilities;
	ACTOR *groups;
	ACTOR *users;
    char *name;
} ROLE;

struct _context {
	ROLE *role;
	ACTOR *actor;
	CMD *cmd;
};

/**
 * Sanitize string, escape unwanted chars to their xml equivalent
 * @param str the string to encode, not modified
 * @return new string with escaped chars
 */
xmlChar* encodeXml(const char* str);

void print_role(xmlNodePtr role_node);

xmlNodePtr addContentNode(xmlNodePtr parent,xmlChar *type, xmlChar *content);
xmlNodePtr addNamedNode(xmlNodePtr parent, xmlChar *label, xmlChar *name);
xmlNodePtr addContainerNode(xmlNodePtr parent, xmlChar *label);
int addNode(xmlNodePtr *elem, char *parent, char *text);
int editNode(xmlNodePtr elem, char *text);
void deleteNode(xmlNodePtr elem);

int get_role(ROLE *role_struct, char *role);
int delete_role(char *role);
int save_role_to_file(ROLE *role);

int researchNode(xmlDocPtr doc, xmlChar *expression, xmlNodePtr *node,
                 xmlXPathObjectPtr *xobject);
int role_verifier(xmlDocPtr doc, xmlNodePtr *role_node, char *role);
xmlDocPtr xml_verifier(void);
#endif