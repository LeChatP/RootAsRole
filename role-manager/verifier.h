#ifndef VERIFIER_H
#define VERIFIER_H

#define XML_FILE "/etc/security/capabilityRole.xml"

#define MAX_BLOC 255
#define MAX_ROLE_LEN 64
#define MAX_NAME_LEN 32
#define MAX_COMMAND_LEN 256

int root_verifier(void);
xmlDocPtr xml_verifier(void);
int role_verifier(xmlDocPtr doc, xmlNodePtr *role_node, char *role);
int capability_verifier(char *cap_text, bool capability[43]);
int user_verifier(char *users);
int group_verifier(char *groups);
int command_verifier(char *command);

#endif
