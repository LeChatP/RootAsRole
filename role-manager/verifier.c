#include <errno.h>
#include <grp.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <unistd.h>

#include "xmlNode.h"
#include "verifier.h"

extern int errno;

/* @return : -1 to failure | 0 to success */
int root_verifier(void)
{
    if (!getuid())
        return 0;
    else {
        fputs("For run this command you must be root user !\n", stderr);
        return -1;
    }
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

    return(doc);

ret_err:
    xmlFreeParserCtxt(ctxt);
    return NULL;
}

/* @role_node is optionnal. NULL for not use
 * @return : -1 to error | 0 if role doesn't exist | 1 if role exists
 */
int role_verifier(xmlDocPtr doc, xmlNodePtr *role_node, char *role)
{
    xmlChar *expression = NULL;
    int ret;

    if (!strcmp(role, "")) {
        fputs("Role is empty\n", stderr);
        return -1;
    }
    if (strlen(role) >= MAX_ROLE_LEN) {
        fprintf(stderr, "Role is too long : %d characters max\n", MAX_ROLE_LEN);
        return -1;
    }
    if (strchr(role, '\'') != NULL && strchr(role, '"') != NULL) {
        fputs("You cannot set quote and apostrophe in a parameter due to XML restrictions\n", stderr);
        return -1;
    }

    expression = newXPression(role, 0, NULL);
    if (!expression)
        return -1;

    ret = researchNode(doc, expression, role_node, NULL);

    free(expression);
    return ret;
}


/* @capability[43] is optionnal. NULL for not use
 * @return : -1 to error | 0 success
 */
int capability_verifier(char *cap_text, bool capability[43])
{
    char *token;
    cap_value_t capVal;

    token = strtok(cap_text, ",");

    if (token == NULL) {
        fputs("Capability is empty\n", stderr);
        return -1;
    }

    do {
        if (!strcmp(token, "*")) {
            if (capability)
                capability[42] = true;
            return 0;
        }
        if (cap_from_name(token, &capVal) == -1) {
            fprintf(stderr, "\"%s\" : Invalid Capability\n", token);
            return -1;
        }

        if (capability)
            capability[capVal] = true;
    } while ( (token = strtok(NULL, ",")) != NULL);

    return 0;
}


/* @return : -1 to error | User number to success */
int user_verifier(char *users)
{
    char *token;
    int i;

    token = strtok(users, ",");

    for (i = 0; token != NULL; i++) {
        if (i == MAX_BLOC) {
            fputs("Limits for user blocs reached\n", stderr);
            return -1;
        }

        if (strchr(token, '\'') != NULL && strchr(token, '"') != NULL) {
            fputs("You cannot set quote and apostrophe in a parameter due to XML restrictions\n", stderr);
            return -1;
        }

        if (strlen(token) >= MAX_NAME_LEN) {
            fprintf(stderr, "Username is too long -> %d characters max\n", MAX_NAME_LEN);
            return -1;
        }

        errno = 0;
        if ( (getpwnam(token)) == NULL) {
            if (errno != 0)
                perror("getpwnam()");
            else
                fprintf(stderr, "\"%s\" : Username doesn't exist\n", token);
            return -1;
        }
        token = strtok(NULL, ",");
    }

    if (!i) {
        fputs("User is empty\n", stderr);
        return -1;
    }

    return i;
}


/* @return : -1 to error | Group number to success */
int group_verifier(char *groups)
{
    char *token;
    int i;

    token = strtok(groups, ",");

    for (i = 0; token != NULL; i++) {
        if (i == MAX_BLOC) {
            fputs("Limits for user blocs reached\n", stderr);
            return -1;
        }

        if (strchr(token, '\'') != NULL && strchr(token, '"') != NULL) {
            fputs("You cannot set quote and apostrophe in a parameter due to XML restrictions\n", stderr);
            return -1;
        }

        if (strlen(token) >= MAX_NAME_LEN) {
            fprintf(stderr, "Group is too long -> %d characters max\n", MAX_NAME_LEN);
            return -1;
        }

        errno = 0;
        if ( (getgrnam(token)) == NULL) {
            if (errno != 0)
                perror("getgrnam()");
            else
                fprintf(stderr, "\"%s\" : Group doesn't exist\n", token);
            return -1;
        }
        token = strtok(NULL, ",");
    }

    if (!i) {
        fputs("Group is empty\n", stderr);
        return -1;
    }

    return i;
}


/* @return : -1 to error | 0 success */
int command_verifier(char *command)
{
    if (command == NULL || !strcmp(command, "")) {
        fputs("Command is empty\n", stderr);
        return -1;
    }
    if (strlen(command) >= MAX_COMMAND_LEN) {
        fprintf(stderr, "Comand is too long -> %d characters max\n", MAX_COMMAND_LEN);
        return -1;
    }
    if (strchr(command, '\'') != NULL && strchr(command, '"') != NULL) {
        fputs("You cannot set quote and apostrophe in a parameter due to XML restrictions\n", stderr);
        return -1;
    }

    return 0;
}
