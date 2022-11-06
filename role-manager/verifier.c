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
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <unistd.h>

#include "xmlNode.h"
#include "verifier.h"

extern int errno;

/******************************************************************************
 *                      PRIVATE FUNCTIONS DECLARATION                         *
 ******************************************************************************/

/* 
Add or remove the capabilities in/from the effective set of the process.
Add the caps if enable is different than 0, remove them if enable is 0.
Return 0 on success, -1 on failure.
*/
static int caps_effective(int enable, int nb_caps, cap_value_t *cap_values);
/* 
Enable/Disable capability linux_immuable effective 
*/
int cap_linux_immuable_effective(int enable);

/* @return : -1 to failure | 0 to success */
int access_verifier(void)
{
    cap_t cap = cap_get_proc(); 
    cap_flag_value_t linux_immutable = 0; 
    cap_get_flag(cap, CAP_LINUX_IMMUTABLE, CAP_EFFECTIVE, &linux_immutable);
    cap_free(cap);
    if (linux_immutable && access(XML_FILE,W_OK))
        return 0;
    else {
        fputs("You need CAP_LINUX_IMMUTABLE capability and access to file to perform action on RAR policy\n", stderr);
        return -1;
    }
    
}

int toggle_lock_config(int unlock)
{
    int status = -1;
    FILE *fp = fopen(XML_FILE, "r");
    if(cap_linux_immuable_effective(1)){
        perror("Unable to reduce capabilities");
        goto ERR;
    }
    int val;
    if (ioctl(fileno(fp), FS_IOC_GETFLAGS, &val) < 0) {
        perror("ioctl(2) error");
        goto ERR;
    }
    if(unlock) val ^= FS_IMMUTABLE_FL;
    else val |= FS_IMMUTABLE_FL;
    if (ioctl(fileno(fp), FS_IOC_SETFLAGS, &val) < 0){
        perror("ioctl(2) error");
        goto ERR;
    }
    if(cap_linux_immuable_effective(0)){
        perror("Unable to reduce capabilities");
        goto ERR;
    }
    status = 0;
    ERR:
    return status;
}

int cap_linux_immuable_effective(int enable)
{
	cap_value_t cap_value;

	//Compute the capvalue setfcap
	if (cap_from_name("CAP_LINUX_IMMUTABLE", &cap_value))
		return -1;
	return caps_effective(enable, 1, &cap_value);
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
int capability_verifier(char *cap_text, uint64_t *capabilities)
{
    char *token;
    cap_value_t capVal;
    *capabilities = (uint64_t)0;

    token = strtok(cap_text, ",");

    if (token == NULL) {
        fputs("Capability is empty\n", stderr);
        return -1;
    }

    do {
        if (!strcmp(token, "*")) {
            *capabilities = (uint64_t) -1 >> (64-cap_max_bits());
            return 0;
        }
        if (cap_from_name(token, &capVal) == -1) {
            fprintf(stderr, "\"%s\" : Invalid Capability\n", token);
            return -1;
        }
        *capabilities |= 1<<capVal;
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
    if (strchr(command, '\'') != NULL && strchr(command, '"') != NULL) {
        fputs("You cannot set quote and apostrophe in a parameter due to XML restrictions\n", stderr);
        return -1;
    }

    return 0;
}


/******************************************************************************
 *                      PRIVATE FUNCTIONS DEFINITION                          *
 ******************************************************************************/

/* 
Add or remove the capabilities in/from the effective set of the process.
Add the caps if enable is different than 0, remove them if enable is 0.
Return 0 on success, -1 on failure.
*/
static int caps_effective(int enable, int nb_caps, cap_value_t *cap_values)
{
	cap_t caps; //Capabilities state
	cap_flag_value_t cap_flag_value; //value of the caps' flag to use
	int return_code = -1;

	//Define the value of the flag to use to enable or disable the caps
	cap_flag_value = enable ? CAP_SET : CAP_CLEAR;
	//Get process' capabilities state
	if ((caps = cap_get_proc()) == NULL)
		return return_code;
	//Set or clear the capabilities in the effective set
	if (cap_set_flag(caps, CAP_EFFECTIVE, nb_caps, cap_values,
			 cap_flag_value))
		goto free_rscs;
	//Update the process' capabilities
	if (cap_set_proc(caps))
		goto free_rscs;
	//Treatment done
	return_code = 0;
free_rscs:
	cap_free(caps);
	return return_code;
}