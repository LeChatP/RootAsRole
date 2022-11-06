#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>

#include "help.h"
#include "verifier.h"
#include "xmlNode.h"

static void print_tree(xmlXPathObjectPtr xobject, bool elem[6]);
static int myScanf(char *s, int size);
static int loop_search_node(xmlNodePtr node, int elemDef, char *arg, char *command);

int main(int argc, char *argv[])
{
    if (access_verifier() == -1)
        return EXIT_FAILURE;

    if (argc < 2) {
        print_help(EDITROLE);
        return(EXIT_SUCCESS);
    }

    int err;
    xmlDocPtr doc = NULL;
    xmlNodePtr role_node = NULL;
    xmlNodePtr node = NULL;
    char *rolename;
    bool elem[6] = {false};
    char buffer[256], choice[4];
    int choices[2] = {0};
    int nIndex;
    xmlChar *expression;
    xmlXPathObjectPtr xobject = NULL;
    char *token;
    int j = 0;
    char *arg;
    char *command;


    LIBXML_TEST_VERSION
    if ((doc = xml_verifier()) == NULL)
        return(EXIT_FAILURE);

    err = role_verifier(doc, &role_node, argv[1]);
    if (!err) {
        fputs("Role doesn't exist.\n", stderr);
        goto ret_err;
    }
    if (err == -1)
        goto ret_err;

    rolename = argv[1];

    printf("1. Add\n2. Edit\n3. Delete\n0. Quit\nWhat do you want to do ? -> ");
    do {
        myScanf(choice, 2);
        if (choice[0] >= '0' && choice[0] < '4') {
            break;
        }
        printf("I haven't understand your answer. Please retry : ");
    } while(1);
    choices[0] = choice[0] - '0';

    if (choices[0] == 0)
        goto ret_err;


    switch (choices[0]) {
    case 1:
        puts("Use URL syntax for add an element to xml file");
        puts("Example : /capabilities/cap_net_bind_service");
        fputs("What do you want to add ? -> ", stdout);
        do {
            memset(buffer, 0, MAX_COMMAND_LEN);
            myScanf(buffer, MAX_COMMAND_LEN);
            token = strtok(buffer, "/");
            for (j = 0; token != NULL; j++) {
                // first pass /""
                if (!j) {
                    if (!strcmp(token, string(2, CAP)))
                        choices[1] = CAP;
                    else if (!strcmp(token, string(2, COMMAND))) {
                        choices[1] = COMMAND;
                        break;
                    }
                    else if (!strcmp(token, string(2, USER)))
                        choices[1] = USER;
                    else if (!strcmp(token, string(2, GROUP)))
                        choices[1] = GROUP;
                    else {
                        fputs("Wrong first elem, ", stdout);
                        break;
                    }
                }
                // second pass /elem/""
                else if (j == 1) {
                    if (choices[1] == CAP) {
                        err = capability_verifier(token, NULL);
                        if (!err)
                            arg = token;
                        break;
                    }
                    else if (choices[1] == USER) {
                        if (!strcmp(token, "*")) {
                            choices[1] = USERCOMMAND;
                            arg = token;
                            break;
                        }
                        arg = token;
                    }
                    else if (choices[1] == GROUP) {
                        if (!strcmp(token, "*")) {
                            choices[1] = GROUPCOMMAND;
                            arg = token;
                            break;
                        }
                        arg = token;
                    }
                    else {
                        fputs("Wrong second elem ", stdout);
                        break;
                    }
                }
                // third pass /elem/elem/""
                else {
                    if (!strcmp(token, string(2, COMMAND))) {
                        if (choices[1] == USER)
                            choices[1] = USERCOMMAND;
                        else if (choices[1] == GROUP)
                            choices[1] = GROUPCOMMAND;
                        else {
                            fputs("Wrong second elem for third elem, ", stdout);
                            arg = NULL;
                        }
                        break;
                    }
                    fputs("Wrong third elem, ", stdout);
                    arg = NULL;
                    break;
                }
                token = strtok(NULL, "/");
            }
            if (arg || choices[1] == COMMAND)
                break;
            fputs("Retry : ", stdout);
        } while (1);

        if (choices[1] == USER || choices[1] == USERCOMMAND) {
            if (strcmp(arg, "*") != 0) {
                err = user_verifier(arg);
                if (err == -1)
                    goto ret_err;
            }
        }
        else if (choices[1] == GROUP || choices[1] == GROUPCOMMAND) {
            if (strcmp(arg, "*") != 0) {
                err = group_verifier(arg);
                if (err == -1)
                    goto ret_err;
            }
        }

        arg = strdup(arg);

        // command choice
        if (choices[1] > 3) {
            fputs("Type your commands : ", stdout);
            do {
                memset(buffer, 0, MAX_COMMAND_LEN);
                myScanf(buffer, MAX_COMMAND_LEN);
                err = command_verifier(buffer);
                if (!err)
                    break;
                fputs("Retry : ", stdout);
            } while (1);
            command = buffer;
        }

        err = loop_search_node(role_node, choices[1], arg, command);
        free(arg);
        break;

    case 2:
        expression = newXPression(rolename, 0, "//*");
        err = researchNode(doc, expression, NULL, &xobject);
        if (err == -1) {
            goto ret_err;
        }
        printf("1 %s :\n", rolename);
        print_tree(xobject, elem);

        fputs("Use the displayed tree and selects ", stdout);
        fputs("the number corresponding to the node -> ", stdout);
        do {
            memset(choice, 0, 4);
            myScanf(choice, 4);
            nIndex = atoi(choice) - 2;
            if (nIndex > xobject->nodesetval->nodeNr || nIndex < -1) {
                fputs("Index invalid, retry -> ", stdout);
            }
            else {
                if (nIndex < 0) {
                    choices[1] = ROLE;
                    break;
                }
                node = xobject->nodesetval->nodeTab[nIndex];
                if (!xmlStrcmp(node->name, BAD_CAST string(1, CAP))) {
                    choices[1] = CAP;
                    break;
                }
                if (!xmlStrcmp(node->name, BAD_CAST string(1, USER))) {
                    choices[1] = USER;
                    break;
                }
                if (!xmlStrcmp(node->name, BAD_CAST string(1, GROUP))) {
                    choices[1] = GROUP;
                    break;
                }
                if (!xmlStrcmp(node->name, BAD_CAST string(1, COMMAND))) {
                    choices[1] = COMMAND;
                    break;
                }
                fputs("Requested node invalid, retry -> ", stdout);
            }
        } while(1);

        printf("By what element would you replace ? -> ");
        do {
            memset(buffer, 0, MAX_COMMAND_LEN);
            myScanf(buffer, MAX_COMMAND_LEN);
            if (choices[1] == ROLE) {
                if (!role_verifier(doc, NULL, buffer))
                    break;
            }
            else if (choices[1] == CAP) {
                if (!capability_verifier(buffer, NULL))
                    break;
            }
            else if (choices[1] == USER) {
                if (user_verifier(buffer))
                    break;
            }
            else if (choices[1] == GROUP) {
                if (group_verifier(buffer))
                    break;
            }
            else {
                if (!command_verifier(buffer))
                    break;
            }
            printf("Please retry : ");
        } while (1);

        editNode(node, buffer);

        break;

    case 3:
        expression = newXPression(rolename, 0, "//*");
        err = researchNode(doc, expression, NULL, &xobject);
        if (err == -1) {
            goto ret_err;
        }
        printf("1 %s :\n", rolename);
        print_tree(xobject, elem);

        fputs("Use the displayed tree and selects ", stdout);
        fputs("the number corresponding to the node -> ", stdout);
        do {
            myScanf(choice, 4);
            nIndex = atoi(choice) - 2;
            if (nIndex > xobject->nodesetval->nodeNr || nIndex < 0) {
                fputs("Index invalid, retry -> ", stdout);
            }
            else {
                node = xobject->nodesetval->nodeTab[nIndex];
                if (!xmlStrcmp(node->name, BAD_CAST string(1, CAP)) ||
                    !xmlStrcmp(node->name, BAD_CAST string(1, USER)) ||
                    !xmlStrcmp(node->name, BAD_CAST string(1, GROUP)) ||
                    !xmlStrcmp(node->name, BAD_CAST string(1, COMMAND)) ||
                    !xmlStrcmp(node->name, BAD_CAST string(2, USER)) ||
                    !xmlStrcmp(node->name, BAD_CAST string(2, GROUP)) ||
                    !xmlStrcmp(node->name, BAD_CAST string(2, COMMAND))) {

                    break;
                }
            fputs("Requested node invalid, retry -> ", stdout);
            }
        } while(1);

        deleteNode(node);
    }


    
    toggle_lock_config(1);
    xmlSaveFormatFileEnc(XML_FILE, doc, "UTF-8", 1);
    // xmlSaveFormatFileEnc("-", doc, "UTF-8", 1); // Debug
    toggle_lock_config(0);

ret_err:
    if (xobject) xmlXPathFreeObject(xobject);
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return(err == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void print_tree(xmlXPathObjectPtr xobject, bool elem[6])
{
    int oldCommand = 0;
    xmlNodePtr node;
    xmlChar *temp = NULL;

    for (int i = 0; i < xobject->nodesetval->nodeNr; i++) {
        node = xobject->nodesetval->nodeTab[i];
        if (!xmlStrcmp(node->name, BAD_CAST "capabilities")) {
            printf("%d\tCapabilities :\n", i+2);
            elem[0] = true;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "users")) {
            printf("%d\tUsers :\n", i+2);
            elem[1] = true;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "groups")) {
            printf("%d\tGroups :\n", i+2);
            elem[2] = true;
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "commands")) {
            printf("%d", i+2);
            if (!xmlStrcmp(node->parent->name, BAD_CAST "user")) {
                fputs("\t\t\t", stdout);
                elem[4] = true;
                oldCommand = 2; // troisieme indentation
            }
            else if (!xmlStrcmp(node->parent->name, BAD_CAST "users")) {
                fputs("\t\t", stdout);
                elem[4] = true;
                oldCommand = 1; // deuxieme indentation
            }
            else if (!xmlStrcmp(node->parent->name, BAD_CAST "group")) {
                fputs("\t\t\t", stdout);
                elem[5] = true;
                oldCommand = 2; // troisieme indentation
            }
            else if (!xmlStrcmp(node->parent->name, BAD_CAST "groups")) {
                fputs("\t\t", stdout);
                elem[5] = true;
                oldCommand = 1; // deuxieme indentation
            }
            else {
                fputs("\t", stdout);
                elem[3] = true;
                oldCommand = 0; // premiere indentation
            }
            puts("Commands :");
        }

        else if (!xmlStrcmp(node->name, BAD_CAST "capability")) {
            temp = xmlNodeGetContent(node);
            printf("%d\t\t%s\n", i+2, (char*)temp);
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "user")) {
            temp = xmlGetProp(node, BAD_CAST "name");
            printf("%d\t\t%s\n", i+2, (char*)temp);
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "group")) {
            temp = xmlGetProp(node, BAD_CAST "name");
            printf("%d\t\t%s\n", i+2, (char*)temp);
        }
        else if (!xmlStrcmp(node->name, BAD_CAST "command")) {
            temp = xmlNodeGetContent(node);
            printf("%d", i+2);
            if (!oldCommand)
                fputs("\t\t", stdout);
            else if (oldCommand == 1)
                fputs("\t\t\t", stdout);
            else
                fputs("\t\t\t\t", stdout);
            printf("%s\n", (char*)temp);
        }

        if (temp) {
            xmlFree(temp);
            temp = NULL;
        }
    }
    puts("");
}


static void viderBuffer(void)
{
    int c = 0;

    while (c != '\n' && c != EOF) {
        c = getchar();
    }
}

static int myScanf(char *s, int size)
{
    char *p = NULL;

    if (fgets(s, size, stdin) != NULL) {
        if ( (p = strchr(s, '\n')) != NULL ) {
            *p = '\0';
        }
        else {
            viderBuffer();
        }
        return(EXIT_SUCCESS);
    }

    viderBuffer();
    return(EXIT_FAILURE);
}

static int loop_search_node(xmlNodePtr node, int elemDef, char *arg, char *command)
{
    xmlNodePtr tempNode;
    xmlChar *tempChar = NULL;

    tempNode = node->children;

    while (tempNode) {
        if (!xmlStrcmp(tempNode->name, BAD_CAST string(2, elemDef))) {
            break;
        }
        tempNode = tempNode->next;
    }

    if (!tempNode) {
        if ((elemDef == USERCOMMAND || elemDef == GROUPCOMMAND) && !strcmp(arg, "*"))
            return EXIT_FAILURE;
        addNode(&node, string(2, elemDef), NULL);
        addNode(&node, NULL, elemDef == COMMAND ? command : arg);
        if (elemDef == USERCOMMAND || elemDef == GROUPCOMMAND) {
            tempNode = node;
            goto ret_command;
        }
        return EXIT_SUCCESS;
    }

    node = tempNode;
    tempNode = node->children;

    while (tempNode) {
        if ((elemDef == USERCOMMAND || elemDef == GROUPCOMMAND) && !strcmp(arg, "*")) {
            if (!xmlStrcmp(tempNode->name, BAD_CAST "commands"))
                break;
        }
        else if (elemDef == CAP) {
            tempChar = xmlNodeGetContent(tempNode);

            if (!xmlStrcmp(tempChar, BAD_CAST arg)) {
                free(tempChar);
                return EXIT_FAILURE;
            }
            free(tempChar);
        }
        else if (elemDef == COMMAND) {
            tempChar = xmlNodeGetContent(tempNode);
            if (!xmlStrcmp(tempChar, BAD_CAST command)) {
                free(tempChar);
                return EXIT_FAILURE;
            }
            free(tempChar);
        }
        else {
            tempChar = xmlGetProp(tempNode, BAD_CAST "name");
            if (!xmlStrcmp(tempChar, BAD_CAST arg)) {
                free(tempChar);
                if (elemDef == USERCOMMAND || elemDef == GROUPCOMMAND)
                    goto ret_command;
                return EXIT_FAILURE;
            }
            free(tempChar);
        }
        tempNode = tempNode->next;
    }

    if (!tempNode) {
        if ((elemDef == USERCOMMAND || elemDef == GROUPCOMMAND) && !strcmp(arg, "*")) {
            addNode(&node, NULL, command);
            return EXIT_SUCCESS;
        }
        else {
            addNode(&node, NULL, elemDef == COMMAND ? command : arg);
            if (elemDef != USERCOMMAND || elemDef != GROUPCOMMAND)
                return EXIT_SUCCESS;
            node = tempNode;
        }
    }


ret_command:
    node = tempNode;
    tempNode = node->children;

    if (!tempNode) {
        addNode(&node, "commands", NULL);
        addNode(&node, NULL, command);
        return EXIT_SUCCESS;
    }

    while (tempNode) {
        tempChar = xmlNodeGetContent(tempNode);
        if (!xmlStrcmp(tempChar, BAD_CAST command)) {
            free(tempChar);
            return EXIT_FAILURE;
        }
        free(tempChar);
        tempNode = tempNode->next;
    }
    addNode(&node->children, NULL, command);

    return EXIT_SUCCESS;
}
