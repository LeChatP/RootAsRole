#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/capability.h>
#include "role_manager.h"

static int all_researcher(xmlNodePtr node, args_struct *args);
static int myScanf(char *s, int size);
static char *string(int a, int choice);
static int editNode(xmlNodePtr elem, char *text);

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_help(ADDROLE);
        return(EXIT_SUCCESS);
    }

    int err;
    xmlDocPtr doc = NULL;
    xmlNodePtr role_node = NULL;
    xmlNodePtr node = NULL;
    args_struct args;
    char buffer[256], choice[2];
    int choices[2];

    memset(&args, 0, sizeof(args));

    LIBXML_TEST_VERSION
    if ((doc = xml_verifier()) == NULL)
        return(EXIT_FAILURE);

    err = role_verifier(doc, &role_node, argv[1]);
    if (!err) {
        fputs("Role doesn't exist. Use editrole\n", stderr);
        goto ret_err;
    }
    if (err == -1) {
        goto ret_err;
    }
    args.rolename = argv[1];

    printf("%d\n", err);

    all_researcher(role_node->children, &args);
    printf("\n1. Add\n2. Edit\n3. Delete\nWhat do you want to do ? -> ");
    do {
        myScanf(choice, 2);
        if (choice[0] > '0' && choice[0] < '4') {
            break;
        }
        printf("I haven't understand your answer. Please retry : ");
    } while(1);

    choices[0] = choice[0] - '0';

    printf("\n1. Capabilites\n2. Users\n3. Groups\n4. UserCommands\n5. GroupCommands\n");
    printf("What do you want to %s ? -> ", string(1, choices[0]));
    do {
        myScanf(choice, 2);
        if (choice[0] > '0' && choice[0] < '6') {
            break;
        }
        printf("I haven't understand your answer. Please retry : ");
    } while(1);

    choices[1] = choice[0] - '0';

    printf("\nWhat %s do you want to %s ? -> ", string(2, choices[1]), string(1, choices[0]));

    do {
        myScanf(buffer, MAX_COMMAND_LEN);
        if (choices[1]) {
            if (!capability_verifier(buffer, &args))
                break;
        }
        else if (choices[1] == 2) {
            if (!user_verifier(buffer, &args))
                break;
        }
        else if (choices[1] == 3) {
            if (group_verifier(buffer, &args) == -1)
                break;
        }
        else {
            if (!command_verifier(buffer))
                break;
        }
        printf("Please retry : ");
    } while (1);

    node = researchNode(role_node->children, choices[1]-1, buffer);
    switch (choices[0]) {
    case 1: // Make user command and group command
        if (node != NULL) {
            fputs("Element already exists in xml file\n", stderr);
            break;
        }

        node = researchNode(role_node->children, choices[1]-1, NULL);
        if (node == NULL) {
            node = role_node;
            addNode(&node, string(2, choices[1]), buffer);

            break;
        }
        addNode(&node, NULL, buffer);

        break;
    case 2:
        if (node == NULL) {
            fputs("Element doesn't exist in xml file\n", stderr);
            break;
        }

        printf("By what element would you replace \"%s\" ? -> ", buffer);

        do {
            myScanf(buffer, MAX_COMMAND_LEN);
            if (choices[1]) {
                if (!capability_verifier(buffer, &args))
                    break;
            }
            else if (choices[1] == 2) {
                if (!user_verifier(buffer, &args))
                    break;
            }
            else if (choices[1] == 3) {
                if (group_verifier(buffer, &args) == -1)
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
        if (node == NULL) {
            fputs("Element doesn't exist in xml file\n", stderr);
            break;
        }
        deleteNode(node);
    }

    xmlSaveFormatFileEnc("-", doc, "UTF-8", 1); // Debug
    // xmlSaveFormatFileEnc(XML_FILE, doc, "UTF-8", 1);

ret_err:
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return(err == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}

static int all_researcher(xmlNodePtr node, args_struct *args)
{
    xmlNode *cur_node = NULL;

    for (cur_node = node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (!xmlStrcmp(cur_node->name, BAD_CAST "capabilities"))
                puts("Capabilities :");
            else if (!xmlStrcmp(cur_node->name, BAD_CAST "users"))
                puts("Users :");
            else if (!xmlStrcmp(cur_node->name, BAD_CAST "groups"))
                puts("Groups");
            else if (!xmlStrcmp(cur_node->name, BAD_CAST "commands"))
                puts("\t\tCommands :");

            else if (!xmlStrcmp(cur_node->name, BAD_CAST "capability")) {
                if (capability_verifier((char*)xmlNodeGetContent(cur_node), args) == -1)
                    return -1;
                printf("\t%s\n", (char*)xmlNodeGetContent(cur_node));
            }

            else if (!xmlStrcmp(cur_node->name, BAD_CAST "user")) {
                if (user_verifier((char*)xmlGetProp(cur_node, BAD_CAST "name"), args) == -1)
                    return -1;
                printf("\t%s\n", (char*)xmlGetProp(cur_node, BAD_CAST "name"));
            }

            else if (!xmlStrcmp(cur_node->name, BAD_CAST "group")) {
                if (group_verifier((char*)xmlGetProp(cur_node, BAD_CAST "name"), args) == -1)
                    return -1;
                printf("\t%s\n", (char*)xmlGetProp(cur_node, BAD_CAST "name"));
            }

            else if (!xmlStrcmp(cur_node->name, BAD_CAST "command")) {
                if (command_verifier((char*)xmlNodeGetContent(cur_node)) == -1)
                    return -1;
                printf("\t\t\t%s\n", (char*)xmlNodeGetContent(cur_node));
            }
        }

        all_researcher(cur_node->children, args);
    }
    return 0;
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

static char *string(int a, int choice)
{
    if (a == 1) {
        switch (choice) {
        case 1:
            return "add";
            break;
        case 2:
            return "edit";
            break;
        case 3:
            return "delete";
        }
    }
    else {
        switch (choice) {
        case 1:
            return "capabilities";
            break;
        case 2:
            return "users";
            break;
        case 3:
            return "groups";
            break;
        case 4:
        case 5:
            return "commands";
        }
    }
    return NULL;
}

static int editNode(xmlNodePtr elem, char *text)
{
    if (!xmlStrcmp(elem->name, BAD_CAST "capability")) {
        xmlNodeSetContent(elem, BAD_CAST text);
        return 1;
    }
    if (!xmlStrcmp(elem->name, BAD_CAST "user")) {
        xmlSetProp(elem, BAD_CAST "name", BAD_CAST text);
        return 1;
    }
    if (!xmlStrcmp(elem->name, BAD_CAST "group")) {
        xmlSetProp(elem, BAD_CAST "name", BAD_CAST text);
        return 1;
    }
    if (!xmlStrcmp(elem->name, BAD_CAST "command")) {
        xmlNodeSetContent(elem, BAD_CAST text);
        return 1;
    }

    fputs("Bad cursor\n", stderr);
    return -1;
}
