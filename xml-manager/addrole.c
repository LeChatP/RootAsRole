#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/capability.h>
#include "xml_manager.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_help(ADDROLE);
        return(EXIT_SUCCESS);
    }

    int err;
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    args_struct args;
    char *token;

    memset(&args, 0, sizeof(args));

    LIBXML_TEST_VERSION
    if ((doc = xml_verifier()) == NULL)
        return(EXIT_FAILURE);

    err = role_verifier(doc, &node, argv[1]);
    if (err) {
        fputs("Role already exists. Use editrole\n", stderr);
        goto ret_err;
    }
    if (err == -1) {
        goto ret_err;
    }
    args.rolename = argv[1];

    err = args_process (&argc, argv, &args);
    if (err == -1)
        goto ret_err;

    printf("%s\n", node->name);
    node = xmlAddRole(node, args.rolename);

    if (args.capability[42] == true) {
        xmlAddCapability(node, "*");
    }
    else {
        for(int i = 0; i < 42; i++) {
            if (args.capability[i] == true) {
                xmlAddCapability (node, cap_to_name((cap_value_t)i));
            }
        }
    }

    if (args.uc != 0) {
        token = strtok(argv[args.ui], ",");
        do {
            xmlAddUser(node, token);
        } while ( (token = strtok(NULL, ",")) != NULL );
    }

    if (args.cc[0] != 0) {
        for (int i = 0; i < args.cc[0]; i++) {
            xmlAddUserCommand (node, argv[args.ci[0][i]]);
        }
    }

    if (args.gc != 0) {
        token = strtok(argv[args.gi], ",");
        do {
            xmlAddGroup(node, token);
        } while ( (token = strtok(NULL, ",")) != NULL );
    }

    if (args.cc[1] != 0) {
        for (int i = 0; i < args.cc[1]; i++) {
            xmlAddGroupCommand(node, argv[args.ci[1][i]]);
        }
    }

    xmlSaveFormatFileEnc(XML_FILE, doc, "UTF-8", 1);

ret_err:
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return(err == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}
