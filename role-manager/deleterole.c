#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libxml/parser.h>
#include <sys/capability.h>
#include "role_manager.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_help(DELETEROLE);
        return(EXIT_SUCCESS);
    }

    int err;
    xmlDocPtr doc;
    xmlNodePtr role_node = NULL;

    LIBXML_TEST_VERSION
    if ((doc = xml_verifier()) == NULL)
        return(EXIT_FAILURE);

    err = role_verifier(doc, &role_node, argv[1]);
    if (!err) {
        fputs("Role doesn't exist\n", stderr);
        goto ret_err;
    }
    if (err == -1) {
        goto ret_err;
    }

    deleteNode(role_node);

    xmlSaveFormatFileEnc("-", doc, "UTF-8", 1); // Debug
    // xmlSaveFormatFileEnc(XML_FILE, doc, "UTF-8", 1);

ret_err:
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return(err == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}
