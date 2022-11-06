#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <stdbool.h>
#include <stdio.h>

#include "help.h"
#include "verifier.h"
#include "xmlNode.h"

int main(int argc, char *argv[])
{
    if (access_verifier() == -1)
        return EXIT_FAILURE;

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
    else if (err == -1)
        goto ret_err;

    deleteNode(role_node);

    toggle_lock_config(1);
    xmlSaveFormatFileEnc(XML_FILE, doc, "UTF-8", 1);
    toggle_lock_config(0);
    // xmlSaveFormatFileEnc("-", doc, "UTF-8", 1); // Debug

ret_err:
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return(err == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}
