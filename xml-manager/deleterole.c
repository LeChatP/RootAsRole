#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libxml/parser.h>
#include <sys/capability.h>
#include "xml_manager.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_help(DELETEROLE);
        return(EXIT_SUCCESS);
    }

    int err, buffsize;
    xmlDocPtr doc;
    xmlNodePtr role_node = NULL;
    xmlChar *xmlbuff;
    FILE *fp = NULL;

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

    xmlUnlinkNode(role_node);
    xmlFreeNode(role_node);

    xmlDocDumpFormatMemory(doc, &xmlbuff, &buffsize, 1);
    fp = fopen(XML_FILE, "w+");
    fputs((char*)xmlbuff, fp);
    fclose(fp);

ret_err:
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return(err == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}
