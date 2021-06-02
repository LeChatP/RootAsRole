#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/capability.h>
#include "role_manager.h"

static int args_process (int *argc, char **argv, args_struct *args);

int main(int argc, char *argv[])
{
    /* Verification */
    if (argc < 2) {
        print_help(ADDROLE);
        return(EXIT_SUCCESS);
    }

    int err;
    xmlDocPtr doc = NULL;
    xmlNodePtr role_node = NULL, node = NULL;
    args_struct args;
    char *token;

    memset(&args, 0, sizeof(args));

    LIBXML_TEST_VERSION
    if ((doc = xml_verifier()) == NULL)
        return(EXIT_FAILURE);

    err = role_verifier(doc, &role_node, argv[1]);
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
    /* ****** */

    /* Adding */
    addNode(&role_node, "role", args.rolename);
    node = role_node;

    addNode(&node, "capabilities", NULL);
    if (args.capability[42] == true) {
        addNode(&node, NULL, "*");
    }
    else {
        for(int i = 0; i < 42; i++) {
            if (args.capability[i] == true) {
                addNode(&node, NULL, cap_to_name((cap_value_t)i));
            }
        }
    }

    if (args.uc != 0) {
        node = role_node;
        addNode(&node, "users", NULL);

        token = strtok(argv[args.ui], ",");
        do {
            addNode(&node, NULL, token);
        } while ( (token = strtok(NULL, ",")) != NULL );
    }

    if (args.cc[0] != 0) {
        addNode(&node, "commands", NULL);

        for (int i = 0; i < args.cc[0]; i++) {
            addNode(&node, NULL, argv[args.ci[0][i]]);
        }
    }

    if (args.gc != 0) {
        node = role_node;
        addNode(&node, "groups", NULL);

        token = strtok(argv[args.gi], ",");
        do {
            addNode(&node, NULL, token);
        } while ( (token = strtok(NULL, ",")) != NULL );
    }

    if (args.cc[1] != 0) {
        addNode(&node, "commands", NULL);

        for (int i = 0; i < args.cc[1]; i++) {
            addNode(&node, NULL, argv[args.ci[1][i]]);
        }
    }
    /* ******* */

    xmlSaveFormatFileEnc("-", doc, "UTF-8", 1); // Debug
    // xmlSaveFormatFileEnc(XML_FILE, doc, "UTF-8", 1);

ret_err:
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return(err == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}

static int args_process (int *argc, char **argv, args_struct *args)
{
    int c, oldC;
    char *save = NULL;

    optind = 2;

    while (1) {
        static struct option long_options[] = {
            { "capability", required_argument, 0, 'C' },
    		{ "user", 		required_argument, 0, 'u' },
    		{ "group", 		required_argument, 0, 'g' },
    		{ "command", 	required_argument, 0, 'c' },
    		{ 0, 			0, 				   0,  0  }
    	};

        c = getopt_long(*argc, argv, "C:u:uc:g:gc", long_options, NULL);

        if (c == -1)
            break;

		switch (c) {
		case 'C':
            if (capability_verifier(optarg, args) == -1)
                return -1;

            oldC = c;
            break;
        case 'u':
            if (args->uc != 0) {
                fputs("User option already used\n", stderr);
                return -1;
            }

            save = strdup(optarg);
            if (save == NULL) {
                perror("strdup()");
                return -1;
            }

            if (user_verifier(save, args) == -1) {
                return -1;
                free(save);
            }

            args->ui = optind-1;
            oldC = c;
            free(save);

            break;
        case 'g':
            if (args->gc != 0) {
                fputs("Group option already used\n", stderr);
                return -1;
            }

            save = strdup(optarg);
            if (save == NULL) {
                perror("strdup()");
                return -1;
            }

            if (group_verifier(save, args) == -1) {
                return -1;
                free(save);
            }

            args->gi = optind-1;
            oldC = c;
            free(save);

            break;
        case 'c':
            if (args->cc[0] == 10 || args->cc[1] == 10) {
                fputs("10 commands max can be added\n", stderr);
                return -1;
            }
            if (oldC != 'u' && oldC != 'g') {
                fputs("Commands can be only used with user or group\n", stderr);
                return -1;
            }

            if (command_verifier(optarg) == -1)
                return -1;

            if (oldC == 'u') {
                args->ci[0][args->cc[0]] = optind-1;
                args->cc[0]++;
            }
            else {
                args->ci[1][args->cc[1]] = optind-1;
                args->cc[1]++;
            }
            break;
        case '?':
        case ':':
            return -1;
		}
    }

    return 0;
}
