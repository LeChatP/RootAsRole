#include <getopt.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>

#include "help.h"
#include "list_manager.h"
#include "verifier.h"
#include "xmlNode.h"

/* @return : -1 to error | 0 to success */
static int args_process (int argc, char **argv, args_struct *args);

void addActor(xmlNodePtr role_node, account_list al, xmlChar *containerStr, xmlChar *actorType, char **argv){
    xmlNodePtr container = addContainerNode(role_node,containerStr);
    //addNode(&node, "users", NULL);
    while(al->account) {
        xmlChar *accountSanitized = encodeXml(al->account);
        container = addNamedNode(container,actorType,accountSanitized);
        xmlFree(accountSanitized);
        al = al->next;
        //addNode(&node, NULL, ul->account);
        if (al->cs) {

            container = addContainerNode(container, (xmlChar*)"commands");
            for (int i = 0; i < al->cs->cc; i++) {
                /* i*2 because : "command(+0) -c(+1) command(+2)" */
                xmlChar *commandSanitized = encodeXml(argv[al->cs->cbi+(i*2)]);
                addContentNode(container,(xmlChar*)"command",commandSanitized);
                xmlFree(commandSanitized);
                //addNode(&node, NULL, argv[ul->cs->cbi+(i*2)]);
            }
            if (al->next)
                container = container->parent->parent;
        }
    }
}

int main(int argc, char *argv[])
{
    if (access_verifier() == -1)
        return EXIT_FAILURE;

    if (argc < 3) {
        print_help(ADDROLE);
        return(EXIT_SUCCESS);
    }

    int err;
    xmlDocPtr doc = NULL;
    xmlNodePtr role_node = NULL, container = NULL;
    args_struct args;
    char *temp;

    account_list ul = NULL;
    account_list gl = NULL;
    command_list cl = NULL;

    memset(&args, 0, sizeof(args_struct));

    LIBXML_TEST_VERSION
    if (!(doc = xml_verifier()))
        return(EXIT_FAILURE);

    err = role_verifier(doc, &role_node, argv[1]);
    if (err) {
        fputs("Role already exists. Use editrole\n", stderr);
        goto ret_err;
    }
    if (err == -1)
        goto ret_err;

    args.rolename = argv[1];
    role_node = xmlDocGetRootElement(doc);
    role_node = role_node->children;

    err = capability_verifier(argv[2], &args.capabilities);
    if (err == -1)
        goto ret_err;

    err = args_process (argc, argv, &args);
    ul = args.ubloc;
    gl = args.gbloc;
    cl = args.cbloc;
    if (err == -1)
        goto ret_err;

    //addNode(&role_node, "role", args.rolename);
    xmlChar *rolename = encodeXml(args.rolename);
    role_node = addNamedNode(role_node,(xmlChar*)"role", rolename);
    xmlFree(rolename);

    container = addContainerNode(role_node,(xmlChar*)"capabilities");
    //addNode(&node, "capabilities", NULL);
    if (args.capabilities == (uint64_t) -1 >> (64-cap_max_bits())) {
        addContentNode(container,(xmlChar*)"capability",(xmlChar*)"*");
    }
    else {
        for(int i = 0; i < cap_max_bits(); i++) {
            if (args.capabilities & (((uint64_t) 1)<<i)) {
                temp = cap_to_name((cap_value_t)i);
                addContentNode(container,(xmlChar*)"capability",(xmlChar*)temp);
                //addNode(&node, NULL, temp);
                cap_free(temp);
            }
        }
    }

    if (ul) {
        addActor(role_node,ul,(xmlChar*)"users",(xmlChar*)"user",argv);
    }

    if (gl) {
        addActor(role_node,gl,(xmlChar*)"groups",(xmlChar*)"group",argv);
    }

    // if (args.cg) {
    //     node = role_node;
    //     //addNode(&node, "commands", NULL);
    //     for (int i = 0; i < cl->cc; i++) {
    //         //addNode(&node, NULL, argv[cl->cbi+(i*2)]);
    //     }
    // }
    toggle_lock_config(1);
    xmlSaveFormatFileEnc(XML_FILE, doc, "UTF-8", 1);
    toggle_lock_config(0);
    //xmlSaveFormatFileEnc("-", doc, "UTF-8", 1); // Debug

ret_err:
    remove_account(ul); remove_account(gl); remove_command(cl);
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return(err == -1 ? EXIT_FAILURE : EXIT_SUCCESS);
}

static int args_process (int argc, char **argv, args_struct *args)
{
    int count, c;
    int oldC = 0;
    char *save = NULL;

    account_list *ul = &args->ubloc;
    account_list *gl = &args->gbloc;
    command_list *cl = &args->cbloc;

    account_list firstUl, firstGl, temp;
    char *oldArg = NULL;


    optind = 3;

    while (1) {
        static struct option long_options[] = {
    		{ "user", 		required_argument, 0, 'u' },
    		{ "group", 		required_argument, 0, 'g' },
    		{ "command", 	required_argument, 0, 'c' },
    		{ 0, 			0, 				   0,  0  }
    	};

        c = getopt_long(argc, argv, "u:g:c:", long_options, NULL);

        if (c == -1)
            break;

		switch (c) {
        case 'u':
            if (args->uc != 0) {
                oldArg = optarg;
            }
            else {
                /* We use strdup() with optarg
                 * for not breaks optarg string
                 */
                save = strdup(optarg);
                if (!save) {
                    perror("strdup()");
                    return -1;
                }

                count = user_verifier(save);
                free(save);
                if (count == -1)
                    return -1;
                args->uc = count;

                push( (*ul) );
                firstUl = (*ul);

                account_allocation(optarg, ul);
            }

            oldC = c;
            break;
        case 'g':
            if (args->gc != 0) {
                oldArg = optarg;
            }
            else {
                save = strdup(optarg);
                if (!save) {
                    perror("strdup()");
                    return -1;
                }

                count = group_verifier(save);
                free(save);
                if (count == -1)
                    return -1;
                args->gc = count;

                push( (*gl) );
                firstGl = (*gl);

                account_allocation(optarg, gl);
            }
            oldC = c;
            break;
        case 'c':
            if (command_verifier(optarg) == -1)
                return -1;

            /* If command must be add in user bloc */
            if (oldC == 'u') {
                push( (*cl) );
                (*cl)->cbi = optind-1;

                if (oldArg) {
                    /* General user bloc */
                    if (!strcmp(oldArg, "*")) {
                        (*ul)->cs = *cl;
                    }

                    /* If it's a particular user */
                    else {
                        for (temp = firstUl; temp != *ul; temp = temp->next) {
                            if (!strcmp(temp->account, oldArg)) {
                                temp->cs = *cl;
                                break;
                            }
                        }
                        if (!temp->cs) {
                            fprintf(stderr, "User : %s not include in main user bloc\n", oldArg);
                            return -1;
                        }
                    }
                    oldArg = NULL;
                }

                /* General user bloc */
                else {
                    (*ul)->cs = *cl;
                }
            }

            /* If command must be add in group bloc */
            else if (oldC == 'g') {
                push( (*cl) );
                (*cl)->cbi = optind-1;

                if (oldArg) {
                    /* General group bloc */
                    if (!strcmp(oldArg, "*")) {
                        (*gl)->cs = *cl;
                    }

                    /* If it's a particular group */
                    else {
                        for (temp = firstGl; temp != *gl; temp = temp->next) {
                            if (!strcmp(temp->account, oldArg)) {
                                temp->cs = *cl;
                                break;
                            }
                        }
                        if (!temp->cs) {
                            fprintf(stderr, "Group : %s not include in main group bloc\n", oldArg);
                            return -1;
                        }
                    }
                    oldArg = NULL;
                }

                /* General group bloc */
                else {
                    (*gl)->cs = *cl;
                }
            }

            /* If -c is first option call, general command bloc */
            else if (!*cl) {
                fputs("You must specify an actor before command\nExample: addrole test cap_net_raw -g netadmin -c /usr/bin/ping\n",stderr);
                return -1;
            }

            if ((*cl)->cc == MAX_BLOC) {
                fputs("Limits for command numbers on one bloc reached\n", stderr);
                return -1;
            }

            (*cl)->cc++;
            oldC = c;

            break;
        case '?':
        case ':':
            print_help(ADDROLE);
            return -1;
		}
    }
    if (*ul) { *ul = firstUl; }
    if (*gl) { *gl = firstGl; }
    if (*cl) { while((*cl)->prev) {*cl = (*cl)->prev;} }

    return 0;
}
