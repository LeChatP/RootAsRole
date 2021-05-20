#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include "xml_manager.h"

int args_process (int *argc, char **argv, args_struct *args)
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

            if (user_verifier(save, args) == -1) {
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

void print_help (int command)
{
    switch(command) {
    case ADDROLE:
        puts("\nUsage : addrole <role> [-C Capability] [-u user] [-g group] [-c command]");
        puts("Add a role for be using with sr.\nOptions :");
        puts(" -C, --capability=cap1,cap2...\tAdd capabilit(y|ies)");
        puts(" -u, --user=user1,user2...\tAdd user(s)");
        puts(" -g, --group=group1,group2...\tAdd group(s)");
        puts(" -c, --command=\"command1\"\tAdd command. Command can be only used with user or group options");
        puts("\n\t/!\\ 10 users|groups|commands max can be added /!\\\n");
        puts("Example :");
        puts("addrole role1 -C cap_net_bind_service -u anderson,ahmed -c \"python server.py -p 80\" -g zayed,university -c \"command\" -c \"command2\"");
        break;
    case EDITROLE:
        printf("Usage : editrole <rolename>\n");
        break;
    case DELETEROLE:
        printf("Usage : deleterole <rolename>\n");
    }
}
