#include <stdio.h>
#include "role_manager.h"

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
