#include <stdio.h>

#include "help.h"

void print_help (int command)
{
    switch(command) {
    case ADDROLE:
        puts("\nUsage : addrole <role> <Capability> [-u user] [-g group] [-c command]");
        puts("Add a role for be using with sr.\n\nMandatory Options :");
        puts("<role>\t\t: role1\t\t\t\tRole to add.");
        puts("<Capability>\t: cap_net_raw,cap_sys_net...\tCapabilit(y|ies) to add.\n");
        puts("Optionnal options :");
        puts(" -u, --user=user1,user2...\tAdd user(s)");
        puts(" -g, --group=group1,group2...\tAdd group(s)");
        puts(" -c, --command=\"command1\"\tAdd command.");
        puts("\nExample :");
        puts("addrole role1 cap_net_bind_service -u anderson,ahmed -c \"python server.py -p 80\" -g zayed,university -c \"command\" -c \"command2\"\n");
        break;
    case EDITROLE:
        printf("Usage : editrole <role>\n");
        break;
    case DELETEROLE:
        printf("Usage : deleterole <role>\n");
    }
}
