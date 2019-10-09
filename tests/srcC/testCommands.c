#include "testCommands.h"

#define USER_CAP_FILE_ROLE "/etc/security/capabilityRole.xml"
#define USER_CAP_FILE_ROOT "tests/resources/rootrole.xml"
#define USER_CAP_FILE_TEMP "tests/resources/temp.xml"

#define USER_CAP_FILE_INFO_USER "tests/resources/infouser.xml"
#define USER_CAP_FILE_INFO_USER_NO_ROLE "tests/resources/infousernorole.xml"
#define USER_CAP_FILE_INFO_GROUP "tests/resources/infogroup.xml"
#define USER_CAP_FILE_INFO_USER_GROUP "tests/resources/infousergroup.xml"

static int before(const char *path, char *args[], int nbargs);
static int after(void);



int before(const char *path, char *args[], int nbargs){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(USER_CAP_FILE_ROLE,abspath);
    realpath(path,abspath);
    copy_file_args(abspath,USER_CAP_FILE_ROLE,1,args);
    return 0;
}

int after(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(abspath,USER_CAP_FILE_ROLE);
    return remove(abspath);
}

int beforeRoot(void){
    char *args[1] = {get_username(getuid())};
    return before(USER_CAP_FILE_ROOT,args,1);
}

int beforeInfoUser(void){
    char *args[1] = {get_username(getuid())};
    return before(USER_CAP_FILE_INFO_USER,args,1);
}


int beforeInfoUserNoRole(void){
    char *args[1] = {get_username(getuid())};
    return before(USER_CAP_FILE_INFO_USER_NO_ROLE,args,1);
}

int beforeInfoGroup(void){
    char *args[1] = {get_username(getuid())};
    return before(USER_CAP_FILE_INFO_GROUP,args,1);
}

int beforeInfoUserGroup(void){
    char *args[2] = {get_username(getuid()),get_username(getuid())};
    return before(USER_CAP_FILE_INFO_USER_GROUP,args,2);
}
/**
 * test if command with simple quote works
 */
int testQuotedCommand(void){
    int return_code = 0;
    beforeRoot();
    char *name = "-r root -c \"echo bobo\"";
    int outfp;
    sr_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)-1) > 0)
    {
        if(strstr(ligne,"bobo") != NULL){
            return_code = 1;
            break;
        }
    }
    if(!return_code) goto free_rscs;
    name = "-r root -c \"echo \\\"bo\'bo\\\"\"";
    sr_async_command(name,&outfp);
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"bo\'bo") != NULL){
            return_code = 0;
            goto free_rscs;
        }
        if(strstr(ligne,"You cannot set") != NULL){
            return_code = 1;
            goto free_rscs;
        }
    }
    free_rscs:
    after();
    return return_code;
}

int testXmlEscaptingChars(void){
    int return_code = 0;
    beforeRoot();
    char *name = "-r root -c 'echo bo\"bo'";
    int outfp;
    sr_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"bo\"bo") != NULL){
            return_code = 1;
            goto free_rscs;
        }
    }
    name = "-r root -c 'echo bo&bo'";
    sr_command(name,&outfp);
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"bo&bo") != NULL){
            return_code = 1;
            goto free_rscs;
        }
    }
    name = "-r root -c 'echo bo<bo'";
    sr_command(name,&outfp);
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"bo<bo") != NULL){
            return_code = 1;
            goto free_rscs;
        }
    }
    name = "-r root -c 'echo bo>bo'";
    sr_command(name,&outfp);
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"bo>bo") != NULL){
            return_code = 1;
            goto free_rscs;
        }
    }
    free_rscs:
    after();
    return return_code;
}

int testUserInfoArg(void){
    int return_code = 0;
    beforeInfoUser();
    char *name = "-i";
    int outfp;
    sr_async_command(name,&outfp);
    char ligne[1024];
    int roles = 0; //result expected : 1 + 2 + 3 + 4 + 5 = 15
    int capnetraw = 0; // result expexted : 2
    int anycommands = 0; //result expected : 2
    int command1 = 0; //result expected : 1
    int command2 = 0; //result expected : 1
    int full = 0; //result expected : 3
    int username = 0; //result expected : 2
    int without = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"null") != NULL) goto free_rscs; //don't output null role
        username+=strstrc(ligne,get_username(getuid()));
        roles+=strstrc(ligne,"info0");
        roles+=strstrc(ligne,"info1")*2;
        roles+=strstrc(ligne,"info2")*3;
        roles+=strstrc(ligne,"info3")*4;
        roles+=strstrc(ligne,"info4")*5;
        capnetraw+=strstrc(ligne,"cap_net_raw");
        anycommands+=strstrc(ligne,"with any commands");
        without+=strstrc(ligne,"without any commands");
        command1+=strstrc(ligne,"command1");
        command2+=strstrc(ligne,"command2");
        full+=strstrc(ligne,"full privileges");
    }
    if(roles == 15 && capnetraw == 2 && anycommands == 2 && command1 == 2 && command2 == 1 && full == 3 && username == 2 && without == 1)
        return_code = 1;
    free_rscs:
    close(outfp);
    after();
    return return_code;
}

int testUserInfoRoleArg(void){
    int return_code = 0;
    beforeInfoUser();
    char *name = "-i -r info1";
    int outfp = 0;
    sr_command(name,&outfp);
    char ligne[1024];
    int roles = 0; //result expected : 2
    int capnetraw = 0; // result expexted : 1
    int anycommands = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        roles+=strstrc(ligne,"info1")*2;
        capnetraw+=strstrc(ligne,"cap_net_raw");
        anycommands+=strstrc(ligne,"any commands");
    }
    if(roles == 2 && capnetraw == 1 && anycommands == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("role info1 not shown");
        goto free_rscs;
    }
    name = "-i -r null";
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0);
    close(outfp);
    sr_command(name,&outfp);
    roles = 0; //result expected : 1
    int cant = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        roles+=strstrc(ligne,"null");
        cant+=strstrc(ligne,"you can't use the role");
    }
    if(roles == 1 && cant == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("denied for role null failed");
        goto free_rscs;
    }
    name = "-i -r info3";
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0);
    close(outfp);
    sr_command(name,&outfp);
    cant = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        cant+=strstrc(ligne,"without any commands");
    }
    if(cant != 1){
        return_code = 0;
        printf("no commands not shown");
        goto free_rscs;
    }
    name = "-i -r info2";
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0);
    close(outfp);
    sr_command(name,&outfp);
    cant = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        cant+=strstrc(ligne,"grant any privileges");
    }
    if(cant != 1){
        return_code = 0;
        printf("no privileges not shown");
        goto free_rscs;
    }
    free_rscs:
    after();
    return return_code;
}

int testUserInfoCommandArg(void){
    int return_code = 0;
    beforeInfoUser();
    char *name = "-i -c command1";
    int outfp;
    sr_async_command(name,&outfp);
    
    char ligne[130];
    int roles = 0; //result expected : 0
    int capnetraw = 0; // result expexted : 0
    int thiscommand = 0; //result expected : 1
    int rightcommand = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        printf("%s\n\n",ligne);
        roles+=strstrc(ligne,"info2");
        capnetraw+=strstrc(ligne,"cap_net_raw");
        thiscommand+=strstrc(ligne,"this command");
        rightcommand+=strstrc(ligne,"sr -c \"command1\"");
        lseek(outfp,0,SEEK_END);
    }
    if(roles == 0 && capnetraw == 0 && thiscommand == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("missing informations in %s\n",name);
        goto free_rscs;
    }
    name = "-i -c null";
    close(outfp);
    sr_command(name,&outfp);
    roles = 0; //result expected : 3
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        roles+=strstrc(ligne,"info0");
        roles+=strstrc(ligne,"info1")*2;
    }
    if(roles == 3)
        return_code = 1;
    else {
        return_code = 0;
        printf("not enough roles shown");
        goto free_rscs;
    }
    name = "-i -c command3";
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0);
    close(outfp);
    sr_command(name,&outfp);
    capnetraw = 0; //expected 1

    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        capnetraw+=strstrc(ligne,"cap_net_raw");
    }
    if(capnetraw != 1){
        return_code = 0;
        printf("capabilities not shown on %s",name);
        goto free_rscs;
    }
    free_rscs:
    after();
    return return_code;
}

int testUserInfoCommandArgNoRole(void){
    int return_code = 0;
    beforeInfoUserNoRole();
    int outfp = 0;
    char ligne[1024];
    char *name = "-i -c null";
    sr_command(name,&outfp);
    int cant = 0; //result expected : 1
    int error = 0; //result expected : 0
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        cant+=strstrc(ligne,"you can't execute this command");
        error +=strstrc(ligne,"sr -c");
        error+=strstrc(ligne,"roles");
        error+=strstrc(ligne,"info");
        error+=strstrc(ligne,"null");
    }
    if(cant == 1 && error == 0)
        return_code = 1;
    else {
        return_code = 0;
        printf("show wrong informations or not show cannot");
        goto free_rscs;
    }
    free_rscs:
    after();
    return return_code;
}

int testUserInfoRoleCommandArg(void){
    int return_code = 0;
    beforeInfoUser();

    int outfp = 0;
    char ligne[1024];
    char *name = "-i -r info2 -c command1";
    sr_command(name,&outfp);
    int simplify = 0; //result expected : 1
    int command1 = 0; //result expected : 0
    int rolearg = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        simplify+=strstrc(ligne,"simplified");
        command1+=strstrc(ligne,"sr -c command1");
        rolearg+=strstrc(ligne,"-r info2");
    }
    if(command1 == 1 && rolearg == 0 && simplify == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("show wrong informations or not show cannot");
        goto free_rscs;
    }
    name = "-i -r null -c null";
    sr_command(name,&outfp);
    int cant = 0; //result expected : 3
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        cant+=strstrc(ligne,"you can't execute this command");
    }
    if(cant == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("expected that you can't execute null command with null role");
        goto free_rscs;
    }
    name = "-i -r info0 -c command";
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0);
    close(outfp);
    sr_command(name,&outfp);
    int can = 0; //result expected : 1
    int command = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        can+=strstrc(ligne,"you can execute \"command\" with command");
        command+=strstrc(ligne,"sr -r \"info0\" -c \"command\"");
    }
    if(can == 1 && command == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("expected that you can execute any command with info0 role");
        goto free_rscs;
    }
    free_rscs:
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0);
    close(outfp);
    after();
    return return_code;
}

/**
 * Group
 * 
 */

int testGroupInfoArg(void){
    int return_code = 0;
    beforeInfoUser();
    char *name = "-i";
    int outfp;
    sr_command(name,&outfp);
    char ligne[32];
    int roles = 0; //result expected : 1 + 2 + 3 + 4 = 7
    int capnetraw = 0; // result expexted : 1
    int anycommands = 0; //result expected : 3
    int command1 = 0; //result expected : 1
    int command2 = 0; //result expected : 1
    int full = 0; //result expected : 2
    int username = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,get_username(getuid()))) username++;
        if(strstr(ligne,"null") != NULL)    goto free_rscs; //don't output null role
        roles+=strstrc(ligne,"info0");
        roles+=strstrc(ligne,"info1")*2;
        roles+=strstrc(ligne,"info2")*3;
        roles+=strstrc(ligne,"info3")*4;
        capnetraw+=strstrc(ligne,"cap_net_raw");
        anycommands+=strstrc(ligne,"any commands");
        command1+=strstrc(ligne,"command1");
        command2+=strstrc(ligne,"command2");
        full+=strstrc(ligne,"full privileges");
    }
    if(roles == 7 && capnetraw == 1 && anycommands == 3 && command1 == 1 && command2 == 2 && full == 2 && username == 1)
        return_code = 1;
    free_rscs:
    after();
    return return_code;
}

int testGroupInfoRoleArg(void){
    int return_code = 0;
    beforeInfoUser();
    char *name = "-i -r info1";
    int outfp;
    sr_command(name,&outfp);
    char ligne[1024];
    int roles = 0; //result expected : 2
    int capnetraw = 0; // result expexted : 1
    int anycommands = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        roles+=strstrc(ligne,"info1")*2;
        capnetraw+=strstrc(ligne,"cap_net_raw");
        anycommands+=strstrc(ligne,"any commands");
    }
    if(roles == 2 && capnetraw == 1 && anycommands == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("role info1 not shown");
        goto free_rscs;
    }
    name = "-i -r null";
    sr_command(name,&outfp);
    roles = 0; //result expected : 1
    int cant = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        roles+=strstrc(ligne,"null");
        if(strstr(ligne,"you can't use the role")) cant++;
    }
    if(roles == 1 && cant == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("denied for role null failed");
        goto free_rscs;
    }
    name = "-i -r info3";
    sr_command(name,&outfp);
    cant = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"without any commands")) cant++;
    }
    if(cant != 1){
        return_code = 0;
        printf("no commands not shown");
        goto free_rscs;
    }
    name = "-i -r info2";
    sr_command(name,&outfp);
    cant = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"grant any privileges")) cant++;
    }
    if(cant != 1){
        return_code = 0;
        printf("no privileges not shown");
        goto free_rscs;
    }
    free_rscs:
    after();
    return return_code;
}

int testGroupInfoCommandArg(void){
    int return_code = 0;
    beforeInfoUser();
    char *name = "-i -c command1";
    int outfp;
    sr_command(name,&outfp);
    char ligne[1024];
    int roles = 0; //result expected : 0
    int capnetraw = 0; // result expexted : 0
    int thiscommand = 0; //result expected : 1
    int rightcommand = 0; //result expected : 1
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        roles+=strstrc(ligne,"info2");
        capnetraw+=strstrc(ligne,"cap_net_raw");
        thiscommand+=strstrc(ligne,"this command");
        rightcommand+=strstrc(ligne,"sr -c \"command1\"");
    }
    if(roles == 0 && capnetraw == 0 && thiscommand == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("missing informations in %s",name);
        goto free_rscs;
    }
    name = "-i -c null";
    sr_command(name,&outfp);
    roles = 0; //result expected : 3
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        roles+=strstrc(ligne,"info0");
        roles+=strstrc(ligne,"info1")*2;
    }
    if(roles == 3)
        return_code = 1;
    else {
        return_code = 0;
        printf("not enough roles shown");
        goto free_rscs;
    }
    name = "-i -c command3";
    sr_command(name,&outfp);
    capnetraw = 0; //expected 1

    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        capnetraw+=strstrc(ligne,"cap_net_raw");
    }
    if(capnetraw != 1){
        return_code = 0;
        printf("capabilities not shown on %s",name);
        goto free_rscs;
    }
    free_rscs:
    after();
    return return_code;
}

int testGroupInfoCommandArgNoRole(void){
    int return_code = 0;
    beforeInfoUserNoRole();
    int outfp = 0;
    char ligne[1024];
    char *name = "-i -c null";
    sr_command(name,&outfp);
    int cant = 0; //result expected : 1
    int error = 0; //result expected : 0
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        cant+=strstrc(ligne,"you can't execute this command");
        error+=strstrc(ligne,"sr -c");
        error+=strstrc(ligne,"roles");
        error+=strstrc(ligne,"info");
        error+=strstrc(ligne,"null");
    }
    if(cant == 1 && error == 0)
        return_code = 1;
    else {
        return_code = 0;
        printf("show wrong informations or not show cannot");
        goto free_rscs;
    }
    free_rscs:
    after();
    return return_code;
}

int testGroupInfoRoleCommandArg(void){
    int return_code = 0;
    beforeInfoUser();

    int outfp = 0;
    char ligne[1024];
    char *name = "-i -r info2 -c command1";
    sr_command(name,&outfp);
    int simplify = 0; //result expected : 1
    int command1 = 0; //result expected : 0
    int rolearg = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        simplify+=strstrc(ligne,"simplified");
        command1+=strstrc(ligne,"sr -c command1");
        if(strstr(ligne,"-r info2")) rolearg++;
    }
    if(command1 == 1 && rolearg == 0 && simplify == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("show wrong informations or not show cannot");
        goto free_rscs;
    }
    name = "-i -r null -c null";
    sr_command(name,&outfp);
    int cant = 0; //result expected : 3
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        cant+=strstrc(ligne,"you can't execute this command");
    }
    if(cant == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("expected that you can't execute null command with null role");
        goto free_rscs;
    }
    name = "-i -r info0 -c command";
    sr_command(name,&outfp);
    int can = 0; //result expected : 1
    int command = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        can+=strstrc(ligne,"you can execute \"command\" with command");
        command+=strstrc(ligne,"sr -r \"info0\" -c \"command\"");
    }
    if(can == 1 && command == 1)
        return_code = 1;
    else {
        return_code = 0;
        printf("expected that you can execute any command with info0 role");
        goto free_rscs;
    }
    free_rscs:
    after();
    return return_code;
}