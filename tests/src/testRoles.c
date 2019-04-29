#include "testRoles.h"

#define USER_CAP_FILE_ROLE "/etc/security/capabilityRole.xml"
#define USER_CAP_FILE_USER "tests/resources/testRoles/configuration1.xml"
#define USER_CAP_FILE_GROUP "tests/resources/testRoles/configuration2.xml"
#define USER_CAP_FILE_USER_GROUP "tests/resources/testRoles/configuration3.xml"
#define USER_CAP_FILE_NO_CMD_SPEC "tests/resources/testRoles/configuration4.xml"
#define USER_CAP_FILE_TEMP "tests/resources/temp.xml"

//saving
static char *password = NULL;
/**
 * ###### tests for User ######
 */

char *getpassword(void){
    if(password == NULL){
        password = getpass("Password:");
    }
    return password;
}

int beforeUser(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(USER_CAP_FILE_ROLE,abspath);
    realpath(USER_CAP_FILE_USER,abspath);
    copy_file_args(abspath,USER_CAP_FILE_ROLE,get_username(getuid()),NULL,NULL);
    return 0;
}

int afterUser(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(abspath,USER_CAP_FILE_ROLE);
    return remove(abspath);
}

pid_t sr_echo_command(char *name, int *outfp){
    char *pass = getpassword();
    char command[64];
    sprintf(command,"/usr/bin/sr -c 'echo \"%s\"'",name);
    int infp;
    popen2(command,&infp,outfp);
    write(infp,pass,strlen(pass));
    close(infp);
    wait(NULL);
    return 0;
}

/** 
 * Test if a role is found with a user
 */
int testFindRoleWithUser(void){
    int return_code = 0;
    beforeUser();
    char *name = "role1-user-cmd";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }
    }
    afterUser();
    return return_code;
}
/** 
 * Test if a role is found with a user in user array in configuration
 */
int testFindRoleWithUserInUserArrayConfig(void){
    int return_code = 0;
    beforeUser();
    char *name = "role2-user-cmd";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }
    }
    afterUser();
    return return_code;
}
/** 
 * Test if a role is found with a user with command array in configuration
 */
int testFindRoleWithUserInCommandArrayConfig(void){
    int return_code = 0;
    beforeUser();
    char *name = "role3-user-cmd2";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }
    }
    afterUser();
    return return_code;
}
/** 
 * Test if a role isn't found with a user and wrong command
 */
int testFindRoleWithUserWrongCommand(void){
    int return_code = 0;
    beforeUser();
    char *name = "user";
    int outfp;
    sr_echo_command(name,&outfp); //wrong command
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 0;
            break;
        }else{
            return_code = 1;
        }
    }
    afterUser();
    return return_code;
}
/** 
 * Test if a role isn't found with a wrong user but right command
 */
int testFindRoleWithWrongUserRightCommand(void){
    int return_code = 0;
    beforeUser();
    char *name = "role2-foo-cmd";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            printf("%s\n",strstr(ligne,name));
            return_code = 0;
            break;
        }else{
            return_code = 1;
        }

    }
    
    afterUser();
    return return_code;
}
/** 
 * Test if the first role is found with a user
 */
int testFindFirstRoleWithUser(void){
    int return_code = 0;
    beforeUser();
    char *name = "role1-user-cmd";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"r0le1") != NULL){
            return_code = 1;
            break;
        }

    }
    
    afterUser();
    return return_code;
}

/**
 * ###### tests for Group ######
 */

int beforeGroup(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(USER_CAP_FILE_ROLE,abspath);
    realpath(USER_CAP_FILE_GROUP,abspath);
    char **groups = NULL;
    int nb_group = 0;
    get_group_names(get_username(getuid()),get_group_id(getuid()),&nb_group,&groups);
    return copy_file_args(abspath,USER_CAP_FILE_ROLE,groups[0],NULL,NULL);
}

int afterGroup(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(abspath,USER_CAP_FILE_ROLE);
    return remove(abspath);
}

/** 
 * Test if a role is found with a group
 */
int testFindRoleWithGroup(void){
    int return_code = 0;
    beforeGroup();
    char *name = "role1-group-cmd";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }
    }
    
    afterGroup();
    return return_code;
}
/** 
 * Test if a role is found with a group array in urc
 */
int testFindRoleWithGroupArrayUrc(void){
    int return_code = 0;
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(USER_CAP_FILE_ROLE,abspath);
    realpath(USER_CAP_FILE_GROUP,abspath);
    char **groups = NULL;
    int nb_group = 0;
    get_group_names(get_username(getuid()),get_group_id(getuid()),&nb_group,&groups);
    if(nb_group > 1) copy_file_args(abspath,USER_CAP_FILE_ROLE,groups[1],NULL,NULL);
    else {
        printf("cannot test groupArray because %s isn't in more than 1 group",get_username(getuid()));
        return -1;
    }
    char *name = "role1-group-cmd";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }
    }
    
    afterGroup();
    return return_code;
}
/** 
 * Test if a role is found with a group array in configuration
 */
int testFindRoleWithGroupArrayConfiguration(void){
    int return_code = 0;
    beforeGroup();
    char *name = "role2-group-cmd";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }
    }
    afterGroup();
    return return_code;
}
/** 
 * Test if a role is found for command with a command array in configuration
 */
int testFindRoleWithGroupWithCommandArrayConfiguration(void){
    int return_code = 0;
    beforeGroup();
    char *name = "role3-group-cmd2";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }
    }
    afterGroup();
    return return_code;
}
/** 
 * Test if a role isn't found with a wrong command in urc
 */
int testFindRoleWithGroupWrongCommand(void){
    int return_code = 0;
    beforeGroup();
    char *name = "role2-gfoo-cmd";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 0;
            break;
        }else{
            return_code = 1;
        }

    }
    afterGroup();
    return return_code;
}

/** 
 * Test if the first role is found with a group in urc
 */
int testFindFirstRoleWithGroup(void){
    int return_code = 0;
    beforeGroup();
    char *name = "role1-group-cmd";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }

    }
    
    afterGroup();
    return return_code;
}

/**
 * test if match when no command is specified to a user
 */
int testFindUserRoleNoCommandInConfiguration(){
    int return_code = 0;
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(USER_CAP_FILE_ROLE,abspath);
    realpath(USER_CAP_FILE_NO_CMD_SPEC,abspath);
    copy_file_args(abspath,USER_CAP_FILE_ROLE,get_username(getuid()),"null",NULL);

    char *name = "anyCommand";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }
    }
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(abspath,USER_CAP_FILE_ROLE);
    remove(abspath);
    return return_code;
}

/**
 * test if match when no command is specified to a group
 */
int testFindGroupRoleNoCommandInConfiguration(){
    int return_code = 0;
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(USER_CAP_FILE_ROLE,abspath);
    realpath(USER_CAP_FILE_NO_CMD_SPEC,abspath);
    char **groups = NULL;
    int nb_group = 0;
    get_group_names(get_username(getuid()),get_group_id(getuid()),&nb_group,&groups);
    copy_file_args(abspath,USER_CAP_FILE_ROLE,"null",groups[0],NULL);
    char *name = "anyCommand";
    int outfp;
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,name) != NULL){
            return_code = 1;
            break;
        }
    }
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(abspath,USER_CAP_FILE_ROLE);
    remove(abspath);
    return return_code;
}

/**
 * ###### tests for User and Group ######
 */

int beforeGroupUser(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(USER_CAP_FILE_ROLE,abspath);
    realpath(USER_CAP_FILE_USER_GROUP,abspath);
    char **groups = NULL;
    int nb_group = 0;
    get_group_names(get_username(getuid()),get_group_id(getuid()),&nb_group,&groups);
    return copy_file_args(abspath,USER_CAP_FILE_ROLE,get_username(getuid()),groups[0],NULL);
}

int afterGroupUser(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(abspath,USER_CAP_FILE_ROLE);
    return remove(abspath);
}