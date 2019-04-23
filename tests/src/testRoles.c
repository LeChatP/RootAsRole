#include "testRoles.h"

#define USER_CAP_FILE_ROLE "/etc/security/capabilityRole.xml"
#define USER_CAP_FILE_USER "tests/resources/testRoles/configuration1.xml"
#define USER_CAP_FILE_GROUP "tests/resources/testRoles/configuration2.xml"
#define USER_CAP_FILE_USER_GROUP "tests/resources/testRoles/configuration3.xml"
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
    return copy_file_args(abspath,USER_CAP_FILE_ROLE,get_username(getuid()),NULL,NULL);
}

int afterUser(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(abspath,USER_CAP_FILE_ROLE);
    return remove(abspath);
}

/** 
 * Test if a role is found with a user
 */
int testFindRoleWithUser(void){
    int return_code = 0;
    beforeUser();
    char *pass = getpassword();
    char command[2048];
    char *echo = "echo \"\"";
    sprintf(command,"/usr/bin/sr -n -r %s -c %s > out.log","role1",echo);
    afterUser();
    return return_code;
}
/** 
 * Test if a role is found with a user in user array in configuration
 */
int testFindRoleWithUserInUserArrayConfig(void){
    int return_code = 0;
    beforeUser();
    char *pass = getpassword();
    afterUser();
    return return_code;
}
/** 
 * Test if a role is found with a user with command array in configuration
 */
int testFindRoleWithUserInCommandArrayConfig(void){
    int return_code = 0;
    beforeUser();
    char *pass = getpassword();
    afterUser();
    return return_code;
}
/** 
 * Test if a role isn't found with a user and wrong command
 */
int testFindRoleWithUserWrongCommand(void){
    int return_code = 0;
    beforeUser();
    char *pass = getpassword();
    afterUser();
    return return_code;
}
/** 
 * Test if a role isn't found with a wrong user but right command
 */
int testFindRoleWithWrongUserRightCommand(void){
    int return_code = 0;
    beforeUser();
    char *pass = getpassword();
    afterUser();
    return return_code;
}
/** 
 * Test if the first role is found with a user
 */
int testFindFirstRoleWithUser(void){
    int return_code = 0;
    beforeUser();
    char *pass = getpassword();
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
    char **groups;
    int nb_group;
    get_group_names(get_username(getuid()),get_group_id(getuid()),nb_group,groups);
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
    char *pass = getpassword();
    afterGroup();
    return return_code;
}
/** 
 * Test if a role is found with a group array in urc
 */
int testFindRoleWithGroupArrayUrc(void){
    int return_code = 0;
    beforeGroup();
    char *pass = getpassword();
    afterGroup();
    return return_code;
}
/** 
 * Test if a role is found with a group array in configuration
 */
int testFindRoleWithGroupArrayConfiguration(void){
    int return_code = 0;
    beforeGroup();
    char *pass = getpassword();
    afterGroup();
    return return_code;
}
/** 
 * Test if a role is found for command with a command array in configuration
 */
int testFindRoleWithGroupWithCommandArrayConfiguration(void){
    int return_code = 0;
    beforeGroup();
    char *pass = getpassword();
    afterGroup();
    return return_code;
}
/** 
 * Test if a role isn't found with a wrong command in urc
 */
int testFindRoleWithGroupWrongCommand(void){
    int return_code = 0;
    beforeGroup();
    char *pass = getpassword();
    afterGroup();
    return return_code;
}
/** 
 * Test if a role isn't found with a wrong group in urc
 */
int testFindRoleWithWrongGroupRightCommand(void){
    int return_code = 0;
    beforeGroup();
    char *pass = getpassword();
    afterGroup();
    return return_code;
}
/** 
 * Test if the first role is found with a group in urc
 */
int testFindFirstRoleWithGroup(void){
    int return_code = 0;
    beforeGroup();
    char *pass = getpassword();
    afterGroup();
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
    char **groups;
    int nb_group;
    get_group_names(get_username(getuid()),get_group_id(getuid()),nb_group,groups);
    return copy_file_args(abspath,USER_CAP_FILE_ROLE,get_username(getuid()),groups[0],NULL);
}

int afterGroupUser(void){
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(abspath,USER_CAP_FILE_ROLE);
    return remove(abspath);
}

/** 
 * Test if a role is found with a user and a group in urc
 */
int testFindRoleWithUserAndGroup(void){
    int return_code = 0;
    beforeGroupUser();
    char *pass = getpassword();
    afterGroupUser();
    return return_code;
}

/**
 * Test if role is not found if command is wrong with user and group
 */
int testFindRoleWithUserAndGroupWrongCommand(void){
    int return_code = 0;
    beforeGroupUser();
    char *pass = getpassword();
    afterGroupUser();
    return return_code;
}

/**
 * Test if Role is found for User when group is wrong
 */
int testFindRoleWithRightUserWrongGroupRightCommand(void){
    int return_code = 0;
    beforeGroupUser();
    char *pass = getpassword();
    afterGroupUser();
    return return_code;
}

/**
 * Test if Role is found for Group when User is wrong
 */
int testFindRoleWithWrongUserRightGroupRightCommand(void){
    int return_code = 0;
    beforeGroupUser();
    char *pass = getpassword();
    afterGroupUser();
    return return_code;
}

/**
 * Test if the first Role is found for User when user and group match
 */
int testFindFirstRoleWithUserAndGroup(void){
    int return_code = 0;
    beforeGroupUser();
    char *pass = getpassword();
    afterGroupUser();
    return return_code;
}

//test result wrong configuration
int testFindRoleErrorConfiguration(void){
    int return_code = 0;
    beforeGroupUser();
    char *pass = getpassword();
    afterGroupUser();
    return return_code;
}