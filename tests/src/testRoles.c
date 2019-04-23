#include "testRoles.h"

#define USER_CAP_FILE_USER "tests/resources/testRoles/configuration1.xml"
#define USER_CAP_FILE_GROUP "tests/resources/testRoles/configuration2.xml"
#define USER_CAP_FILE_USER_GROUP "tests/resources/testRoles/configuration3.xml"

/**
 * ###### tests for User ######
 */

/** 
 * Test if a role is found with a user
 */
int testFindRoleWithUser(void){
    int return_code = 0;
    get_document_from_urc();
    return return_code;
}
/** 
 * Test if a role is found with a user in user array in configuration
 */
int testFindRoleWithUserInUserArrayConfig(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if a role is found with a user with command array in configuration
 */
int testFindRoleWithUserInCommandArrayConfig(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if a role isn't found with a user and wrong command
 */
int testFindRoleWithUserWrongCommand(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if a role isn't found with a wrong user but right command
 */
int testFindRoleWithWrongUserRightCommand(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if the first role is found with a user
 */
int testFindFirstRoleWithUser(void){
    int return_code = 0;
    return return_code;
}

/**
 * ###### tests for Group ######
 */

/** 
 * Test if a role is found with a group
 */
int testFindRoleWithGroup(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if a role is found with a group array in urc
 */
int testFindRoleWithGroupArrayUrc(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if a role is found with a group array in configuration
 */
int testFindRoleWithGroupArrayConfiguration(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if a role is found for command with a command array in configuration
 */
int testFindRoleWithGroupWithCommandArrayConfiguration(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if a role isn't found with a wrong command in urc
 */
int testFindRoleWithGroupWrongCommand(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if a role isn't found with a wrong group in urc
 */
int testFindRoleWithWrongGroupRightCommand(void){
    int return_code = 0;
    return return_code;
}
/** 
 * Test if the first role is found with a group in urc
 */
int testFindFirstRoleWithGroup(void){
    int return_code = 0;
    return return_code;
}

/**
 * ###### tests for User and Group ######
 */

/** 
 * Test if a role is found with a user and a group in urc
 */
int testFindRoleWithUserAndGroup(void){
    int return_code = 0;
    return return_code;
}

/**
 * Test if role is not found if command is wrong with user and group
 */
int testFindRoleWithUserAndGroupWrongCommand(void){
    int return_code = 0;
    return return_code;
}

/**
 * Test if Role is found for User when group is wrong
 */
int testFindRoleWithRightUserWrongGroupRightCommand(void){
    int return_code = 0;
    return return_code;
}

/**
 * Test if Role is found for Group when User is wrong
 */
int testFindRoleWithWrongUserRightGroupRightCommand(void){
    int return_code = 0;
    return return_code;
}

/**
 * Test if the first Role is found for User when user and group match
 */
int testFindFirstRoleWithUserAndGroup(void){
    int return_code = 0;
    return return_code;
}

//test result wrong configuration
int testFindRoleErrorConfiguration(void){
    int return_code = 0;
    return return_code;
}