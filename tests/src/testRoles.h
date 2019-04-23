#ifndef TEST_ROLES_H
#define TEST_ROLES_H
#include "../../src/user.h"
#include "utilsTests.h"
#include <stdlib.h>

/**
 * ###### tests for User ######
 */

/** 
 * Test if a role is found with a user
 */
int testFindRoleWithUser(void);
/** 
 * Test if a role is found with a user in user array in configuration
 */
int testFindRoleWithUserInUserArrayConfig(void);
/** 
 * Test if a role is found with a user with command array in configuration
 */
int testFindRoleWithUserInCommandArrayConfig(void);
/** 
 * Test if a role isn't found with a user and wrong command
 */
int testFindRoleWithUserWrongCommand(void);
/** 
 * Test if a role isn't found with a wrong user but right command
 */
int testFindRoleWithWrongUserRightCommand(void);
/** 
 * Test if the first role is found with a user
 */
int testFindFirstRoleWithUser(void);

/**
 * ###### tests for Group ######
 */

/** 
 * Test if a role is found with a group
 */
int testFindRoleWithGroup(void);
/** 
 * Test if a role is found with a group array in urc
 */
int testFindRoleWithGroupArrayUrc(void);
/** 
 * Test if a role is found with a group array in configuration
 */
int testFindRoleWithGroupArrayConfiguration(void);
/** 
 * Test if a role is found for command with a command array in configuration
 */
int testFindRoleWithGroupWithCommandArrayConfiguration(void);
/** 
 * Test if a role isn't found with a wrong command in urc
 */
int testFindRoleWithGroupWrongCommand(void);
/** 
 * Test if a role isn't found with a wrong group in urc
 */
int testFindRoleWithWrongGroupRightCommand(void);
/** 
 * Test if the first role is found with a group in urc
 */
int testFindFirstRoleWithGroup(void);

/**
 * ###### tests for User and Group ######
 */

/** 
 * Test if a role is found with a user and a group in urc
 */
int testFindRoleWithUserAndGroup(void);

/**
 * Test if role is not found if command is wrong with user and group
 */
int testFindRoleWithUserAndGroupWrongCommand(void);

/**
 * Test if Role is found for User when group is wrong
 */
int testFindRoleWithRightUserWrongGroupRightCommand(void);

/**
 * Test if Role is found for Group when User is wrong
 */
int testFindRoleWithWrongUserRightGroupRightCommand(void);

/**
 * Test if the first Role is found for User when user and group match
 */
int testFindFirstRoleWithUserAndGroup(void);

//test result wrong configuration
int testFindRoleErrorConfiguration(void);

#endif //TEST_ROLES_H