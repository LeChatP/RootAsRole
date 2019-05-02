#ifndef TEST_ROLES_H
#define TEST_ROLES_H
#include "../../src/user.h"
#include "utilsTests.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

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
 * Test if the first role is found with a group in urc
 */
int testFindFirstRoleWithGroup(void);

/**
 * ###### Specific tests ######
 */

/**
 * test if match when no command is specified to a user
 */
int testFindUserRoleNoCommandInConfiguration();

/**
 * test if match when no command is specified to a group
 */
int testFindGroupRoleNoCommandInConfiguration();

/**
 * ###### tests for User and Group ######
 */

/**
 * TODO: Test if role with user is selected in first
 */

#endif //TEST_ROLES_H