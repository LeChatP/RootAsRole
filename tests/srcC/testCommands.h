#ifndef TEST_COMMANDS_H
#define TEST_COMMANDS_H

#include "../../src/user.h"
#include "utilsTests.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

int testQuotedCommand(void);

/**
 * Testing Escapting chars in inputs
 * & -> &amp; 
 * " -> &quot;
 * < -> &lt;
 * > ->&gt;
 */
int testXmlEscaptingChars(void);

/**
 * test sr -i with user configuration
 */
int testUserInfoArg(void);

/**
 * test sr -i -r role with user configuration
 */
int testUserInfoRoleArg(void);

/**
 * test sr -i -c command with user configuration
 */
int testUserInfoCommandArg(void);

/**
 * test sr -i -r role -c command with user configuration
 */
int testUserInfoRoleCommandArg(void);

/**
 * test sr -i -r role -c command with user configuration
 * but with configuration with no matching role
 */
int testUserInfoCommandArgNoRole(void);

/**
 * test sr -i with group configuration
 */
int testGroupInfoArg(void);

/**
 * test sr -i -r role with group configuration
 */
int testGroupInfoRoleArg(void);

/**
 * test sr -i -c command with group configuration
 */
int testGroupInfoCommandArg(void);

/**
 * test sr -i -r role -c command with group configuration
 */
int testGroupInfoRoleCommandArg(void);

/**
 * test sr -i -r role -c command with group configuration
 * but with configuration with no matching role
 */
int testGroupInfoCommandArgNoRole(void);
#endif