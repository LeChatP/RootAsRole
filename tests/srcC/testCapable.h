#include "utilsTests.h"

/**
 * Test that the help message has the right options
 */
int testCapableFullHelp();
/**
 * Test capable command without any options, so by default as daemon
 */
int testCapableCommand();
/**
 * Test if filter is rightly coded
 * TODO enhance this test
 */
int testCapableCommandFilter();
/**
 * Test if sleep options is sleeping the right time
 */
int testCapableSleep();
/**
 * Test if capable run as daemon with -d option
 */
int testCapableDaemon();
/**
 * Test if -r option is showing raw data
 */
int testCapableRaw();
/**
 * Test the version of capable
 * Useful for reminder
 */
int testCapableVersion();

/**
 * Test if tcpdump returns CAP_NET_RAW
 */
int testCapableCommandTcpdumpResult();
/**
 * Test if ping returns CAP_NET_RAW
 */
int testCapableCommandPingResult();
/**
 * Test if cat /proc/kallsyms returns CAP_SYSLOG, also test if cat has CAP_SYSLOG capability (be warned if this occurs)
 */
int testCapableCommandCatResult();
/**
 * Test if sshd returns CAP_NET_BIND_SERVICE
 */
int testCapableCommandSSHD();
/**
 * Test if apache2ctl returns CAP_NET_BIND_SERVICE and CAP_SYS_PTRACE
 */
int testCapableCommandApache();
/**
 * Test if incorrect command showing command not found
 */
int testCapableCommandIncorrect();
/**
 * Test if we fill sleep option with a non-number parameter say bad parameter 
 */
int testCapableSleepIncorrect();
/**
 * Test if syntax error in command showing Usage
 */
int testCapableSyntaxError();
/**
 * Test when command doesn't need caps showing only CAP_SYS_ADMIN...
 * TODO: Need to enhance
 */
int testCapableNoCapabilitiesNeeded();
