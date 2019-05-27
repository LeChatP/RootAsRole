#include "utilsTests.h"

int testCapableFullHelp();
int testCapableCommand();
int testCapableCommandFilter();
int testCapableSleep();
int testCapableDaemon();
int testCapableRaw();
int testCapableVersion();

int testCapableCommandTcpdumpResult();
int testCapableCommandPingResult();
int testCapableCommandCatResult();
int testCapableCommandSSHD();
int testCapableCommandApache();

int testCapableCommandIncorrect();
int testCapableSleepIncorrect();
int testCapableSyntaxError();
int testCapableNoCapabilitiesNeeded(); //impossible there's almost only cap_sys_admin
