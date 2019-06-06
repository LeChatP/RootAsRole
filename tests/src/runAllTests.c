#include <sys/capability.h>
#include "allTests.h"
#include "testScenarios.h"
#include "testObserver.h"
#include "testRoles.h"
#include "utilsTests.h"
#include "testCommands.h"
#include "testCapable.h"

#define USER_CAP_FILE_ROLE "/etc/security/capabilityRole.xml"

static int haswriteaccess(){
    cap_t cap = cap_get_proc();
    cap_flag_value_t v = 0; 
    cap_get_flag(cap, CAP_DAC_OVERRIDE, CAP_PERMITTED, &v);
    return v;
}

int main(void){
    //testObserver
    TestSuite *suite1 = newTestSuite("ObserverTest");
    registerTest(suite1,newTest(&testTestSubjectAttached,"TestSubjectAttached"));
    registerTest(suite1,newTest(&testTestSubjectCollection,"SubjectCollection"));
    registerTest(suite1,newTest(&testTestSubjectCollectionReachMax,"SubjectCollectionReachMax"));
    registerTest(suite1,newTest(&testTestObserverNotified,"ObserverNotified"));
    registerTest(suite1,newTest(&testTestObserverWrongNotified,"ObserverWrongNotified"));
    registerTest(suite1,newTest(&testTestObserversNotified,"ObserversNotified"));
    registerTest(suite1,newTest(&testTestObserversWrongNotified,"ObserversWrongNotified"));
    
    //testScenario1
    TestSuite *suite2 = newTestSuite("Scenarios");
    registerTest(suite2,newTest(&testScenario1,"Scénario1"));

    //test noRoleSpecified
    TestSuite *noroleSuite = newTestSuite("No Role Specified Tests");
    //User Tests
    registerTest(noroleSuite,newTest(&testFindRoleWithUser,"FindRoleWithUser"));
    registerTest(noroleSuite,newTest(&testFindRoleWithUserInUserArrayConfig,"FindRoleWithUserInUserArrayConfig"));
    registerTest(noroleSuite,newTest(&testFindRoleWithUserInCommandArrayConfig,"FindRoleWithUserInCommandArrayConfig"));
    registerTest(noroleSuite,newTest(&testFindRoleWithUserWrongCommand,"FindRoleWithUserWrongCommand"));
    registerTest(noroleSuite,newTest(&testFindRoleWithWrongUserRightCommand,"FindRoleWithWrongUserRightCommand"));
    registerTest(noroleSuite,newTest(&testFindFirstRoleWithUser,"FindFirstRoleWithUser"));
    
    //Group Tests
    registerTest(noroleSuite,newTest(&testFindRoleWithGroup,"FindRoleWithGroup"));
    registerTest(noroleSuite,newTest(&testFindRoleWithGroupArrayUrc,"FindRoleWithGroupArrayUrc"));
    registerTest(noroleSuite,newTest(&testFindRoleWithGroupArrayConfiguration,"FindRoleWithGroupArrayConfiguration"));
    registerTest(noroleSuite,newTest(&testFindRoleWithGroupWithCommandArrayConfiguration,"FindRoleWithGroupWithCommandArrayConfiguration"));
    registerTest(noroleSuite,newTest(&testFindRoleWithGroupWrongCommand,"FindRoleWithGroupWrongCommand"));
    registerTest(noroleSuite,newTest(&testFindFirstRoleWithGroup,"FindFirstRoleWithGroup"));

    //other Tests
    registerTest(noroleSuite,newTest(&testFindUserRoleNoCommandInConfiguration,"FindUserRoleNoCommandInConfiguration"));
    registerTest(noroleSuite,newTest(&testFindGroupRoleNoCommandInConfiguration,"FindGroupRoleNoCommandInConfiguration"));


    TestSuite *commandsTest = newTestSuite("Testing commands");
    registerTest(commandsTest,newTest(&testQuotedCommand,"QuotedCommand"));

    TestSuite *capableTest = newTestSuite("Testing capable command");
    registerTest(capableTest,newTest(&testCapableFullHelp,"testCapableFullHelp"));
    registerTest(capableTest,newTest(&testCapableCommand,"testCapableCommand"));
    registerTest(capableTest,newTest(&testCapableCommandFilter,"testCapableCommandFilter"));
    registerTest(capableTest,newTest(&testCapableSleep,"testCapableSleep"));
    registerTest(capableTest,newTest(&testCapableDaemon,"testCapableDaemon"));
    registerTest(capableTest,newTest(&testCapableRaw,"testCapableRaw"));
    registerTest(capableTest,newTest(&testCapableVersion,"testCapableVersion"));

    registerTest(capableTest,newTest(&testCapableCommandTcpdumpResult,"testCapableCommandTcpdumpResult"));
    registerTest(capableTest,newTest(&testCapableCommandPingResult,"testCapableCommandPingResult"));
    registerTest(capableTest,newTest(&testCapableCommandCatResult,"testCapableCommandCatResult"));
    registerTest(capableTest,newTest(&testCapableCommandSSHD,"testCapableCommandSSHD"));
    registerTest(capableTest,newTest(&testCapableCommandApache,"testCapableCommandApache"));

    registerTest(capableTest,newTest(&testCapableCommandIncorrect,"testCapableCommandIncorrect"));
    registerTest(capableTest,newTest(&testCapableSleepIncorrect,"testCapableSleepIncorrect"));
    registerTest(capableTest,newTest(&testCapableSyntaxError,"testCapableSyntaxError"));
    registerTest(capableTest,newTest(&testCapableNoCapabilitiesNeeded,"testCapableNoCapabilitiesNeeded"));

    trigger(suite1,1);
    if(!haswriteaccess()){
        printf("You don't have the permission to run these tests\nPlease use sr to run this command\n");
        exit(-1);
    }
    trigger(suite2,1);
    trigger(noroleSuite,1);
    trigger(commandsTest,1);
    trigger(capableTest,1);
    printf("\n=========End of tests============\n");
}