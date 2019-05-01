#include <sys/capability.h>
#include "allTests.h"
#include "testScenarios.h"
#include "testObserver.h"
#include "testRoles.h"
#include "utilsTests.h"

#define USER_CAP_FILE_ROLE "/etc/security/capabilityRole.xml"

static int haswriteaccess(){
    cap_t cap = cap_get_proc();
    cap_flag_value_t v = 0; 
    cap_get_flag(cap, CAP_DAC_OVERRIDE, CAP_PERMITTED, &v);
    return v;
}

int main(void){
    if(!haswriteaccess()){
        printf("You don't have the permission to run these tests\nPlease use sr to run this command\n");
        exit(-1);
    }
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

    trigger(suite1,1);
    trigger(suite2,1);
    trigger(noroleSuite,1);
    printf("\n=========End of tests============\n");
}