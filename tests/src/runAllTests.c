#include "allTests.h"
#include "testScenarios.h"
#include "testObserver.h"
#include "testRoles.h"


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

    trigger(suite1,1);
    trigger(suite2,1);
    trigger(noroleSuite,1);
    printf("\n=====================\n");
}