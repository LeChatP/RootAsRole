#include "allTests.h"
#include "testScenarios.h"
#include "testObserver.h"
#include "testRoles.h"
#include "utilsTests.h"

#define USER_CAP_FILE_ROLE "/etc/security/capabilityRole.xml"
#define USER_CAP_FILE_ROOT "tests/resources/root.xml"
#define USER_CAP_FILE_TEMP "tests/resources/temp.xml"

int main(void){
    if(access(USER_CAP_FILE_ROLE,W_OK)!=0){
        printf("You don't have permission to write in %s\ntests cannot continue, stopping\n",USER_CAP_FILE_ROLE);
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

    // restore file permissions after all tests
    char abspath[PATH_MAX];
    realpath(USER_CAP_FILE_TEMP,abspath);
    copy_file(USER_CAP_FILE_ROLE,abspath);
    copy_file_args(USER_CAP_FILE_ROOT,USER_CAP_FILE_ROLE,get_username(getuid()),NULL,NULL);

    int infp, outfp;
    char *password = getpass("Typing a last time the Password:");
    char *commandFormat = "sr -r root -c 'cp %s %s&&chmod o-w %s'";
    char *command = malloc((strlen(commandFormat)-6+strlen(USER_CAP_FILE_TEMP)+strlen(USER_CAP_FILE_ROLE)*2+1)*sizeof(char));
    sprintf(command,commandFormat,USER_CAP_FILE_TEMP,USER_CAP_FILE_ROLE,USER_CAP_FILE_ROLE);
    popen2(command,&infp,&outfp);
    free(command);
    write(infp,password,strlen(password));
    close(infp);
    wait(NULL);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) > 0)   /*  stop sur fin de fichier ou erreur  */
    {
        if(strstr(ligne,"chmod: ") != NULL){
            printf("Cannot restore file permissions, please remove other access to /etc/security/capabilityRole.xml");
        }
        if(strstr(ligne,"cp: ") != NULL){
            printf("Cannot restore file content, please move tests/resources/temp.xml to /etc/security/capabilityRole.xml and remove other write access");
        }
    }
    close(outfp);
}