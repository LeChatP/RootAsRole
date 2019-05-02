#include "testObserver.h"
#include "allTests.h"

int anyTest(void);
int anyWrongTest(void);

static int call = 0;
static int wrongcall = 0;

int testTestSubjectAttached(void){
    TestSuite *ts = newTestSuite("");
    registerTest(ts,newTest(&anyTest,""));
    if(ts->size != 1){
        perror("testSuite not inscremented\n");
        return 0;
    }
    if(ts->tests[0] == NULL){
        perror("pointer not set\n");
        return 0;
    }
    return 1;
}
int testTestSubjectCollection(void){
    TestSuite *ts = newTestSuite("");
    registerTest(ts,newTest(&anyTest,""));
    registerTest(ts,newTest(&anyTest,""));
    registerTest(ts,newTest(&anyTest,""));
    if(ts->size != 3){
        return 0;
    }
    if(ts->tests[1] == NULL || ts->tests[2] == NULL){
        printf("pointer not set");
        return 0;
    }
    return 1;
}
int testTestSubjectCollectionReachMax(void){
    TestSuite *ts = newTestSuite("");
    int n = 0;
    while(registerTest(ts,newTest(&anyTest,"")))if(n++ > MAX_TESTS) return 0;
    if(ts->size != MAX_TESTS){
        return 0;
    }
    if(ts->tests[MAX_TESTS-1] == NULL){
        printf("pointer not set at end\n");
        return 0;
    }
    return 1;
}

int testTestObserverNotified(void){
    call = 0;
    wrongcall = 0;
    TestSuite *ts = newTestSuite("");
    registerTest(ts,newTest(&anyTest,""));
    if(!trigger(ts,0)){
        printf("there was an error in trigger\n");
        return 0;
    }
    if(call != 1){
        printf("anyTest wasn't call\n");
        return 0;
    }
    return 1;
}
int testTestObserverWrongNotified(void){
    call = 0;
    wrongcall = 0;
    TestSuite *ts = newTestSuite("");
    registerTest(ts,newTest(&anyWrongTest,""));
    if(trigger(ts,0)){
        printf("excepting false\n");
        return 0;
    }
    if(wrongcall != 1){
        printf("anyWrongTest wasn't call\n");
        return 0;
    }
    return 1;
}
int testTestObserversNotified(void){
    call = 0;
    wrongcall = 0;
    TestSuite *ts = newTestSuite("");
    registerTest(ts,newTest(&anyTest,""));
    registerTest(ts,newTest(&anyTest,""));
    registerTest(ts,newTest(&anyTest,""));
    if(!trigger(ts,0)){
        printf("there was an error in trigger\n");
        return 0;
    }
    if(call != 3){
        printf("anyTest wasn't call multiple times\n");
        return 0;
    }
    return 1;
}
int testTestObserversWrongNotified(void){
    call = 0;
    wrongcall = 0;
    TestSuite *ts = newTestSuite("");
    registerTest(ts,newTest(&anyTest,""));
    registerTest(ts,newTest(&anyWrongTest,""));
    registerTest(ts,newTest(&anyTest,""));
    if(trigger(ts,0)){
        printf("excepting false\n");
        return 0;
    }
    if(wrongcall != 1){
        printf("anyWrongTest wasn't call\n");
        return 0;
    }
    if(call != 2){
        printf("anyTest wasn't call 2 times\n");
        return 0;
    }
    return 1;
}
int anyTest(void){
    call++;
    return 1;
}
int anyWrongTest(void){
    wrongcall++;
    return 0;
}