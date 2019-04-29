#include "allTests.h"

void printStacktrace(void** callstack);

int registerTest(TestSuite *testSuite, Test *test){
    if(testSuite->size >= MAX_TESTS) return 0;
    testSuite->tests[testSuite->size] = test;
    testSuite->size++;
    return 1;
}

int trigger(TestSuite *suite,int notification){
    void* callstack[128];
    if(notification)printf("\033[0;34m====== running TestSuite %s ======\033[0m\n",suite->name);
    jmp_buf testjmp;
    int return_code = 1;
    if(!setjmp(testjmp)){ //try
        for(int i = 0 ; i<suite->size;i++){
            if(notification)printf("\033[0;34mrunning test %s()\033[0m\n",suite->tests[i]->name);
            if(return_code){
                return_code = ((suite->tests[i]->impl)());
                if((!return_code) && notification) printf("\033[1;31mCe test a échoué\033[0m\n");
            }else{
                if((!(suite->tests[i]->impl)())&& notification) printf("\033[1;31mCe test a échoué\033[0m\n");
            }
        }
    }else // catch
    { 
        printStacktrace(callstack); //print stacktrace
        return 0;
    }
    return return_code;
}

void printStacktrace(void** callstack){
    int i, frames = backtrace(callstack, 128);
    char** strs = backtrace_symbols(callstack, frames);
    for (i = 0; i < frames; ++i) {
        printf("%s\n", strs[i]);
    }
}
TestSuite* newTestSuite(char* name)
{
	TestSuite* element = (TestSuite *) malloc(sizeof(TestSuite));
    element->name = name;
	return element;
}
void destroyTestSuite(TestSuite* element){
    if(element != NULL){
        free(element);
        element = NULL;
    }
}