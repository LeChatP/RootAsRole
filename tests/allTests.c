#include "allTests.h"

void printStacktrace(void** callstack);

int registerTest(TestSuite *testSuite, Test *test){
    testSuite->tests[testSuite->size] = test;
    testSuite->size++;
}

int trigger(TestSuite *suite){
    void* callstack[128];
    int result_code = EXIT_SUCCESS;
    jmp_buf testjmp;
    if(!setjmp(testjmp)){ //try
        for(int i = 0 ; i<suite->size &&result_code==EXIT_SUCCESS;i++){
            result_code = (suite->tests[i]->impl)();
        }
    }else // catch
    { 
        printStacktrace(callstack); //print stacktrace
        result_code = EXIT_FAILURE; //return error
    }
    return result_code;
}

void printStacktrace(void** callstack){
    int i, frames = backtrace(callstack, 128);
    char** strs = backtrace_symbols(callstack, frames);
    for (i = 0; i < frames; ++i) {
        printf("%s\n", strs[i]);
    }
}
TestSuite* observerNew()
{
	TestSuite* element = (TestSuite *) malloc(sizeof(TestSuite));
	return element;
}
void destroy(TestSuite* element){
    if(element != NULL){
        free(element);
        element = NULL;
    }
}