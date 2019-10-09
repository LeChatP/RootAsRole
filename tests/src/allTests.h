#ifndef ALL_TESTS_H_INCLUDED
#define ALL_TESTS_H_INCLUDED
#define MAX_TESTS 20
#include "test.h"
#include <setjmp.h>
#include <execinfo.h>
typedef unsigned char ubyte;

//application of Observer design pattern
//TestSuite is subject and Test is Observer

typedef struct __TestSuite {
    ubyte size;
    Test *tests[MAX_TESTS];
    char* name;
} TestSuite;

TestSuite* newTestSuite(char* name); //construct
void destroy(TestSuite* element); //destroy
/**
 * registering Test to pattern
 * @return new size of TestSuite
 */
int registerTest(TestSuite *testSuite, Test *test);
int trigger(TestSuite *suite,int notification);

void destroyTestSuite(TestSuite* element);

#endif // ALL_TESTS_H_INCLUDED