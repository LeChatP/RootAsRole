#ifndef ALL_TESTS_H_INCLUDED
#define ALL_TESTS_H_INCLUDED
#define MAX_TESTS 20
#include "test.h"
#include <setjmp.h>
typedef char byte;

//application of Observer design pattern
//TestSuite is subject and Test is Observer

typedef struct __TestSuite {
    char *name;
    byte size;
    Test *tests[MAX_TESTS]; 
} TestSuite;

TestSuite* newTestSuite(char*); //construct
void destroy(TestSuite* element); //destroy
/**
 * registering Test to pattern
 * @return new size of TestSuite
 */
int registerTest(TestSuite*,Test*);

#endif // ALL_TESTS_H_INCLUDED