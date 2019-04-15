#ifndef TEST_H
#define TEST_H
#include <stdlib.h>
//application Observer design pattern
//TestSuite is subject and Test is Observer

typedef struct __Test{
    int ((*impl)(void)); // TEST
}Test;

int runTest(Test*); // Notifier

void _destroy(Test *element); //destructor
Test* newTest(int ((*pointer)(void))); //constructor

#endif TEST_H