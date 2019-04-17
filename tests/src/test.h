#ifndef TEST_H
#define TEST_H
#include <stdlib.h>
#include <stdio.h>
//application Observer design pattern
//TestSuite is subject and Test is Observer

typedef struct __Test{
    int ((*impl)(void)); // TEST
    char* name;
}Test;

int runTest(Test*); // Notifier

void _destroy(Test *element); //destructor
Test* newTest(int ((*pointer)(void)),char* name); //constructor

#endif// TEST_H