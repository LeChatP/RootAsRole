#include "test.h"
int runTest(Test *element)
{
	return (element->impl)();
}

Test* newTest(int ((*pointer)(void)),char* name){
    Test *test = (Test*) malloc(sizeof(Test));
    test->impl = pointer;
	test->name = name;
    return test;
}
void destroyTest(Test* element)
{
	if (element != NULL) {
		free(element);
		element = NULL;
	}
}
