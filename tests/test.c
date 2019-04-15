#include "test.h"
int runTest(Test *element)
{
	return (element->impl)();
}

Test* newTest(int ((*pointer)(void))){
    Test *test = (Test*) malloc(sizeof(Test));
    test->impl = pointer;
    return test;
}
void destroy(Test* element)
{
	if (element != NULL) {
		free(element);
		element = NULL;
	}
}
