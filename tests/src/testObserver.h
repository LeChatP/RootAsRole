#ifndef TEST_OBSERVER_H
#define TEST_OBSERVER_H

/**
 * Test if Test type is properly attached to TestSuite
 */
int testTestSubjectAttached(void);

/**
 * Test if Test type collection is properly attached to TestSuite
 */
int testTestSubjectCollection(void);

/**
 * Test if TestSuite reach Max
 */
int testTestSubjectCollectionReachMax(void);

/**
 * Test if Test are executed
 */
int testTestObserverNotified(void);

/**
 * Test if failing Test is properly identified
 */
int testTestObserverWrongNotified(void);

/**
 * Test if all successful tests are identified
 */
int testTestObserversNotified(void);

/**
 * Test if mixing failing and sucessful tests are identified
 */
int testTestObserversWrongNotified(void);

#endif //TEST_OBSERVER_H