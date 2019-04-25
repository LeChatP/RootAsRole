# Testing RootAsRole Project

## Authors

Ahmad Samer Wazan : ahmad-samer.wazan@irit.fr

Rémi Venant: remi.venant@gmail.com

Guillaume Daumas : guillaume.daumas@univ-tlse3.fr

Eddie Billoir : eddie.billoir@gmail.com

## How Does it works

This part of project is a system to test the sr command, by listening output of sr command and replacing configuration file by testing into default configuration path "/etc/security/capabilitiesRoles.xml" .
This system use simple Observer design pattern style to work : TestSuite is Subject and Test is Observer.

## Run tests

To build the executable simple run in tests/ directory

```Bash
make build
```

the built executable is located at tests/bin/runTests

## List of Actual tests

### Tests of Testing Observer System (intrinsic Test)

* Test if Test type is properly attached to TestSuite
* Test if Test type collection is properly attached to TestSuite
* Test if TestSuite reach Max
* Test if Test are executed
* Test if failing Test is properly identified
* Test if all successful tests are identified
* Test if mixing failing and successful tests are identified

### Tests scenarios from README

* Test Scenario 1

### Tests command without Role specified

* Tests for User capabilities
  * Test if a role is found with a user
  * Test if a role is found with a user in user array in configuration
  * Test if a role is found with a user with command array in configuration
  * Test if a role isn't found with a user and wrong command
  * Test if a role isn't found with a wrong user but right command
  * Test if the first role is found with a user
* Tests for Group
  * Test if a role is found with a group
  * Test if a role is found with a group array for user (Require user executing has more than one group)
  * Test if a role is found with a group array in configuration
  * Test if a role is found for command with a command array in configuration
  * Test if a role isn't found with a wrong command in configuration
  * Test if the first role is found with a group in configuration
* **TO-DO: Tests for User And Group**

## Contributing

To create new tests, just create in convenient location your new functions with him header in header file
Copy-Paste are authorized but functions must test different cases. Refactoring tests are not mandatory (at all) but it mustn't broke any other tests.
To register a suite of test, just initialize TestSuite type
by example:

```C
TestSuite *suite = newTestSuite("my_TestSuite");
```

then you can add your test function pointers to this suite :

```C
registerTest(suite,newTest(&function_pointer_to_my_test,"My Test Name"));
```

Finally, you can execute this suite by calling "trigger()". This function needs a second parameter that activates or not verbose of tests (0 or 1)

```C
trigger(suite,1);
```