# Testing RootAsRole Project

## Authors

Ahmad Samer Wazan : ahmad-samer.wazan@irit.fr

Rémi Venant: remi.venant@gmail.com

Guillaume Daumas : guillaume.daumas@univ-tlse3.fr

Eddie Billoir : eddie.billoir@gmail.com

## How Does it works

This part of project is a system to test the sr command, by listening output of sr command and replacing configuration file by testing into default configuration path "/etc/security/capabilitiesRoles.xml" .
This system use simple Observer design pattern style to work : TestSuite is Subject and Test is Observer.
If you don't know how works Observer design pattern it simple handle the execution of list of functions.
Listening output is done by making asynchronous pipes. You need also to give write access permission of main config (located at /etc/security/capabilityRole.xml) to your user.
Tests are executed as your user, don't forget to save your last configuration before executing tests.

Every tests aren't optimized or well coded, and hardcode can be used. Tests can be written with the ugliest code ever but it must test the sr program as expected to be.

## Run tests

### How to build

```Bash
make build
```

### Usage

the executable is located at tests/bin/runTests, simple run it and see tests running

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
* Specific tests
  * test if match when no command is specified to a user in configuration
  * test if match when no command is specified to a group in configuration
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

### How to write a test with example

To write a test correctly, You have functions in disposition to simplify writing of test, located in utilsTests.h, so you juste need to include this header to begin writing test.
Every tests must return int, which 0 means fail and any other value means success.

The tests needs to be executed with the current user which execute tests. So to test the sr command we need to set up configuration in function of current user and in function of test.
Before replacing configuration file with the testing one, the best practice is to copy the actual configuration to a temporary file, to preserve the real configuration (and the root role, that's important).
To copy/replace file securely, I execute these manipulations as root role of sr. So if copy fail, it means that sr command doesn't work. It means also that the initial configuration to test needs the root role described in default configuration.
It means also that every test configuration.

```C
    /**
     * copy file old_filename to new_filename and replace every arguments by array order
     */
    int copy_file_args(char *old_filename, char  *new_filename,int nb_args, char **args);
    /**
     * copy file old_filename to new_filename
     */
    int copy_file(char *from_file, char *to_file);
```

So in example :

```C
    char *temppath = NULL;
    realpath("tests/resource/temp.xml",temppath);
    int saving_result = copy_file("/etc/security/capabilityRole.xml",temppath);
    char **args = {get_username(getuid())};
    int copy_result = copy_file_args("tests/resource/scenario1.xml",1,args);
```

This save the actual configuration and copy the scenario1 configuration test to /etc/security/capabilityRole.xml and replace %1$s parameter to username.

Now that we have right configuration to test command, we can listen output of sr command.
To do that, I created a function which automatically fill password when asking :

```C
    //exec sr with args return pid and output pipe
    pid_t sr_command(char *args, int *outfp);
```

