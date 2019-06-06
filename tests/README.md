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
Listening output is done by making asynchronous pipes.
In expected case, every test make a backup of configuration file before executing tests are executed, but if tests fail it probably won't recover configuration file, so don't forget to save your last configuration before executing tests.

Every tests aren't optimized or well-coded, and hard-code can be used. Tests can be written with the ugliest code ever but it must test the sr program as expected to be.

## Run tests

### How to build

in root git directory :

```Bash
make build-test
```

### Usage

To run tests you must set in actual configuration a root role with every capabilities that runner (you) has access, present in default configuration, then you can run all tests.

```Bash
make run-test
```

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

### Tests for Capable

**TODO These tests aren't functionning**

* Test that the help message has the right options
* Test capable command without any options, so by default as daemon
* Test if filter is rightly coded **TODO enhance this test**
* Test if sleep options is sleeping the right time
* Test if capable run as daemon with -d option
* Test if -r option is showing raw data
* Test the version of capable *Useful for reminder*
* Test if tcpdump returns CAP_NET_RAW
* Test if ping returns CAP_NET_RAW
* Test if cat /proc/kallsyms returns CAP_SYSLOG, also test if cat has CAP_SYSLOG capability (be warned if this occurs)
* Test if sshd returns CAP_NET_BIND_SERVICE
* Test if apache2ctl returns CAP_NET_BIND_SERVICE and CAP_SYS_PTRACE
* Test if incorrect command showing command not found
* Test if we fill sleep option with a non-number parameter say bad parameter
* Test if syntax error in command showing Usage
* Test when command doesn't need caps showing only CAP_SYS_ADMIN... **TODO enhance this test**

### TO-DO: test every argument of sr

### TO-DO: test for sr in special cases (like sr command in sr command with different capabilities...)

### TO-DO: test for sr with commands uses expected capabilities

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
    int sizeargs = 1;
    char *args[sizeargs] = {get_username(getuid())};
    realpath("tests/resource/example.xml",temppath);
    int copy_result = copy_file_args(temppath,sizeargs,args);
```

This save the actual configuration and copy the scenario1 configuration test to /etc/security/capabilityRole.xml and replace %1$s parameter to username.

Now that we have right configuration to test command, we can listen output of sr command.
To do that, I created a function which automatically fill password when asking in sr and WAIT for ending.

```C
    /**
     * executes sr command and output pid with output pipe
     * and wait for exit
     * Warning : pipe may not listen everything
     */
    void sr_command(char *args, int *outfp);
    /**
     * execute echo in sr command, useful to see if configuration allow a command or not
     * and wait for exit
     */
    void sr_echo_command(char *name, int *outfp);
```

So by example :

```C
    char *name = "hello world!";
    sr_echo_command(name,&outfp);
    char ligne[1024];
    while (read(outfp,ligne,sizeof(ligne)) >= 0) //outfp pipe is not blocked
    {
        if(strstr(ligne,name) != NULL){
            printf("hello world successfully read");
            break;
        }
    }
```

this will execute sr command which execute echo command and verify that the echo has successfully executed.
Finally, your test must return 0 if fail or other if success. Here's the final example :

```C
    int testSRTestExample(){
        char *temppath = NULL;
        realpath("tests/resource/temp.xml",temppath);
        int saving_result = copy_file("/etc/security/capabilityRole.xml",temppath);
        int sizeargs = 1;
        char *args[sizeargs] = {get_username(getuid())};
        realpath("tests/resource/example.xml",temppath);
        int copy_result = copy_file_args(temppath,sizeargs,args);
        char *name = "hello world!";
        sr_echo_command(name,&outfp);
        char ligne[1024];
        while (read(outfp,ligne,sizeof(ligne)) >= 0) //outfp pipe is not blocked
        {
            if(strstr(ligne,name) != NULL){
                printf("hello world successfully read");
                break;
            }
        }
    }

    int main(void){
        TestSuite suite = newTestSuite("My Example Test Suite");
        registerTest(suite,&testSRTestExample,"Example Test");
        return trigger(suite,1); // trigger and verbose tests
    }
```