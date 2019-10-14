# Testing RootAsRole Project

## Authors

Ahmad Samer Wazan : ahmad-samer.wazan@irit.fr

Rémi Venant: remi.venant@gmail.com

Guillaume Daumas : guillaume.daumas@univ-tlse3.fr

Eddie Billoir : eddie.billoir@gmail.com

## How Does it works

This part of project is a system to test the sr command, by listening output of sr command and replacing configuration file by testing into default configuration path "/etc/security/capabilitiesRoles.xml" .
This system is a python program that use libcap.so C library and unittest package

## Run tests

### How to run tests

```Bash
./tests/configure.sh
```

### Usage

To run tests you must set in actual configuration a root role with every capabilities that runner (you) has access, present in default configuration, then you can run all tests. You must be on RootAsRole root folder to run this following command : 

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

To create new tests, choose to create just test in class or create a class for a specific case:

```Python
class TestFindUserRoles(unittest.TestCase):
```

How to create test is very simple, you can find the documentation explain how to do : <https://docs.python.org/fr/3.8/library/unittest.html>
Note that setUp() is executed before each test and tearDown() after
The project has already a bunch of functions that simplify the creation of test. Then you can create one test with only 4 lines. Here is an Example :

```Python
class TestFindUserRoles(unittest.TestCase): ## specify unittest.TestCase class

    def setUp(self): # begin of test
        utils.before("testRoles/configuration1",[getpass.getuser()])
        # this wille copy a preconfigured configuration
        # to current capabilityRole file and will
        # replace %x$s to xth element in list (arg 2)
        return super().setUp()

    def tearDown(self): # end of test
        utils.after() # this will restore the ancient configuration
        return super().tearDown()

    def testFindRoleWithUser(self):
        echo = "role1-user-cmd"
        res, code = utils.sr_echo_cmd(echo)
        # run sr -c 'echo role1-user-cmd'
        # returning output to res and result code to code
        utils.multipleAssertCommand(res,code,code==0,res.count(echo)==1)
        # execute assertions listed on > 2 arg
        # if assertion error then
        # output pertinent informations of assertion error.
```

When you have created your class you must add it to TestSuite in `__init__.py` file.
If your class is uncategorised, you can create new tuple like this :

```Python
test_Roles = (testRoles.TestFindUserRoles, testRoles.TestFindGroupRoles, testRoles.TestFindGroupNoRole) 
#all classes about FindRoles for sr with only -c argument
```

And append this tuple to test suite :

```Python
def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    readTestSuite(loader,test_Roles)
    #append tuple of TestCase to TestSuite
    return suite
```

That's all you can run `__init__.py`.
