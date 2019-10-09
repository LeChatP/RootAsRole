import unittest,getpass
import prctl
from . import utilsTests as utils

class TestFindUserRoles(unittest.TestCase):

    def setUp(self):
        utils.before("testRoles/configuration1",[getpass.getuser()])
        return super().setUp()

    def tearDown(self):
        utils.after()
        return super().tearDown()

    def testFindRoleWithUser(self):
        echo = "role1-user-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code==0,res.count(echo)==1)
        
    def testFindRoleWithUserInUserArrayConfig(self):
        echo = "role2-user-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code==0,res.count(echo)==1)

    def testFindRoleWithUserInCommandArrayConfig(self):
        echo = "role3-user-cmd2"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code==0,res.count(echo)==1)

    def testFindRoleWithUserWrongCommand(self):
        echo = "wrong-command"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code!=0,res.count(echo)==0)

    def testFindRoleWithWrongUserRightCommand(self):
        echo = "role2-foo-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code!=0,res.count(echo)==0)

    def testFindFirstRoleWithUser(self):
        echo = "role1-user-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code==0,res.count("r0le1")==1)

class TestFindGroupRoles(unittest.TestCase):

    def setUp(self):
        utils.before("testRoles/configuration2",utils.getgroups())
        return super().setUp()

    def tearDown(self):
        utils.after()
        return super().tearDown()

    def testFindRoleWithGroup(self):
        echo = "role2-group-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code==0,res.count(echo)==1)

    def testFindRoleWithGroupArrayUrc(self):
        echo = "role1-group-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code==0,res.count(echo)==1)

    def testFindRoleWithGroupArrayConfiguration(self):
        echo = "role2-group-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code==0,res.count(echo)==1)

    def testFindRoleWithGroupWithCommandArrayConfiguration(self):
        echo = "role3-group-cmd2"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code==0,res.count(echo)==1)

    def testFindRoleWithGroupWrongCommand(self):
        echo = "role2-gfoo-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code!=0,res.count(echo)==0)

    def testFindFirstRoleWithGroup(self):
        echo = "role1-group-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code==0,res.count(echo)==1)

class TestFindGroupNoRole(unittest.TestCase):

    def setUp(self):
        utils.before("testRoles/configuration4",["null"]+utils.getgroups())
        return super().setUp()

    def tearDown(self):
        utils.after()
        return super().tearDown()

    def testFindUserRoleNoCommandInConfiguration(self):
        echo = "role1-user-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code!=0,res.count(echo)==0)

    def testFindGroupRoleNoCommandInConfiguration(self):
        echo = "role1-user-cmd"
        res, code = utils.sr_echo_cmd(echo)
        utils.assertCommand(res,code,code!=0,res.count(echo)==0)