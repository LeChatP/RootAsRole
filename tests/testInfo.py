import constants,utilsTests as utils
import unittest

class TestInfoUser(unittest.TestCase):

    def setUp(self):
        utils.before("testInfo/infouser",[utils.getuser()])
        return super().setUp()
    
    def tearDown(self):
        utils.after()
        return super().tearDown()
    
    # test sr -i with user configuration
    def testUserInfoArg(self):
        res,code = utils.sr_cmd("-i")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"null",0),
            utils.assertCount(res,"info0",1),
            utils.assertCount(res,"info1",1),
            utils.assertCount(res,"info2",1),
            utils.assertCount(res,"info3",1),
            utils.assertCount(res,"info4",1),
            utils.assertCount(res,"cap_net_raw",2),
            utils.assertCount(res,"with any commands",2),
            utils.assertCount(res,"without any commands",1),
            utils.assertCount(res,"command1",2),
            utils.assertCount(res,"command2",1),
            utils.assertCount(res,"full privileges",3))

    # test sr -i -r role with user configuration 
    def testUserInfoRoleArg(self):
        res,code = utils.sr_cmd("-i -r info1")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"info1",1),
            utils.assertCount(res,"cap_net_raw",1),
            utils.assertCount(res,"any commands",1))
    
    def testUserInfoRoleArg1(self):
        res,code = utils.sr_cmd("-i -r null")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"null",1),
            utils.assertCount(res,r"You can\\+'t use the role",1))
    
    def testUserInfoRoleArg2(self):
        res,code = utils.sr_cmd("-i -r info3")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"without any commands",1))

    # test sr -i -c command with user configuration
    def testUserInfoCommandArg(self):
        res,code = utils.sr_cmd("-i -c command1")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"info2",0),
            utils.assertCount(res,"cap_net_raw",0),
            utils.assertCount(res,"this command",1),
            utils.assertCount(res,"sr -c \"command1\"",1))

    def testUserInfoCommandArg1(self):
        res,code = utils.sr_cmd("-i -c null")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"info0",1),
            utils.assertCount(res,"info1",1))
    
    def testUserInfoCommandArg2(self):
        res,code = utils.sr_cmd("-i -c command3")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"cap_net_raw",1))


    # test sr -i -r role -c command with user configuration
    def testUserInfoRoleCommandArg(self):
        res,code = utils.sr_cmd("-i -r info2 -c command1")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"simplified",1),
            utils.assertCount(res,"sr -c \"command1\"",1),
            utils.assertCount(res,"-r info2",0),
            utils.assertCount(res,"full privileges",1))
    
    def testUserInfoRoleCommandArg1(self):
        res,code = utils.sr_cmd("-i -r null -c null")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,r"you can\\'t execute this command",1))
    
    def testUserInfoRoleCommandArg2(self):
        res,code = utils.sr_cmd("-i -r info0 -c command")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"you can execute \"command\" with command",1),
            utils.assertCount(res,"sr -r \"info0\" -c \"command\"",1))

class TestInfoNoRole(unittest.TestCase):
    # test sr -i -r role -c command with user configuration
    # but with configuration with no matching role
    def testUserInfoCommandArgNoRole(self):
        utils.before("testInfo/infousernorole")
        res, code = utils.sr_cmd("-i -c null")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,r"you can\\'t execute this command",1),
            utils.assertCount(res,"sr -c",0),
            utils.assertCount(res,"roles",0),
            utils.assertCount(res,"null",0))
        utils.after()

    # test sr -i -r role -c command with group configuration
    # but with configuration with no matching role
    def testGroupInfoCommandArgNoRole(self):
        utils.before("testInfo/infogroupnorole")
        res, code = utils.sr_cmd("-i -c null")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,r"you can\\+'t execute this command",1),
            utils.assertCount(res,"sr -c",0),
            utils.assertCount(res,"roles",0),
            utils.assertCount(res,"null",0))
        utils.after()

class TestInfoGroup(unittest.TestCase):
    def setUp(self):
        utils.before("testInfo/infogroup",utils.getgroups())
        return super().setUp()
    
    def tearDown(self):
        utils.after()
        return super().tearDown()
    
    # test sr -i with group configuration
    def testGroupInfoArg(self):
        res,code = utils.sr_cmd("-i")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"null",0),
            utils.assertCount(res,"info0",1),
            utils.assertCount(res,"info1",1),
            utils.assertCount(res,"info2",1),
            utils.assertCount(res,"info3",1),
            utils.assertCount(res,"info4",1),
            utils.assertCount(res,"cap_net_raw",2),
            utils.assertCount(res,"with any commands",2),
            utils.assertCount(res,"without any commands",1),
            utils.assertCount(res,"command1",1),
            utils.assertCount(res,"command2",1),
            utils.assertCount(res,"full privileges",3))

    # test sr -i -r role with group configuration 
    def testGroupInfoRoleArg(self):
        res,code = utils.sr_cmd("-i -r info1")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"info1",1),
            utils.assertCount(res,"cap_net_raw",1),
            utils.assertCount(res,"any commands",1))
    
    def testGroupInfoRoleArg1(self):
        res,code = utils.sr_cmd("-i -r null")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"null",1),
            utils.assertCount(res,r"You can\\+'t use the role",1))
    
    def testGroupInfoRoleArg2(self):
        res,code = utils.sr_cmd("-i -r info3")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"without any commands",1))

    # test sr -i -c command with group configuration
    def testGroupInfoCommandArg(self):
        res,code = utils.sr_cmd("-i -c \"command1\"")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"info2",0),
            utils.assertCount(res,"cap_net_raw",0),
            utils.assertCount(res,"this command",1),
            utils.assertCount(res,"sr -c \"command1\"",1))

    def testGroupInfoCommandArg1(self):
        res,code = utils.sr_cmd("-i -c null")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"info0",1),
            utils.assertCount(res,"info1",1))
    
    def testGroupInfoCommandArg2(self):
        res,code = utils.sr_cmd("-i -c \"command3\"")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"cap_net_raw",1))


    # test sr -i -r role -c command with group configuration
    def testGroupInfoRoleCommandArg(self):
        res,code = utils.sr_cmd("-i -r info2 -c \"command1\"")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"simplified",1),
            utils.assertCount(res,"sr -c \"command1\"",1),
            utils.assertCount(res,"-r info2",0),
            utils.assertCount(res,"full privileges",1))
    
    def testGroupInfoRoleCommandArg1(self):
        res,code = utils.sr_cmd("-i -r null -c null")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,r"you can\\+'t execute this command",1))
    
    def testGroupInfoRoleCommandArg2(self):
        res,code = utils.sr_cmd("-i -r info0 -c command")
        utils.multipleAssertCommand(res,code,
            code==0,
            utils.assertCount(res,"you can execute \"command\" with command",1),
            utils.assertCount(res,"sr -r \"info0\" -c \"command\"",1))
