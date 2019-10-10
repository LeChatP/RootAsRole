import utilsTests as utils,constants
import unittest

class TestScenarios(unittest.TestCase):
    def testScenario1(self):
        port = "79"
        utils.before("scenario1",[utils.getuser()])
        res,code = utils.sr_cmd("-r role1 -c 'python %s -p %s'"% (constants.SC1_FILE_SERVERPY,port),1)
        utils.multipleAssertCommand(res,code,code == 0,res.count("OK")==1)
        utils.after()