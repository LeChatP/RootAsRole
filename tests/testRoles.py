import unittest,getpass
import prctl
import subprocess,subprocess,pwd,grp,os,sys,re
import ctypes

libcap = ctypes.cdll.LoadLibrary("libcap.so")

libcap.cap_get_proc.argtypes = []
libcap.cap_get_proc.restype = ctypes.c_void_p
libcap.cap_to_text.restype = ctypes.c_char_p
libcap.cap_free.restype = ctypes.c_void_p
cap_p = libcap.cap_get_proc()
currentcaps = libcap.cap_to_text(cap_p, None)

def copyArgsFile(source:str,dest:str,values:list=[]):
    f = open(source,"r")
    cap = open(dest,"w")
    content = f.read()
    f.close()
    if(len(values)>0):
        for i in range(0,len(values)):
            content = re.sub("%"+str(i+1)+"\$s",values[i],content)
    cap.write(content)
    cap.close()

password = None
def getpassword():
    global password
    if(password == None):
        password = getpass.getpass(prompt='Password: ', stream=None).encode(encoding="utf8")
    return password

def capable_cmd(str:list):
    try:
        return str(subprocess.check_output(["capable"]+str,stderr=subprocess.STDOUT,shell=True).output), 0
    except subprocess.CalledProcessError as exc:
        return ''.join(exc.output.decode()), exc.returncode

def sr_echo_cmd(str:str):
    return sr_cmd("-c 'echo "+str+"'")

def sr_cmd(str:str):
    try:
        return str(subprocess.check_output(["sr "+str],stderr=subprocess.STDOUT,shell=True,input=getpassword())),0
    except subprocess.CalledProcessError as exc:
        return ''.join(exc.output.decode()), exc.returncode

def getgroups() -> list:
    groups = [g.gr_name for g in grp.getgrall() if getpass.getuser() in g.gr_mem]
    gid = pwd.getpwnam(getpass.getuser()).pw_gid
    return groups.append(grp.getgrgid(gid).gr_name)

def before(path:str,values:list=[]):
    copyArgsFile("/etc/security/capabilityRole.xml","tests/resources/temp.xml",[])
    copyArgsFile("tests/resources/"+path+".xml","/etc/security/capabilityRole.xml",values)

def after():
    copyArgsFile("tests/resources/temp.xml","/etc/security/capabilityRole.xml",[])

class TestFindUserRoles(unittest.TestCase):

    def setUp(self):
        before("testRoles/configuration1",[getpass.getuser()])
        return super().setUp()

    def tearDown(self):
        after()
        return super().tearDown()

    def testFindRoleWithUser(self):
        echo = "role1-user-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise
        
    def testFindRoleWithUserInUserArrayConfig(self):
        echo = "role2-user-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindRoleWithUserInCommandArrayConfig(self):
        echo = "role3-user-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindRoleWithUserWrongCommand(self):
        echo = "wrong-command"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==0
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindRoleWithWrongUserRightCommand(self):
        echo = "role2-foo-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==0
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindFirstRoleWithUser(self):
        echo = "role1-group-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

class TestFindGroupRoles(unittest.TestCase):

    def setUp(self):
        before("testRoles/configuration2",[grp.getgrgid(i).gr_name for i in os.getgrouplist(pwd.getpwuid(os.geteuid()).pw_name,os.getegid())])
        return super().setUp()

    def tearDown(self):
        after()
        return super().tearDown()

    def testFindRoleWithGroup(self):
        echo = "role2-group-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindRoleWithGroupArrayUrc(self):
        echo = "role1-group-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindRoleWithGroupArrayConfiguration(self):
        echo = "role2-group-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindRoleWithGroupWithCommandArrayConfiguration(self):
        echo = "role3-group-cmd2"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindRoleWithGroupWrongCommand(self):
        echo = "role2-gfoo-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindFirstRoleWithGroup(self):
        echo = "role1-group-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==1
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

class TestGroupNoRole(unittest.TestCase):

    def setUp(self):
        before("testRoles/configuration4",[grp.getgrgid(i).gr_name for i in [0]+os.getgrouplist(pwd.getpwuid(os.geteuid()).pw_name,os.getegid())])
        return super().setUp()

    def tearDown(self):
        after()
        return super().tearDown()

    def testFindUserRoleNoCommandInConfiguration(self):
        echo = "role1-user-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==0
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

    def testFindGroupRoleNoCommandInConfiguration(self):
        echo = "role1-user-cmd"
        res, code = sr_echo_cmd(echo)
        try:
            assert res.count(echo)==0
        except AssertionError as e:
            e.args += (res.split('\n'),code)
            raise

if __name__ == '__main__':
    if str(currentcaps).find("cap_dac_override") < 0:
        print("please run this with sr")
        exit(-1)
    unittest.main()

libcap.cap_free(currentcaps)