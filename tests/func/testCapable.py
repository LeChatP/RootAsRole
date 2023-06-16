import utilsTests as utils
import unittest,time,re,subprocess

class TestCapable(unittest.TestCase):
    #Test that the help message has the right option
    def testCapableFullHelp(self):
        res,code = utils.capable_cmd("-h")
        utils.assertCount(res,"Usage :",1)
        utils.assertCount(res,r"-[sdvh],",4)

    #Test capable command without any options, so by default as daemon
    """def testCapableCommand(self):
        res,code = utils.capable_cmd("",1)
        utils.multipleAssertCommand(res,code,code==0)
        utils.assertCount(res,"Collecting capabilities asked to system...",1)
        utils.assertCount(res,"Ctrl+C to print result",1)
        utils.assertCount(res,"| PID",1)
        utils.assertCount(res,"| PPID",1)
        utils.assertCount(res,"| UID",1)
        utils.assertCount(res,"| GID",1)
        utils.assertCount(res,"| NS",1)
        utils.assertCount(res,"| PNS",1)
        utils.assertCount(res,"| NAME",1)
        utils.assertCount(res,"| CAPABILITIES",1)
        utils.assertCount(res,"WARNING: These capabilities aren't mandatory, but they can change the behavior of tested program.",1)
        utils.assertCount(res,"WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant",1)"""

    #Test if filter is rightly coded
    #TODO enhance this test
    def testCapableCommandFilter(self):
        res,code = utils.capable_cmd("-c 'echo bobo'")
        self.assertEqual(code,0,"Assert Code == 0")
        utils.assertCount(res,"cap_sys_admin",1)

    #Test if sleep options is sleeping the right time
    """def testCapableSleep(self):
        start = time.time()
        process = subprocess.Popen(["capable -s 2"],stderr=subprocess.STDOUT,shell=True, stdout=-1)
        returned = str(process.communicate()), 0
        process.wait()
        end = time.time()
        self.assertGreaterEqual(end-start,2,"Test sleeping")

    #Test if capable run as daemon with -d option
    def testCapableDaemon(self):
        res,code = utils.capable_cmd("-d",1)
        self.assertEqual(code,0,"Assert Code == 0")
        nb = len(re.findall(re.compile(r"\| [0-9]+[ ]*\| [0-9]+[ ]*\| [0-9]+[ ]*\| [0-9]+[ ]*\| [0-9]+[ ]*\| [0-9]+[ ]*\| .*[ ]+\| [a-zA-Z_]+[ ]*\|"),res))
        self.assertGreater(nb,0,"Test nb lines")"""

    #Test the version of capable
    #Useful for reminder
    def testCapableVersion(self):
        res,code = utils.capable_cmd("-v")
        self.assertEqual(code,0,"Assert Code == 0")
        utils.assertCount(res,"RootAsRole V.*",1)

    #Test if tcpdump returns CAP_NET_RAW
    def testCapableCommandTcpdumpResult(self):
        res,code = utils.capable_cmd("-c tcpdump")
        self.assertEqual(code,0,"Assert Code == 0")
        utils.multipleAssertCommand(res,code,
            code == 0,
            res.count("cap_dac_override")==1,
            res.count("cap_dac_read_search")==1,
            res.count("cap_net_admin")==1,
            res.count("cap_net_raw")==1,
            res.count("cap_sys_admin")==1)
    #Test if ping returns CAP_NET_RAW
    def testCapableCommandPingResult(self):
        res,code = utils.capable_cmd("-c 'ping 8.8.8.8 -c 1'")
        self.assertEqual(code,0,"Assert Code == 0")
        utils.multipleAssertCommand(res,code,
            res.count("cap_setuid")==1,
            res.count("cap_setpcap")==1, # ping downgrade his capabilities
            res.count("cap_net_raw")==1,
            res.count("cap_sys_admin")==1)

    #Test if cat /proc/kallsyms returns CAP_SYSLOG, also test if cat has CAP_SYSLOG capability (be warned if this occurs)
    def testCapableCommandCatResult(self):
        res,code = utils.capable_cmd("-c 'cat /proc/kallsyms>/dev/null'")
        self.assertEqual(code,0,"Assert Code == 0")
        utils.multipleAssertCommand(res,code,
            res.count("cap_syslog")==1,
            res.count("cap_sys_admin")==1)
    #Test if sshd returns CAP_NET_BIND_SERVICE
    def testCapableCommandSSHD(self):
        res,code = utils.capable_cmd("-c '/usr/sbin/sshd'",5)
        self.assertEqual(code,0,"Assert Code == 0")
        try:
            utils.multipleAssertCommand(res,code,
                res.count("cap_dac_override")==1,
                res.count("cap_dac_read_search")==1,
                res.count("cap_setgid")==1,
                res.count("cap_net_bind_service")==1,
                res.count("cap_sys_resource")==1,
                res.count("cap_sys_admin")==1)
        except AssertionError as e:
            e.args += ("Have-you installed sshd?",0)

    #Test if apache2ctl returns CAP_NET_BIND_SERVICE and CAP_SYS_PTRACE
    def testCapableCommandApache(self):
        res,code = utils.capable_cmd("-c '/usr/sbin/apache2ctl start'",5)
        self.assertEqual(code,0,"Assert Code == 0")
        try:
            utils.multipleAssertCommand(res,code,
                res.count("cap_sys_ptrace")==1,
                res.count("cap_net_bind_service")==1,
                res.count("cap_sys_admin")==1)
        except AssertionError as e:
            e.args += ("Have-you installed apache2?",0)

    #Test if we fill sleep option with a non-number parameter say bad parameter 
    def testCapableSleepIncorrect(self):
        res,code = utils.capable_cmd("-s D")
        utils.multipleAssertCommand(res,code,
            code != 0,
            res.count("Bad parameter.")==1,
            res.count("Usage : ")==1)

    #Test if syntax error in command showing Usage
    def testCapableSyntaxError(self):
        res,code = utils.capable_cmd("-foobar")
        utils.multipleAssertCommand(res,code,
            code != 0,
            res.count("capable: invalid option -- 'f'")==1,
            res.count("Bad parameter.")==1,
            res.count("Usage")==1)