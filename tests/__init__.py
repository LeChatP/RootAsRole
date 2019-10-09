import testRoles,constants,utilsTests
import ctypes,unittest
import signal,sys,os
from os import path
libcap = ctypes.cdll.LoadLibrary("libcap.so")

libcap.cap_get_proc.argtypes = []
libcap.cap_get_proc.restype = ctypes.c_void_p
libcap.cap_to_text.restype = ctypes.c_char_p
libcap.cap_free.restype = ctypes.c_void_p
cap_p = libcap.cap_get_proc()
currentcaps = libcap.cap_to_text(cap_p, None)

test_Roles = (testRoles.TestFindUserRoles, testRoles.TestFindGroupRoles, testRoles.TestFindGroupNoRole) 

def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for test_class in test_Roles:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    return suite

def signal_handler(sig, frame):
    if path.exists(constants.TEMP_XML):
        utilsTests.after()
    sys.exit(0)

if __name__ == '__main__':
    if str(currentcaps).find("cap_dac_override") < 0:
        print("please run this with sr")
        exit(-1)
    signal.signal(signal.SIGINT, signal_handler)
    unittest.main()

libcap.cap_free(currentcaps)