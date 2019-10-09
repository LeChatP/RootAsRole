import subprocess,pwd,grp,re,getpass
import os,sys,grp,pwd
from . import constants
password = None

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

def sr_echo_cmd(name:str):
    return sr_cmd("-c 'echo "+name+"'")

def sr_cmd(args:str):
    try:
        return str(subprocess.check_output(["sr "+args],stderr=subprocess.STDOUT,shell=True,input=getpassword())),0
    except subprocess.CalledProcessError as exc:
        return ''.join(exc.output.decode()), exc.returncode

def getgroups() -> list:
    return [grp.getgrgid(i).gr_name for i in os.getgrouplist(pwd.getpwuid(os.geteuid()).pw_name,os.getegid())]

def before(path:str,values:list=[]):
    copyArgsFile(constants.CAP_ROLE_XML,constants.TEMP_XML,[])
    copyArgsFile("tests/resources/"+path+".xml",constants.CAP_ROLE_XML,values)

def after():
    copyArgsFile(constants.TEMP_XML,constants.CAP_ROLE_XML,[])
    os.remove(constants.TEMP_XML)

def assertCommand(res,code,*assertions:bool)->bool:
    i = 1
    argCount = len(assertions)
    if argCount > 0 :
        # Iterate over all the arguments and calculate average
        for elem in assertions :
            try:
                assert elem == True
            except AssertionError as e:
                e.args += ("Assertion "+str(i)+" is False",res.split('\n'),code)
                raise
            i+=1
    return True