import subprocess,pwd,grp,re,getpass
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
    groups = [g.gr_name for g in grp.getgrall() if getpass.getuser() in g.gr_mem]
    gid = pwd.getpwnam(getpass.getuser()).pw_gid
    return groups.append(grp.getgrgid(gid).gr_name)

def before(path:str,values:list=[]):
    copyArgsFile("/etc/security/capabilityRole.xml","tests/resources/temp.xml",[])
    copyArgsFile("tests/resources/"+path+".xml","/etc/security/capabilityRole.xml",values)

def after():
    copyArgsFile("tests/resources/temp.xml","/etc/security/capabilityRole.xml",[])

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