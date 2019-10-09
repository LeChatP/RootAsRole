#include "testCapable.h"
#include <time.h>
#include <signal.h>

#define CONCAT_STR(a,b) a b

int testCapableFullHelp(){
    int return_code = 0;
    char *name = "-h";
    int outfp = 0;
    capable_command(name,&outfp);
    wait(NULL);
    char ligne[1024];
    int usage = 0,c = 0,s = 0,d = 0,r = 0,v = 0,h = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"Usage :") != NULL){
            usage = 1;
        }
        if(strstr(ligne,"-c") !=NULL){
            c = 1;
        }
        if(strstr(ligne,"-s") !=NULL){
            s = 1;
        }
        if(strstr(ligne,"-d") !=NULL){
            d = 1;
        }
        if(strstr(ligne,"-r") !=NULL){
            r = 1;
        }
        if(strstr(ligne,"-v") !=NULL){
            v = 1;
        }
        if(strstr(ligne,"-h") !=NULL){
            h = 1;
        }
    }
    close(outfp);
    if(usage&&c&&s&&d&&r&&v&&h) return_code = 1;
    else printf("usage %d c %d s %d d %d r %d v %d h %d\n",usage,c,s,d,r,v,h);
    return return_code;
}
int testCapableCommand(){
    int return_code = 0;
    char *name = "";
    int outfp = 0;
    pid_t c = capable_command(name,&outfp);
    sleep(1);
    kill(c,SIGINT);
    kill(c,SIGINT);
    wait(NULL);
    int status;
    char ligne[1024];
    int asking = 0,table = 0,warn1 = 0,warn2 = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"Collecting capabilities asked to system...") != NULL){
            asking = 1;
        }
        if(strstr(ligne,"UID") != NULL && strstr(ligne,"GID") != NULL && strstr(ligne,"PID") != NULL && strstr(ligne,"NAME") != NULL && strstr(ligne,"CAPABILITIES")!=NULL){
            table = 1;
        }
        if(strstr(ligne,"WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.") !=NULL){
            warn1 = 1;
        }
        if(strstr(ligne,"WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant") !=NULL){
            warn2 = 1;
        }
    }
    close(outfp);
    if(asking && table && warn1 && warn2) return_code = 1;
    return return_code;
}
int testCapableCommandFilter(){
    int return_code = 0;
    char *name = "-c \"echo 'bobo'\"";
    int outfp = 0;
    capable_command(name,&outfp);
    wait(NULL);
    char ligne[1024];
    int bobo;
    int cap;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        
        if(strstr(ligne,"bobo") != NULL){
            bobo = 1;
        }
        if(strstr(ligne,"cap_sys_admin") != NULL){
            cap = 1;
        }
    }
    close(outfp);
    if(cap && bobo) return_code = 1;
    return return_code;
}
int testCapableSleep(){
    int return_code = 0;
    clock_t t = clock();
    printf("testing sleeping 2 sec\n");
    system("/usr/bin/capable -s 2");
    clock_t t2 = clock();
    double total = (double)(t2 - t) /100;
    printf("time elapsed : %lf\n", total);
    if ((double) total >= (double)2.0) return_code = 1;
    return return_code;
}
int testCapableDaemon(){
    int outfp = 0;
    clock_t t = clock();
    char *pass = getpassword();
    int infp = 0;
    pid_t pid = popen2("/usr/bin/capable -d",&infp,&outfp,1);
    write(infp,pass,strlen(pass));
    close(infp);
    close(outfp);
    kill(pid,SIGINT);
    wait(NULL);
    return 1;
}
int testCapableRaw(){
    int return_code = 0;
    char *name = "-r";
    int outfp = 0;
    printf("sleep 2 seconds to listen capabilities asked\n");
    pid_t c = capable_command(name,&outfp);
    sleep(2);
    kill(c, SIGINT);
    wait(NULL);
    char ligne[1024];
    int table = 0, rows = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"KERNEL") != NULL && strstr(ligne,"PID") && strstr(ligne,"PPID") != NULL && strstr(ligne,"CAP") != NULL){
            table = 1;
        }else if(strlen(ligne) > 40){
            rows++;
        }
    }
    close(outfp);
    if(table && rows > 0) return_code = 1;
    return return_code;
}
int testCapableVersion(){
    int return_code = 0;
    char *name = "-v";
    int outfp = 0;
    capable_command(name,&outfp);
    wait(NULL);
    char ligne[1024];
    int table = 0, rows = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"RootAsRole V") !=NULL){
            if(strstr(ligne,"dev-build") != NULL)printf("WARNING: this is a dev build\n");
            return 1;
        }
    }
    close(outfp);
    return return_code;
}

int testCapableCommandTcpdumpResult(){
    int return_code = 0;
    char *name = "-c 'tcpdump'";
    int outfp = 0;
    pid_t c = capable_command(name,&outfp);
    sleep(1);
    kill(c, SIGINT);
    wait(NULL);
    char ligne[1024];
    int cnraw = 0, csadmin = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"cap_net_raw") !=NULL)cnraw = 1;
        if(strstr(ligne,"cap_sys_admin") !=NULL)csadmin = 1;
    }
    close(outfp);
    if(cnraw&&csadmin) return_code = 1;
    return return_code;
}
int testCapableCommandPingResult(){
    int return_code = 0;
    char *name = "-c 'ping 8.8.8.8 -c 1'";
    int outfp = 0;
    pid_t c = capable_command(name,&outfp);
    sleep(1);
    kill(c,SIGINT);
    waitpid(c,NULL,0);
    char ligne[1024];
    int cnraw = 0, cdoverride = 0, csadmin = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        printf("%s\n",ligne);
        if(strstr(ligne,"cap_setpcap") !=NULL)cdoverride = 1;
        if(strstr(ligne,"cap_sys_admin") !=NULL)csadmin = 1;
    }
    close(outfp);
    if(cnraw&&cdoverride&&csadmin) return_code = 1;
    return return_code;
}
int testCapableCommandCatResult(){
    int return_code = 0;
    char *name = "-c 'cat /proc/kallsyms > /dev/null'"; // need output for cat otherwise program stuck
    int outfp = 0;
    pid_t c = capable_command(name,&outfp);
    waitpid( c, NULL,0);
    char ligne[1024];
    int cnraw = 0, csadmin = 0;
    int nb_kall = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >=0)
    {
        printf("%s\n",ligne);
        if(strstr(ligne,"cap_syslog") !=NULL)cnraw = 1;
        if(strstr(ligne,"cap_sys_admin") !=NULL)csadmin = 1;
    }
    close(outfp);
    if(cnraw&&csadmin) return_code = 1;
    return return_code;
}
int testCapableCommandSSHD(){
    int return_code = 0;
    char *name = "-c '/usr/sbin/sshd'";
    int outfp = 0;
    capable_command(name,&outfp);
    wait(NULL);
    char ligne[1024];
    int cnbs = 0;
    int nb_kall = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"cap_net_bind_service") !=NULL)cnbs = 1;
    }
    close(outfp);
    if(cnbs) return_code = 1;
    return return_code;
}
int testCapableCommandApache(){
    int return_code = 0;
    char *name = "-c '/usr/sbin/apache2ctl'";
    int outfp = 0;
    capable_command(name,&outfp);
    wait(NULL);
    char ligne[1024];
    int cnbs = 0, cspt = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"cap_net_bind_service") !=NULL)cnbs = 1;
        if(strstr(ligne,"cap_sys_ptrace") != NULL) cspt = 1;
    }
    close(outfp);
    if(cnbs && cspt) return_code = 1;
    return return_code;
}

int testCapableCommandIncorrect(){
    int return_code = 0;
    char *name = "-c 'CapaBle'";
    int outfp = 0;
    capable_command(name,&outfp);
    wait(NULL);
    char ligne[1024];
    int notfound = 0, param = 0, usage = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"CapaBle: not found") !=NULL)notfound = 1;
        if(strstr(ligne,"Bad parameter") != NULL) param = 1;
        if(strstr(ligne,"Usage : ") != NULL) usage = 1;
    }
    close(outfp);
    if(notfound && param && usage) return_code = 1;
    return return_code;
}
int testCapableSleepIncorrect(){
    int return_code = 0;
    char *name = "-s 3d";
    int outfp = 0;
    capable_command(name,&outfp);
    wait(NULL);
    char ligne[1024];
    int  param = 0, usage = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"Bad parameter") != NULL) param = 1;
        if(strstr(ligne,"Usage : ") != NULL) usage = 1;
    }
    close(outfp);
    if(param && usage) return_code = 1;
    return return_code;
}
int testCapableSyntaxError(){
    int return_code = 0;
    char *name = "-foo bar";
    int outfp = 0;
    capable_command(name,&outfp);
    wait(NULL);
    char ligne[1024];
    int invalid = 0, param = 0, usage = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"capable: invalid option -- 'f'") != NULL) invalid = 1;
        if(strstr(ligne,"Bad parameter") != NULL) param = 1;
        if(strstr(ligne,"Usage : ") != NULL) usage = 1;
    }
    close(outfp);
    if(invalid && param && usage) return_code = 1;
    return return_code;
}
int testCapableNoCapabilitiesNeeded(){
    int return_code = 0;
    char *name = "-c echo";
    int outfp = 0;
    capable_command(name,&outfp);
    wait(NULL);
    char ligne[1024];
    int csa = 0, multiplecaps = 0;
    while (read(outfp,ligne,sizeof(ligne)-1) >= 0)
    {
        if(strstr(ligne,"cap_sys_admin") != NULL) csa = 1;
        if(strstr(ligne,", ") != NULL) multiplecaps = 1;
    }
    close(outfp);
    if(csa&&!multiplecaps) return_code = 1;
    return return_code;
}
