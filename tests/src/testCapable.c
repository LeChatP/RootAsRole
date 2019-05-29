#include "testCapable.h"
#include <time.h>
#include <signal.h>

int testCapableFullHelp(){
    int return_code = 0;
    char *name = "";
    int outfp;
    capable_command(name,&outfp);
    char ligne[1024];
    int usage = 0,c = 0,s = 0,d = 0,r = 0,v = 0,h = 0;
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"Usage:") != NULL){
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
    if(usage,c,s,d,r,v,h) return_code = 1;
    return return_code;
}
int testCapableCommand(){
    int return_code = 0;
    char *name = "";
    int outfp;
    capable_command(name,&outfp);
    char ligne[1024];
    int asking = 0,table = 0,warn1 = 0,warn2 = 0;
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
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
    if(asking && table && warn1 && warn2) return_code = 1;
    return return_code;
}
int testCapableCommandFilter(){
    int return_code = 0;
    char *name = "-c \"echo 'bobo'\"";
    int outfp;
    capable_command(name,&outfp);

    char ligne[1024];
    int bobo;
    int cap;
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"bobo") != NULL){
            bobo = 1;
        }
        if(strstr(ligne,"cap_sys_admin") != NULL){
            cap = 1;
        }
    }
    if(cap && bobo) return_code = 1;
    return return_code;
}
int testCapableSleep(){
    int return_code = 0;
    int outfp;
    clock_t t = clock();
    char *pass = getpassword();
    int infp;
    pid_t pid = popen2("/usr/bin/capable -s 2",&infp,outfp);
    write(infp,pass,strlen(pass));
    close(infp);
    wait(NULL);
    clock_t t2 = clock();
    clock_t total = (double)(t2 - t) / CLOCKS_PER_SEC;
    if ((double) total >= (double)2.0) return_code = 1;
    return return_code;
}
int testCapableDaemon(){
    int outfp;
    clock_t t = clock();
    char *pass = getpassword();
    int infp;
    pid_t pid = popen2("/usr/bin/capable -d",&infp,outfp);
    write(infp,pass,strlen(pass));
    close(infp);
    kill(pid,SIGINT);
    wait(NULL);
    return 1;
}
int testCapableRaw(){
    int return_code = 0;
    char *name = "-r";
    int outfp;
    capable_command(*name,outfp);
    char ligne[1024];
    int table = 0, rows = 0;
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"KERNEL") != NULL && strstr(ligne,"PID") && strstr(ligne,"PPID") != NULL && strstr(ligne,"CAP") != NULL){
            table = 1;
        }else if(strlen(ligne) > 40){
            rows++;
        }
    }
    if(table && rows > 0) return_code = 1;
    return return_code;
}
int testCapableVersion(){
    int return_code = 0;
    char *name = "-v";
    int outfp;
    capable_command(*name,outfp);
    char ligne[1024];
    int table = 0, rows = 0;
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"RootAsRole V") !=NULL){
            if(strstr(ligne,"dev-build") != NULL)printf("WARNING: this is a dev build");
            return 1;
        }
    }
    return return_code;
}

int testCapableCommandTcpdumpResult(){
    int return_code = 0;
    char *name = "-c 'tcpdump'";
    int outfp;
    capable_command(*name,outfp);
    char ligne[1024];
    int cnraw = 0, cnadmin = 0, cdoverride = 0, cdreadsearch= 0, csadmin = 0;
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"cap_net_raw") !=NULL)cnraw = 1;
        if(strstr(ligne,"cap_dac_override") !=NULL)cdoverride = 1;
        if(strstr(ligne,"cap_dac_read_search") !=NULL)cdreadsearch = 1;
        if(strstr(ligne,"cap_net_admin") !=NULL)cnadmin = 1;
        if(strstr(ligne,"cap_sys_admin") !=NULL)csadmin = 1;
    }
    if(cnraw&& cnadmin&&cdoverride&&cdreadsearch&&csadmin) return_code = 1;
    return return_code;
}
int testCapableCommandPingResult(){
    int return_code = 0;
    char *name = "-c 'ping'";
    int outfp;
    capable_command(*name,outfp);
    char ligne[1024];
    int cnraw = 0, cdoverride = 0, csadmin = 0;
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"cap_setuid") !=NULL)cnraw = 1;
        if(strstr(ligne,"cap_setpcap") !=NULL)cdoverride = 1;
        if(strstr(ligne,"cap_sys_admin") !=NULL)csadmin = 1;
    }
    if(cnraw&&cdoverride&&csadmin) return_code = 1;
    return return_code;
}
int testCapableCommandCatResult(){
    int return_code = 0;
    char *name = "-c 'cat /proc/kallsyms'";
    int outfp;
    capable_command(*name,outfp);
    char ligne[1024];
    int cnraw = 0, csadmin = 0;
    int nb_kall = 0;
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"cap_syslog") !=NULL)cnraw = 1;
        if(strstr(ligne,"cap_sys_admin") !=NULL)csadmin = 1;
        if(strstr(ligne,"0000000000000000") != NULL) nb_kall ++;
    }
    if(cnraw&&csadmin) return_code = 1;
    if(nb_kall == 0) printf("WARNING: cat has Syslog capablity!");
    return return_code;
}
int testCapableCommandSSHD(){
    int return_code = 0;
    char *name = "-c '/usr/sbin/sshd'";
    int outfp;
    capable_command(*name,outfp);
    char ligne[1024];
    int cnbs = 0;
    int nb_kall = 0;
    while (read(outfp,ligne,sizeof(ligne)) >= 0)
    {
        if(strstr(ligne,"cap_net_bind_service") !=NULL)cnbs = 1;
    }
    if(cnbs) return_code = 1;
    return return_code;
}
int testCapableCommandApache(){
    
}

int testCapableCommandIncorrect(){
    
}
int testCapableSleepIncorrect(){
    
}
int testCapableSyntaxError(){
    
}
int testCapableNoCapabilitiesNeeded(){
    
}
