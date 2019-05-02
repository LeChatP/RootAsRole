#include "testScenarios.h"
#include "utilsTests.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>
#include <stdarg.h>

#define USER_CAP_FILE_ROLE "/etc/security/capabilityRole.xml"
#define USER_CAP_FILE_SCENARIO1 "tests/resources/scenario1.xml"
#define USER_CAP_FILE_SERVERPY "tests/resources/server.py"
#define USER_CAP_FILE_BASH "tests/resources/sr.sh"
#define USER_CAP_FILE_TEMP "tests/resources/temp.xml"

void handle_sigint(int sig);

    int before(void){
        char abspath[PATH_MAX];
        realpath(USER_CAP_FILE_TEMP,abspath);
        return copy_file(USER_CAP_FILE_ROLE,abspath);
    }

    int after(void){
        char abspath[PATH_MAX];
        realpath(USER_CAP_FILE_TEMP,abspath);
        copy_file(abspath,USER_CAP_FILE_ROLE);
        return remove(abspath);
    }

    int testScenario1(void){
        int return_code = 0;
        char *port = "79";
        // firstly, insert configuration for Scenario
        before();
        char abspath[512];
        realpath(USER_CAP_FILE_SCENARIO1,abspath);
        char serverpy[512];
        realpath(USER_CAP_FILE_SERVERPY,serverpy);
        char *username = NULL;
        username = get_username(getuid());
        char *args[3] = {username,serverpy,port};
        copy_file_args(abspath,USER_CAP_FILE_ROLE,3,args);
        char python[2060];
        sprintf(python,"-r role1 -c 'python %s -p %s'",serverpy,port);
        int outfp;
        sr_command(python,&outfp);
        char ligne[1024];
        while (read(outfp,ligne,sizeof(ligne)) > 0)   /*  stop sur fin de fichier ou erreur  */
        {
            if(strstr(ligne,"OK") != NULL){
                return_code = 1;
                break;
            }
        }
        close(outfp);
        after();
        return return_code;
    }