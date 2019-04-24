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
#include <sys/wait.h>
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
        char abspath[1024];
        realpath(USER_CAP_FILE_SCENARIO1,abspath);
        char serverpy[1024];
        realpath(USER_CAP_FILE_SERVERPY,serverpy);
        char *username = NULL;
        username = get_username(getuid());
        copy_file_args(abspath,USER_CAP_FILE_ROLE,username,serverpy,port);
        char python[1037];
        char *password = getpass("Password:");
        char srpath[1000];
        char command[2060];
        realpath(USER_CAP_FILE_BASH,srpath);
        sprintf(python,"'python %s -p %s'",serverpy,port);
        sprintf(command,"/usr/bin/sr -n -r %s -c %s","role1",python);
        int infp, outfp;
        popen2(command,&infp,&outfp);
        write(infp,password,strlen(password));
        close(infp);
        wait(NULL);
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