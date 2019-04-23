#include "testScenarios.h"
#include "utilsTests.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stddef.h>
#include <assert.h>
#include <signal.h>

#define USER_CAP_FILE_ROLE "/etc/security/capabilityRole.xml"
#define USER_CAP_FILE_SCENARIO1 "tests/resources/scenario1.xml"
#define USER_CAP_FILE_SERVERPY "tests/resources/server.py"
#define USER_CAP_FILE_BASH "tests/resources/sr.sh"
#define USER_CAP_FILE_TEMP "tests/resources/temp.xml"

void handle_sigint(int sig);

    /*
    char* str_replace(char* string, const char* substr, const char* replacement) {
        char* tok = NULL;
        char* newstr = NULL;
        char* oldstr = NULL;
        int   oldstr_len = 0;
        int   substr_len = 0;
        int   replacement_len = 0;
        newstr = strdup(string);
        substr_len = strlen(substr);
        replacement_len = strlen(replacement);
        if (substr == NULL || replacement == NULL) {
            return newstr;
        }
        while ((tok = strstr(newstr, substr))) {
            oldstr = newstr;
            oldstr_len = strlen(oldstr);
            newstr = (char*)malloc(sizeof(char) * (oldstr_len - substr_len + replacement_len + 1));
            if (newstr == NULL) {
                free(oldstr);
                return NULL;
            }
            memcpy(newstr, oldstr, tok - oldstr);
            memcpy(newstr + (tok - oldstr), replacement, replacement_len);
            memcpy(newstr + (tok - oldstr) + replacement_len, tok + substr_len, oldstr_len - substr_len - (tok - oldstr));
            memset(newstr + oldstr_len - substr_len + replacement_len, 0, 1);
            
        }
        //free(string);
        return newstr;
    }*/

    int copy_file_args(char *old_filename, char  *new_filename,char *arg1,char *arg2,char *arg3)
	{
        char path[PATH_MAX];
		FILE  *ptr_old, *ptr_new;
		ptr_old = fopen(old_filename, "r");
		ptr_new = fopen(new_filename, "w");
		if(ptr_old == NULL)
			return  -1;
		if(ptr_new == NULL){
			fclose(ptr_old);
			return  -1;
		}
		while(fgets(path, sizeof(path)-1, ptr_old)!=NULL){
            if(strstr(path,"%s$1")!=NULL)
                strcpy(path,str_replace(path,"%s$1",arg1));
            if(strstr(path,"%s$2")!=NULL)
                strcpy(path,str_replace(path,"%s$2",arg2));
            if(strstr(path,"%s$3")!=NULL)
                strcpy(path,str_replace(path,"%s$3",arg3));
			if(!feof(ptr_old))
				fputs(path, ptr_new);
			else
				break;
		}
		fclose(ptr_new);
		fclose(ptr_old);
		return  0;
	}



    int before(void){
        char abspath[PATH_MAX];
        realpath(USER_CAP_FILE_TEMP,abspath);
        return copy_file(USER_CAP_FILE_ROLE,abspath);
    }

    int after(void){
        char abspath[PATH_MAX];
        realpath(USER_CAP_FILE_TEMP,abspath);
        return copy_file(abspath,USER_CAP_FILE_ROLE);
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
        char username[32];
        getlogin_r(username,sizeof(username));
        copy_file_args(abspath,USER_CAP_FILE_ROLE,username,serverpy,port);
        readFile(USER_CAP_FILE_ROLE);
/*         char *args[7];
        args[0]="/usr/bin/sr";
        args[1]="-n";
        args[2]="-r";
        args[3]="role1";
        args[4]="-c";
        
        char arg3[2048];
        sprintf(arg3,"\"python %s -p %s\"",serverpy,port);
        args[5] = arg3;
        args[6]=NULL;
        printf("%s ",args[0]);
        printf("%s ",args[1]);
        printf("%s ",args[2]);
        printf("%s ",args[3]);
        printf("%s ",args[4]);
        printf("%s\n",args[5]); */
        char python[1041];
        char *password = getpass("Password:");
        char *rawpassword = escape_char(password,"$");
        char srpath[1000];
        char command[2048];
        realpath(USER_CAP_FILE_BASH,srpath);
        sprintf(python,"'python %s -p %s'",abspath,port);
        sprintf(command,"%s %s %s %s",srpath,rawpassword,"role1",python);
        int infp, outfp;
        char buf[128];
        pid_t p_pid;
        p_pid = popen2(command,&infp,&outfp);
        if (p_pid <=0 ) {
            printf("Failed to run /usr/bin/sr command\n" );
            goto free_rcs;
        }
        
        
        kill(p_pid,SIGTSTP);
        *buf = '\0';
        while(1){
            read(outfp, buf, sizeof(buf));
            printf("%s\n",buf);
            if(strstr(buf,"serving at port") != NULL){
                return_code = 1;
                break;
            }else if(strstr(buf,"denied")!=NULL)break;
            else if(strstr(buf,"failure")!=NULL)break;
            else if(strstr(buf,"failed")!=NULL)break;
            else if(strstr(buf,"Authentication of")!=NULL){
                
                kill(p_pid,SIGCONT);
            }
        }
        kill(p_pid,SIGKILL);
        free_rcs:
        after();
        return return_code;
    }