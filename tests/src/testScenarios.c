#include "testScenarios.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stddef.h>
#include <linux/limits.h>
#include <assert.h>

#define USER_CAP_FILE_ROLE "/etc/security/capabilityRole.xml"
#define USER_CAP_FILE_SCENARIO1 "tests/resources/scenario1.xml"
#define USER_CAP_FILE_SERVERPY "tests/resources/server.py"
#define USER_CAP_FILE_TEMP "tests/resources/temp.xml"

	int copy_file(char *old_filename, char  *new_filename)
	{
        char path[PATH_MAX];
		FILE  *ptr_old, *ptr_new;

		ptr_old = fopen(old_filename, "r");
		ptr_new = fopen(new_filename, "w");

		if(ptr_old == NULL)
			return  -1;

		if(ptr_new == NULL)
		{
			fclose(ptr_old);
			return  -1;
		}

		while(fgets(path, sizeof(path)-1, ptr_old)!=NULL)
		{
			if(!feof(ptr_old))
				fputs(path, ptr_new);
			else
				break;
		}

		fclose(ptr_new);
		fclose(ptr_old);
		return  0;
	}

    void readFile(char* file){
        int c;
        FILE *fff = fopen(file,"r");
        while(1) {
            c = fgetc(fff);
            if( feof(fff) ) {
                break ;
            }
            printf("%c", c);
        }
        fclose(fff);
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
        // firstly, insert configuration for Scenario
        before();
        char abspath[1024];
        realpath(USER_CAP_FILE_SCENARIO1,abspath);
        copy_file(abspath,USER_CAP_FILE_ROLE);

        char path[1035];
        char command[PATH_MAX];
        realpath(USER_CAP_FILE_SERVERPY,abspath);
        sprintf(command,"/usr/bin/sr -n -r role1 -c \"python %s -p 79\"",abspath);
        printf("%s\n",command);
        

        // Open the command for reading.
        FILE *fp = popen(command, "r");
        if (fp == NULL) {
            printf("Failed to run /usr/bin/sr command\n" );
            goto free_rcs;
        }

        //Read the output a line at a time - output it.
        while (fgets(path, sizeof(path)-1, fp) != NULL) {
            printf("%s",path);
        }
        // close
        pclose(fp);
        return_code = 0;

        free_rcs:
        if(fp != NULL){
            fclose(fp);
        }
        if(fp != NULL){
            fclose(fp);
        }
        after();
        exit(return_code);
    }