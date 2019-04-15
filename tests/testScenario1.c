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
#define USER_CAP_FILE_TEMP "tests/resourcesl/temp.xml"

	int copy_file(char *old_filename, char  *new_filename)
	{
        char path[PATH_MAX];
		FILE  *ptr_old, *ptr_new;

		ptr_old = fopen(old_filename, "rb");
		ptr_new = fopen(new_filename, "wb");

		if(ptr_old != NULL)
			return  -1;

		if(ptr_new != NULL)
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

    int before(void){
        return copy_file(USER_CAP_FILE_ROLE,USER_CAP_FILE_TEMP);
    }

    int after(void){
        return copy_file(USER_CAP_FILE_TEMP,USER_CAP_FILE_ROLE);
    }

    int main(void){
        int return_code = EXIT_FAILURE;
        // firstly, insert configuration for Scenario
        before();
        char testfile[PATH_MAX];
        char cwd[PATH_MAX];
        *cwd = getcwd(cwd, sizeof(cwd));
        sprintf(testfile,"%s/%s",cwd,USER_CAP_FILE_SCENARIO1);
        copy_file(testfile,USER_CAP_FILE_ROLE);
        char path[1035];
        char command[PATH_MAX];
        sprintf(command,"/usr/bin/sr -role role1 -c \"python %s/server.py\"",cwd);

        // Open the command for reading.
        FILE *fp = popen(command, "r");
        if (fp == NULL) {
            printf("Failed to run /usr/bin/sr command\n" );
            goto free_rcs;
        }

        //Read the output a line at a time - output it.
        while (fgets(path, sizeof(path)-1, fp) != NULL) {
            
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
        exit(return_code);
    }