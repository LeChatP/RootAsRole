#include "utilsTests.h"
#include <signal.h>

    //saving
    static char *password = NULL;

    char *getpassword(void){
        if(password == NULL){
            password = getpass("Password:");
        }
        return password;
    }

    pid_t capable_command(char *args, int *outfp){
        char *command = malloc(strlen(args)+19);
        sprintf(command,"/usr/bin/capable %s",args);
        pid_t r = popen2(command,NULL,outfp);
        free(command);
        return r;
    }

    void sr_command(char *args, int *outfp){
        char *pass = getpassword();
        char *command = malloc(strlen(args)+14);
        sprintf(command,"/usr/bin/sr %s",args);
        int infp;
        popen2(command,&infp,outfp);
        free(command);
        write(infp,pass,strlen(pass));
        close(infp);
        wait(NULL);
    }

    void sr_echo_command(char *name, int *outfp){
        char *pass = getpassword();
        char *command = malloc(strlen(name)+26);
        sprintf(command,"/usr/bin/sr -c 'echo \"%s\"'",name);
        int infp;
        popen2(command,&infp,outfp);
        free(command);
        write(infp,pass,strlen(pass));
        close(infp);
        wait(NULL);
    }

    //https://dzone.com/articles/simple-popen2-implementation
    //implementing popen but returning pid and getting in & out pipes
    pid_t popen2(const char *command, int *infp, int *outfp)
    {
        int p_stdin[2], p_stdout[2];
        pid_t pid;
        if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
            return -1;
        if(fd_set_blocking(p_stdout[READ],0)==0){
            printf("Cannot set non_blocking command output\n");
            return -1;
        }
        pid = fork();
        if (pid < 0)return pid;
        else if (pid == 0){
            close(p_stdin[WRITE]);
            dup2(p_stdin[READ], READ);
            close(p_stdout[READ]);
            dup2(p_stdout[WRITE], WRITE);
            char final_command[PATH_MAX];
            sprintf(final_command,"'%s'",command);
            execl("/bin/bash", "sh", "-c", command, NULL);
            perror("execl");
            exit(1);
        }
        if (infp == NULL)
            close(p_stdin[WRITE]);
        else
            *infp = p_stdin[WRITE];
        if (outfp == NULL)
            close(p_stdout[READ]);
        else
            *outfp = p_stdout[READ];
        return pid;
    }


	int copy_file(char *old_filename, char  *new_filename)
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
			fputs(path, ptr_new);
		}
		fclose(ptr_new);
		fclose(ptr_old);
		return  0;
	}

    int copy_file_args(char *old_filename, char  *new_filename,int nb_args,char **args)
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
            for(int i = 0 ; i < nb_args;i++){
                char *paramFormat = "%%%d$s";
                size_t needed = snprintf(NULL, 0, paramFormat, i)+1;
                char *param = malloc(needed);
                sprintf(param,paramFormat,i+1);
                if(strstr(path,param)!=NULL){
                    strcpy(path,str_replace(path,param,args[i]));
                }
                free(param);
            }
			fputs(path, ptr_new);
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

    char* str_replace(char* str, char* a, char* b)
    {
        int increment = 1;
        int len  = strlen(str);
        int lena = strlen(a), lenb = strlen(b);
        if(strstr(b,a) != NULL)increment = lenb;
        for (char* p = str; (p = strstr(p, a)); p+=increment) {
            if (lena != lenb)
                memmove(p+lenb, p+lena,
                    len - (p - str) + lenb);
            memcpy(p, b, lenb);
        }
        return str;
    }

    int fd_set_blocking(int fd, int blocking) {
        /* Save the current flags */
        int flags = fcntl(fd, F_GETFD);
        if (flags == -1)
            return 0;

        if (blocking)
            flags &= ~O_NONBLOCK;
        else
            flags |= O_NONBLOCK;
        return fcntl(fd, F_SETFL, flags) != -1;
    }
