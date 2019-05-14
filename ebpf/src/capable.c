#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <getopt.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/capability.h>
#include "sr_constants.h"
#include <signal.h>

#define READ   0
#define WRITE  1

extern char *optarg;
extern int optind, opterr, optopt;

//Internal structure of input parameters
typedef struct _arguments_t {
    char *command;
	int sleep;
	int daemon;
	int kill;
    int version;
    int help;
} arguments_t;

static pid_t p_popen;

/*
Parse input arguments and check arguments validity (in length)
return 0 on success, -1 on unknown arguments, -2 on invalid argument
*/
static int parse_arg(int argc, char **argv, arguments_t *args);

/*
Print Help message
*/
static void print_help(int long_help);

/*
https://dzone.com/articles/simple-popen2-implementation
implementing popen but returning pid and getting in & out pipes asynchronous
in and out pipes can be NULL
*/
static pid_t popen2(const char *command);

/*
Inject file_kern.o to kernel as bpf
return 1 on success, 0 on error occurs (cannot be known)
*/
static int load_bpf(char *file);

/**
 * print line with capabilities
 * Note: this method is optimized
 */
static void print_caps(int pid, int ppid,u_int64_t caps);

/**
 * appends s2 to str with realloc, return new char*
 */
static char *concat(char *str, char *s2);

const char* get_process_name_by_pid(const int pid);

static void killpopen(int signum);

int main(int argc, char **argv)
{

	while(1);
	int return_code = EXIT_FAILURE;
	arguments_t args; //The input args

	if(parse_arg(argc, argv, &args)){
	    fprintf(stderr, "Bad parameter.\n");
		print_help(0);
        goto free_rscs;
	}
	if(args.version){
        printf("RootAsRole V%s\n",RAR_VERSION);
        goto free_rscs;
    }
	if(args.help){
	    print_help(1);
	    return_code = EXIT_SUCCESS;
		goto free_rscs;
	}
	if(args.command == NULL){
		printf("You must specify command\n");
		print_help(0);
		goto free_rscs;
	}
	if(load_bpf(argv[0])){
		perror("The injection into the kernel has failed");
		goto free_rscs;
	}
	p_popen = popen2(args.command);
	pid_t const thisp = getpid();
	int stat_loc;
	if(args.daemon){
		printf("| PID | PPID | CAPABILITY |\n");
		read_trace_pipe();
	}else{
		signal(SIGINT,killpopen);
	}
	if(args.sleep >=0){
		sleep(args.sleep);
		if(args.kill)kill(p_popen,SIGINT);
	}else{
		if(args.kill)kill(p_popen,SIGINT);
		waitpid(p_popen,&stat_loc,0);
	}
	int key;
	u_int64_t value;
	int ppid;
	int res, prev_key = -1;
	printf("Here's all capabilities intercepted :\n");
	printf("| PID\t| PPID\t| NAME\t| CAPABILITIES |\n");
	while(bpf_map_get_next_key(map_fd[0], &prev_key, &key) == 0){
		res = bpf_map_lookup_elem(map_fd[0], &key, &value);
		if(res < 0){
			printf("No value??\n");
        	continue;
		}
		res = bpf_map_lookup_elem(map_fd[1], &key, &ppid);
		if(res < 0){
			printf("No value??\n");
        	continue;
		}
		//if(key==thisp || key=2=p){
			print_caps(key,ppid,value);
		//}
		prev_key=key;
	}
	if(prev_key == -1){
		printf("It seems that there is any capabilities intercepted, do you have the capabilities ?\n");
	}
	free_rscs:
	return return_code;
}

/*
	sleep(15);
Parse input arguments and check arguments validity (in length)
return 0 on success, -1 on unknown arguments, -2 on invalid argument
*/
static int parse_arg(int argc, char **argv, arguments_t *args){
    *args = (arguments_t) {NULL, -1,0, 0, 0, 0};
    
    while(1){
        int option_index = 0;
        int c;
        static struct option long_options[] = {
            {"command", required_argument,	0,   'c'},
			{"sleep",	optional_argument,	0,   's'},
			{"daemon",  no_argument,		0,   'd'},
			{"kill",	no_argument, 		0,	 'k'},
            {"version", no_argument,		0,   'v'},
            {"help",    no_argument,		0,   'h'},
            {0,         0,					0,   0}
        };

        c = getopt_long(argc, argv, "c:s:dkvh", long_options, &option_index);
        if(c == -1) break;
    	char *endptr;
        switch(c){
            case 'c':
                args->command = optarg;
                break;
            case 'h':
                args->help = 1;
                break;
            case 'v':
                args->version = 1;
                break;
			case 'k':
				args->kill = 1;
				break;
			case 'd':
				args->daemon = 1;
				break;
			case 's':
				args->sleep = strtol(optarg, &endptr, 10);
				if (*endptr != '\0')
					return -2;
				break;
            default:
                return -1;
        }
    }
    //If other unknown args
    if (optind < argc) {
        return -1;
    }
    if(args->command != NULL){
        if(strlen(args->command) > 256) return -2;
    }
    return 0;
}

/*
Print Help message
*/
static void print_help(int long_help){
    printf("Usage : capable [ -c command] [-h] [-v]\n");
    if (long_help){
        printf("Get every capabilities used by running program into sandbox.\n");
		printf("If you run this command for daemon please use -s to kill automatically process\n");
        printf("Options:\n");
        printf(" -c, --command=command  launch the command instead of a bash shell.*\n");
		printf(" -s, --sleep=number		specify number of seconds before kill program");
		printf(" -p, --privileged		passing current privileges to program WARNING:Maybe unsafe");
        printf(" -v, --version          show the actual version of RootAsRole\n");
        printf(" -h, --help             print this help and quit.\n");
    }
}

//https://dzone.com/articles/simple-popen2-implementation
//implementing popen but returning pid and getting in & out pipes asynchronous
static pid_t popen2(const char *command)
{
	//int p_stdin[2], p_stdout[2];
	pid_t pid;
	//if (pipe(p_stdin) != 0 || pipe(p_stdout) != 0)
	//	return -1;
	pid = fork();
	if (pid < 0)return pid;
	else if (pid == 0){
		//close(p_stdin[WRITE]);
		//dup2(p_stdin[READ], READ);
		//close(p_stdout[READ]);
		//dup2(p_stdout[WRITE], WRITE);
		char final_command[PATH_MAX];
		sprintf(final_command,"%s",command);
		execl("/bin/sh", "sh", "-c", command, NULL);
		perror("execl");
		exit(1);
	}
	/**if (infp == NULL)
		close(p_stdin[WRITE]);
	else
		*infp = p_stdin[WRITE];
	if (outfp == NULL)
		close(p_stdout[READ]);
	else
		*outfp = p_stdout[READ];
	**/return pid;
}

static int load_bpf(char *file){
	int return_code = -1;
	char *filenameFormat = "%s_kern.o";
	char *filename = malloc(strlen(file)+strlen(filenameFormat)-2+1);
	sprintf(filename,filenameFormat,file);
	if(access(filename,F_OK)){
		if(!access("/usr/lib/RootAsRole/capable_kern.o",F_OK)){
			free(filename);
			filename = "/usr/lib/RootAsRole/capable_kern.o";
		}else{
			free(filename);
			perror("Missing injector in librairies or in current folder");
			goto free_on_error;
		}
	}
	if (load_bpf_file(filename)) {
		if(strlen(bpf_log_buf)>1)
			fprintf(stderr,"%s\n", bpf_log_buf);
		goto free_on_error;
	}
	return_code = 0;
	free_on_error:
	return return_code;
}

static void print_caps(int pid,int ppid,u_int64_t caps) {
	if(caps <= (u_int64_t)0){
		printf("%d\t: No capabilities needed.\n",pid);
		return;
	}
	char *capslist =NULL;
	for (int pos = 0; pos < sizeof(u_int64_t)*8;pos++){ //caps > ((u_int64_t)1 << pos)&&
		if((caps & ((u_int64_t)1 << pos)) != 0){
			char *cap = cap_to_name(pos);
			if(capslist != NULL)capslist=concat(capslist,", ");
			capslist=concat(capslist,cap);
			cap_free(cap);
		}
	}
	printf("| %d\t| %d\t| %s\t| %s |\n",pid,ppid,get_process_name_by_pid(pid),capslist);
	free(capslist);
}

/**
 * appends s2 to str with realloc, return new char*
 */
static char *concat(char *str, char *s2){
        int len = 0;
        char *s = NULL;
        if (str != NULL)
                len = strlen(str);
        len += strlen(s2) + 1 * sizeof(*s2);
        s = realloc(str, len);
        strcat(s, s2);
        return s;
}
static void killpopen(int signum){
	kill(SIGINT,p_popen);
}

const char* get_process_name_by_pid(const int pid)
{
    char* name = (char*)calloc(1024,sizeof(char));
    if(name){
        sprintf(name, "/proc/%d/cmdline",pid);
        FILE* f = fopen(name,"r");
        if(f){
            size_t size;
            size = fread(name, sizeof(char), 1024, f);
            if(size>0){
                if('\n'==name[size-1])
                    name[size-1]='\0';
            }
            fclose(f);
        }
    }
    return name;
}