#define _GNU_SOURCE
#include "bpf_load.h"
#include "libbpf.h"
#include "sr_constants.h"
#include "sorting.h"
#include "../../src/capabilities.h"
#include <sched.h>
#include <getopt.h>
#include <pwd.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define READ 0
#define WRITE 1
#define MAX_CHECK 3
#define BUFFER_KALLSYM 128
#define HEX 16
#define STACK_SIZE (1024 * 1024)    /* Stack size for cloned child */
//#define DEBUG 1

extern char *optarg;
extern int optind, opterr, optopt;

// Internal structure of input parameters
typedef struct _arguments_t {
	char *command;
	int sleep;
	int daemon;
	int raw;
	int version;
	int help;
} arguments_t;

// keeps process pid, needed for signals and filtering
volatile pid_t p_popen = -1;
uid_t u_popen = -1;
volatile unsigned int nsinode = -1;

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

static int do_clone(void *ptr);

/*
Inject %s_kern.o to kernel as bpf
return 1 on success, 0 on error occurs (cannot be known)
*/
static int load_bpf(char *);

/**
 * print line with capabilities
 * Note: this method is optimized
 */
static void print_ns_caps(unsigned int ns,unsigned int pns, u_int64_t caps);


/**
 * print line with capabilities
 * Note: this method is optimized
 */
static void print_caps(int pid, int ppid,unsigned int uid,unsigned int gid,unsigned int ns,unsigned int pns, u_int64_t caps);

static char* get_caplist(u_int64_t caps);

/**
 * appends s2 to str with realloc, return new char*
 */
static char *concat(char *str, char *s2);

/**
 * Looking for command name
 * return command or path if process does not exist anymore
 */
static char *get_process_name_by_pid(const int pid);

static void killProc(int signum);

static void killpopen(int signum);

static int printResult();

static int printDaemonResult();

static int printNSDaemonResult();

int main(int argc, char **argv)
{
	int return_code = EXIT_FAILURE;
	arguments_t args; // The input args

	if (parse_arg(argc, argv, &args)) {
		fprintf(stderr, "Bad parameter.\n");
		print_help(0);
		goto free_rscs;
	}
	if (args.version) {
		printf("RootAsRole V%s\n", RAR_VERSION);
		goto free_rscs;
	}
	if (args.help) {
		print_help(1);
		return_code = EXIT_SUCCESS;
		goto free_rscs;
	}
	if(!access(KPROBE_EVENTS,W_OK)){
		cap_t cap = cap_get_proc(); 
		cap_flag_value_t cap_sys_admin = 0, cap_dac_override = 0; 
		cap_get_flag(cap, CAP_SYS_ADMIN, CAP_EFFECTIVE, &cap_sys_admin);
		cap_get_flag(cap, CAP_DAC_OVERRIDE, CAP_EFFECTIVE, &cap_dac_override);
		if(!cap_sys_admin && !cap_dac_override){
			printf("Please run this command with CAP_DAC_OVERRIDE and CAP_SYS_ADMIN capability\n");
			goto free_rscs;
		}
		cap_free(cap);
	}
	#ifndef DEBUG
	if (args.command == NULL && load_bpf("capable")) {
		goto free_rscs;
	}else if(load_bpf("nscapable")){
		goto free_rscs;
	}
	#endif
	ignoreKallsyms(); // we remove blacklisted 
	if (args.command != NULL) {
		char *stack;					/* Start of stack buffer */
		char *stackTop;					/* End of stack buffer */
		stack = malloc(STACK_SIZE);
		stackTop = stack + STACK_SIZE;	/* Assume stack grows downward */
		p_popen = clone(do_clone,stackTop,CLONE_NEWPID  | SIGCHLD,(void*)&args);
		char *namespaceFile = "/proc/%d/ns/pid";
		char *namespace = malloc(strlen(namespaceFile)*sizeof(char)+sizeof(pid_t));
		snprintf(namespace,strlen(namespaceFile)*sizeof(char)+sizeof(pid_t),namespaceFile,p_popen);
		struct stat file_stat;  
		int ret;
		ret = fstatat(0,namespace, &file_stat,0);
		free(namespace);
		free(stack);
		if (ret < 0) {
			perror("Unable to access to namespace");
			goto free_rscs;
		}
		nsinode = file_stat.st_ino;
		return_code=0;
			while(wait(0) >= 0) sleep(1);
	} else if (!args.daemon &&
		   args.sleep < 0) { // if there's no command, no daemon and no sleep
		// specified the run as daemon by default
		args.daemon = 1;
	}
	if(args.daemon){ // if command run as daemon then read and print logs from
		// eBPF
		sigset_t set;
		int sig;
		sigemptyset(&set);
		sigaddset(&set, SIGINT);
		sigprocmask(SIG_BLOCK, &set, NULL);
		printf("Collecting capabilities asked to system...\nUse Ctrl+C to print result\n");
		int ret_val = sigwait(&set,&sig);
		if(ret_val == -1)
			perror("sigwait failed");
		if(args.command == NULL)printDaemonResult();
		else printNSDaemonResult();
	} else return_code = printResult();
free_rscs:
	return return_code;
}

static int do_clone(void *ptr){
	arguments_t* args = (arguments_t*) ptr;
	int return_code = -1;
	execl("/bin/sh", "sh", "-c", args->command, NULL);
	return return_code;
}

/*
Parse input arguments and check arguments validity (in length)
return 0 on success, -1 on unknown arguments, -2 on invalid argument
*/
static int parse_arg(int argc, char **argv, arguments_t *args)
{
	*args = (arguments_t){ NULL, -1, 0, 0, 0 };

	while (1) {
		int option_index = 0;
		int c;
		static struct option long_options[] = {
			{ "command", optional_argument, 0, 'c' },
			{ "sleep", optional_argument, 0, 's' },
			{ "daemon", no_argument, 0, 'd' },
			{ "raw", no_argument, 0, 'r'},
			{ "version", no_argument, 0, 'v' },
			{ "help", no_argument, 0, 'h' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "c:s:drnvh", long_options,
				&option_index);
		if (c == -1)
			break;
		char *endptr;
		switch (c) {
		case 'c':
			args->command = optarg;
			break;
		case 'h':
			args->help = 1;
			break;
		case 'v':
			args->version = 1;
			break;
		case 'd':
			args->daemon = 1;
			break;
		case 'r':
			args->raw = 1;
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
	// If other unknown args
	if (optind < argc) {
		return -1;
	}
	if (args->command != NULL) {
		if (strlen(args->command) > 256)
			return -2;
	}
	return 0;
}

/*
Print Help message
*/
static void print_help(int long_help)
{
	printf("Usage : capable [-c command] [-s seconds] [-r | -d] [-h] [-v]\n");
	if (long_help) {
		printf("Get every capabilities used by running programs.\n");
		printf("If you run this command for daemon you can use -s to kill "
		       "automatically process\n");
		printf("Options:\n");
		printf(" -c, --command=command	launch the command and filter result by his pid and childs.\n");
		printf(" -s, --sleep=number	specify number of seconds before kill "
		       "program \n");
		printf(" -d, --daemon		collecting data until killing program printing result at end\n");
		printf(" -r, --raw		show raw results of injection without any filtering\n");
		printf(" -v, --version		show the actual version of RootAsRole\n");
		printf(" -h, --help		print this help and quit.\n");
		printf("Note: .\n");
	}
}

/**
 * signal handler to kill command if executed
 */
static void killProc(int signum)
{
	if (p_popen != -1) {
		kill(p_popen, SIGINT);
		int i = 0;
		while (waitpid(p_popen, NULL, 0) > 0 && i < MAX_CHECK) {
			sleep(1);
			i++;
		}
		if(i >= MAX_CHECK){
			printf("SIGINT wait is timed-out\n");
			if(!kill(p_popen, SIGKILL));
			i = 0;
			while (waitpid(p_popen, NULL, 0) > 0 && i < MAX_CHECK) {
				sleep(1);
				i++;
			}
			if(i >= MAX_CHECK) {
				perror("Cannot kill process... exit");
				exit(-1);
			}
		}
	}else {
		printDaemonResult();
		exit(0);
	}
}
/**
 * signal handler to kill process before exit
 */
static void killpopen(int signum)
{
	killProc(signum);
	exit(0);
}

static int printDaemonResult(){
	int return_value = EXIT_SUCCESS, res;
	u_int64_t value, uid_gid,pnsid_nsid;
	pid_t key, prev_key = -1;
	int ppid = -1;
	printf("\nHere's all capabilities intercepted :\n");
	printf("| UID\t| GID\t| PID\t| PPID\t| NS\t\t| PNS\t\t| NAME\t\t\t| CAPABILITIES\t|\n");
	while (bpf_map_get_next_key(map_fd[1], &prev_key, &key) == 0) { // key are composed by pid and ppid
		res = bpf_map_lookup_elem(map_fd[1], &key,
					&value); // get capabilities
		if (res < 0) {
			printf("No capabilities value for %d ??\n", key);
			prev_key = key;
			return_value = EXIT_FAILURE;
			continue;
		}
		res = bpf_map_lookup_elem(map_fd[2], &key, &uid_gid); // get uid/gid
		if (res < 0) {
			printf("No uid/gid for %d ??\n", key);
			prev_key = key;
			return_value = EXIT_FAILURE;
			continue;
		}
		res = bpf_map_lookup_elem(map_fd[3], &key, &ppid); // get ppid
		if (res < 0) {
			printf("No ppid for %d ??\n", key);
			prev_key = key;
			return_value = EXIT_FAILURE;
			continue;
		}
		res = bpf_map_lookup_elem(map_fd[4], &key, &pnsid_nsid); // get ppid
		if (res < 0) {
			printf("No ns for %d ??\n", key);
			prev_key = key;
			return_value = EXIT_FAILURE;
			continue;
		}
		print_caps(key, ppid, (unsigned int)uid_gid,(unsigned int)(uid_gid >> 32), (unsigned int)pnsid_nsid, (unsigned int)(pnsid_nsid >> 32),
				value); // else print everything
		prev_key = key;
	}
	printf("WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.\n");
	printf("WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant\n");
}
static int printNSDaemonResult(){
	int return_value = EXIT_SUCCESS, res;
	u_int64_t value, parent = 0;
	unsigned int key, prev_key = -1;
	printf("\nHere's all capabilities intercepted :\n");
	printf("| NS\t\t| PNS\t\t| CAPABILITIES\t|\n");
	while (bpf_map_get_next_key(map_fd[1], &prev_key, &key) == 0) { // key are composed by pid and ppid
		res = bpf_map_lookup_elem(map_fd[1], &key,
					&value); // get capabilities
		if (res < 0) {
			printf("No capabilities value for %d ??\n", key);
			prev_key = key;
			return_value = EXIT_FAILURE;
			continue;
		}
		res = bpf_map_lookup_elem(map_fd[2], &key, &parent); // get uid/gid
		print_ns_caps(key, parent,value); // else print everything
		prev_key = key;
	}
	printf("WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.\n");
	printf("WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant\n");
}
/**
 * will print the result with or without filter in function of p_popen > 0
 */
static int printResult()
{
	int return_value = EXIT_SUCCESS;
	u_int64_t value;
	int res;
	unsigned int key, prev_key = -1, parent;
	u_int64_t caps = 0;
	int nbchilds = 1;
	unsigned int *childs = calloc(nbchilds,sizeof(unsigned int));
	childs[0] = nsinode;
	while (bpf_map_get_next_key(map_fd[1], &prev_key, &key) == 0) { // key is inode of namespace
		res = bpf_map_lookup_elem(map_fd[2], &key, &parent); // get ppid
		if (res < 0) {
			prev_key = key;
			continue;
		}
		for(int i = 0;i< nbchilds || childs[i] == key;i++){
			if(childs[i] == parent){ //if parent of actual key is in child list then add key to childs
				nbchilds++;
				childs=(unsigned int *)realloc(childs,nbchilds*sizeof(unsigned int));
				childs[nbchilds-1] = key;
			}
		}
		prev_key = key;
	}
	for(int i = 0 ; i < nbchilds; i++){
		bpf_map_lookup_elem(map_fd[1], &(childs[i]), &value);
		caps |= value;
	}
	free(childs);
	if(caps){
		char *capslist = get_caplist(caps);
		printf("\nHere's all capabilities intercepted for this program :\n%s\n",capslist);
		free(capslist);
		printf("WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.\n");
		printf("WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant\n");
	}else{
		printf("No capabilities are needed for this program.\n");
	}
	printNSDaemonResult();
	return return_value;
}

int static exec_clone(void *command){
	return execl("/bin/sh", "sh", "-c", (char*) command, NULL);
}

// https://dzone.com/articles/simple-popen2-implementation
// implementing popen but returning pid and getting in & out pipes asynchronous
static pid_t popen2(const char *command)
{
	char *stack;                    /* Start of stack buffer */
    char *stackTop;                 /* End of stack buffer */
	stack = malloc(STACK_SIZE);
    stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */
	pid_t pid = clone(exec_clone, stackTop, CLONE_NEWPID,(void*)command);
	return pid;
}

/**
 * will inject JIT ebpf to the kernel
 */
static int load_bpf(char* name)
{
	int return_code = -1;
	char *filename = (char*)malloc(strlen(name)*sizeof(char)+8*sizeof(char));
	sprintf(filename,"%s_kern.o",name);
	if (access(filename, F_OK)) {
		char *buffer = (char*)malloc(strlen(name)*sizeof(char)+30);
		sprintf(buffer,"/usr/lib/RootAsRole/%s_kern.o",name);
		free(filename);
		filename = buffer;
		if (access(buffer, F_OK)) { //if file in library is accessible
			perror("Missing injector in librairies or in current folder");
			goto free_on_error;
		}
	}
	if (load_bpf_file(filename)) {
		if (strlen(bpf_log_buf) > 1)
			fprintf(stderr, "%s\n", bpf_log_buf);
		goto free_on_error;
	}
	return_code = 0;
free_on_error:
	free(filename);
	return return_code;
}

/**
 * print caps logged from map
 */
static void print_caps(int pid, int ppid,unsigned int uid,unsigned int gid,unsigned int ns,unsigned int pns, u_int64_t caps)
{
	char* name = get_process_name_by_pid(pid);
	if (caps <= (u_int64_t)0) {
		
		printf("| %d\t| %d\t| %d\t| %d\t| %u\t| %u\t| %s\t| %s\t|\n", uid,
	       gid, pid, ppid,ns,pns, name,
	       "No capabilities needed");
		return;
	}
	char *capslist = NULL;
	capslist = get_caplist(caps);
	printf("| %d\t| %d\t| %d\t| %d\t| %u\t| %u\t| %s\t| %s\t|\n",uid,
	       gid, pid, ppid,ns,pns, name,
	       capslist);
	free(capslist);
	free(name);
}

static void print_ns_caps(unsigned int ns,unsigned int pns, u_int64_t caps)
{
	if (caps <= (u_int64_t)0) {
		
		printf("| %u\t| %u\t| %s\t|\n", ns,pns,
	       "No capabilities needed");
		return;
	}
	char *capslist = NULL;
	capslist = get_caplist(caps);
	printf("| %u\t| %u\t| %s\t|\n",ns,pns,capslist);
	free(capslist);
}

static char* get_caplist(u_int64_t caps){
	char *capslist = NULL;
	for (int pos = 0; pos < sizeof(u_int64_t) * 8;
	     pos++) { // caps > ((u_int64_t)1 << pos)&&
		if ((caps & ((u_int64_t)1 << pos)) != 0) {
			char *cap = NULL;
			if((cap= cap_to_name(pos)) == NULL){
				printf("Can't recognize %d capability",pos);
				perror("");
			}
			if (capslist != NULL){
				capslist = concat(capslist, ", ");
				capslist = concat(capslist, cap);
			}else{
				capslist = malloc(strlen(cap)*sizeof(char)+1);
				strcpy(capslist,cap);
			}
			cap_free(cap);
		}
	}
	return capslist;
}

/**
 * appends s2 to str with realloc, return new char*
 */
static char *concat(char *str, char *s2)
{
	int len = 0;
	char *s = NULL;
	if (str != NULL)
		len = strlen(str);
	len += strlen(s2) + 1 * sizeof(*s2);
	s = realloc(str, len);
	strcat(s, s2);
	return s;
}

/**
 * Looking for command name
 * return command or path if process does not exist anymore
 */
static char *get_process_name_by_pid(const int pid)
{
	char *name = (char *)calloc(64, sizeof(char));
	if (name) {
		sprintf(name, "/proc/%d/cmdline", pid);
		FILE *f = fopen(name, "r");
		if (f) {
			size_t size;
			size = fread(name, sizeof(char), 61, f);
			if (size > 0) {
				char *limit=strchr(name,' ');
				if(limit != NULL){
					name[limit-name]='\0';
				}else if(name[size-1]=='\n'){
					name[size-1]='\0';
				}else{
					name[size]='.';
					name[size+1]='.';
					name[size+2]='\0';
				}
			}
			fclose(f);
		}
	}
	return name;
}

int ignoreKallsyms(){
	char kall[HEX + 1] = "", line[BUFFER_KALLSYM] = "";
	int k = 0;
	FILE *fp_kallsyms = fopen("/proc/kallsyms","r");
	while(fgets(line,BUFFER_KALLSYM,fp_kallsyms) != NULL){
		if(strchr(line,"_do_fork") != NULL){
			strncpy(line,kall,16);
		}
		unsigned long v = strtol(kall,NULL,HEX);
		if(kall != "") {
			bpf_map_update_elem(map_fd[0],&k,&v,0);
			k++;
			strcpy(line,"");
		}
	}
}