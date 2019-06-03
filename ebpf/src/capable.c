#include "bpf_load.h"
#include "libbpf.h"
#include "sr_constants.h"
#include "sorting.h"
#include "../../src/capabilities.h"
#include <getopt.h>
#include <pwd.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/prctl.h>

#define READ 0
#define WRITE 1
#define MAX_CHECK 5

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
volatile sig_atomic_t stop;

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
static void print_caps(int pid, int ppid, u_int64_t uid, u_int64_t caps);

static char* get_caplist(u_int64_t caps);

static uid_t set_uid();

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
	if (load_bpf(argv[0])) {
		goto free_rscs;
	}
	if (args.command != NULL) {
		if(u_popen > 0)p_popen = popen2(args.command);
		else {
			goto free_rscs;
		}
	} else if (!args.daemon &&
		   args.sleep < 0) { // if there's no command, no daemon and no sleep
		// specified the run as daemon by default
		args.daemon = 1;
	}
	if (args.raw) { // if command run as daemon then read and print logs from
		// eBPF
		signal(SIGINT,
		       killpopen); // if sigint then kill command before exit
		printf("| KERNEL\t\t\t\t\t   | PID\t| PPID\t| CAP\t|\n");
		read_trace_pipe(); // print logs until kill
		printf("an error has occured\n");
		goto free_rscs;
	} else if(args.daemon){
		signal(SIGINT,killProc);
		printf("Collecting capabilities asked to system...\nUse Ctrl+C to print result\n");
		while (!stop)
        	pause();
	} else {
		signal(SIGINT,
		       killProc); // kill only command if SIGINT to continue program and
			// print result
		if (args.sleep >=
		    0) { // if sleep argument is specified the sleep before kill
			sleep(args.sleep);
			killProc(0);
		} else if (p_popen >=
			   0) { // if user don't specify command then it goes
			// directly to result
			waitpid(p_popen, NULL, 0);
		}
	}
	return_code = printResult();
free_rscs:
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
		stop = 1;
	}else {
		stop = 1;
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
/**
 * will print the result with or without filter in function of p_popen > 0
 */
static int printResult()
{
	int return_value = EXIT_SUCCESS;
	u_int64_t value, uid_gid;
	pid_t key, prev_key = -1;
	int res;
	if(p_popen ==-1){
		int ppid = -1;
		printf("\nHere's all capabilities intercepted :\n");
		printf("| UID\t| GID\t| PID\t| PPID\t| NAME\t\t\t| CAPABILITIES\t|\n");
		while (bpf_map_get_next_key(map_fd[0], &prev_key, &key) == 0) { // key are composed by pid and ppid
			res = bpf_map_lookup_elem(map_fd[0], &key,
						&value); // get capabilities
			if (res < 0) {
				printf("No capabilities value for %d ??\n", key);
				return_value = EXIT_FAILURE;
				continue;
			}
			res = bpf_map_lookup_elem(map_fd[1], &key, &uid_gid); // get uid/gid
			if (res < 0) {
				printf("No uid/gid for %d ??\n", key);
				return_value = EXIT_FAILURE;
				continue;
			}
			res = bpf_map_lookup_elem(map_fd[2], &key, &ppid); // get uid/gid
			if (res < 0) {
				printf("No ppid for %d ??\n", key);
				return_value = EXIT_FAILURE;
				continue;
			}
			print_caps(key, ppid, uid_gid,
					value); // else print everything
			prev_key = key;
		}
		printf("WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.\n");
		printf("WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant\n");
	}else {
		u_int64_t caps = 0;
		int array_size = 1;
		pid_t ppid;
		pid_t *puids = calloc(array_size,sizeof(pid_t*));
		SortedPids *all = NULL;
		puids[0] = p_popen;
		while (bpf_map_get_next_key(map_fd[0], &prev_key, &key) == 0) { // get all process with this uid store all in sorted array
			res = bpf_map_lookup_elem(map_fd[1], &key,
						&uid_gid);
			if (res < 0) {
				printf("No capabilities value for %d ??\n", key);
				return_value = EXIT_FAILURE;
				continue;
			}
			res = bpf_map_lookup_elem(map_fd[2], &key,
						&ppid);
			if (res < 0) {
				printf("No capabilities value for %d ??\n", key);
				return_value = EXIT_FAILURE;
				continue;
			}
			if((int)uid_gid == u_popen){
				array_size++;
				if((puids = realloc(puids,array_size*sizeof(pid_t*))) == NULL){
					perror("unable to store pids");
				}
				puids[array_size-1] = key;
			}
			append_pid(all,key,ppid);
			prev_key = key;
		}
		prev_key = -1;
		int result_size = array_size;
		pid_t *result = calloc(result_size+1,sizeof(pid_t));
		memcpy(result,puids,sizeof(pid_t)*result_size+1);
		for(int i = 0 ; i< array_size ; i++){
			get_childs(all,puids[i],result,&result_size); // get all childs of all puids
		}
		free(puids);
		for(int i = 0 ; i<result_size;i++){ // retrieve all capabilities from all childs
				res = bpf_map_lookup_elem(map_fd[0], &result[i],
				&value); // lookup capabilities
				caps |= value;
		}
		free(result);
		if(caps == 0)
			printf("No capabilities needed for this program.\n");
		else{
			char *capslist = NULL;
			capslist = get_caplist(caps);
			printf("\nHere's all capabilities intercepted for this program :\n%s\n",capslist);
			free(capslist);
			printf("WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.\n");
			printf("WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant\n");
		}
	}
		
	return return_value;
}
/**
 * retrieve capable user, otherwise, use non-defined uid in the range of scripts uids
 * from https://refspecs.linuxfoundation.org/LSB_2.1.0/LSB-generic/LSB-generic/uidrange.html
 */
static uid_t set_uid(){
	int return_value = 0;
	struct passwd *capasswd;
	if((capasswd = getpwnam("capable")) != NULL){
		if(!setuid(capasswd->pw_uid)) return_value = capasswd->pw_uid;
		else perror("an error occur");
	}else{
		perror("capable user isn't exist, please reinstall capable tool");
	}
	return return_value;
}

// https://dzone.com/articles/simple-popen2-implementation
// implementing popen but returning pid and getting in & out pipes asynchronous
static pid_t popen2(const char *command)
{
	int pipefd[2];
	if(pipe(pipefd)){
		perror("cannot create pipe");
		return 0;
	}
	pid_t pid = fork();
	if (pid == 0) {
		if(close(pipefd[0])){
			perror("child cannot close reading pipe");
			exit(1);
		}
		uid_t uid =set_uid();
		if(write(pipefd[1],&uid,sizeof(uid_t)) < 0){
			perror("child cannot send uid to father");
			exit(1);
		}
		if(close(pipefd[1])){
			perror("child cannot close writing pipe");
			exit(1);
		}
		char final_command[PATH_MAX];
		sprintf(final_command, "%s", command);
		execl("/bin/sh", "sh", "-c", command, NULL);
		perror("execl");
		exit(1);
	}else{ //parent
		if(close(pipefd[1])){
			perror("father cannot close writing pipe");
			exit(1);
		}
		if(read(pipefd[0],&u_popen,sizeof(uid_t))<0){
			perror("father cannot read uid");
			exit(1);
		}
		if(close(pipefd[0])){
			perror("father cannot close reading pipe");
			exit(1);
		}
	}
	return pid;
}

/**
 * will inject JIT ebpf to the kernel
 */
static int load_bpf(char *file)
{
	int return_code = -1;
	char *filenameFormat = "%s_kern.o";
	char *filename = malloc(strlen(file) + strlen(filenameFormat) - 2 + 1);
	sprintf(filename, filenameFormat, file);
	if (access(filename, F_OK)) {
		if (!access("/usr/lib/RootAsRole/capable_kern.o", F_OK)) { //if file in library is accessible
			free(filename); // then free actual path to malloc new path
			filename = malloc(35);
			strcpy(filename,"/usr/lib/RootAsRole/capable_kern.o");
		} else {
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
static void print_caps(int pid, int ppid, u_int64_t uid_gid, u_int64_t caps)
{
	char* name = get_process_name_by_pid(pid);
	if (caps <= (u_int64_t)0) {
		
		printf("| %d\t| %d\t| %d\t| %d\t| %s\t| %s\t|\n", (u_int32_t)uid_gid,
	       (u_int32_t)(uid_gid >> 32), pid, ppid, name,
	       "No capabilities needed");
		return;
	}
	char *capslist = NULL;
	capslist = get_caplist(caps);
	printf("| %d\t| %d\t| %d\t| %d\t| %s\t| %s\t|\n", (u_int32_t)uid_gid,
	       (u_int32_t)(uid_gid >> 32), pid, ppid, name,
	       capslist);
	free(capslist);
	free(name);
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