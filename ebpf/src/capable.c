#include "bpf_load.h"
#include "libbpf.h"
#include "sr_constants.h"
#include <getopt.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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
	int version;
	int help;
} arguments_t;

// keeps process pid, needed for signals and filtering
static pid_t p_popen = -1;

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

/**
 * appends s2 to str with realloc, return new char*
 */
static char *concat(char *str, char *s2);

/**
 * Looking for command name
 * return command or path if process does not exist anymore
 */
static const char *get_process_name_by_pid(const int pid);

static void killProc(int signum);

static void killpopen(int signum);

static int printResult();

static int filter(pid_t pid, pid_t ppid, pid_t **pids, int *array_size);

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
	if (load_bpf(argv[0])) {
		perror("The injection into the kernel has failed");
		goto free_rscs;
	}
	if (args.command != NULL) {
		p_popen = popen2(args.command);
	} else if (!args.daemon &&
		   args.sleep < 0) { // if there's no command, no daemon and no sleep
		// specified the run as daemon by default
		args.daemon = 1;
	}
	if (args.daemon) { // if command run as daemon then read and print logs from
		// eBPF
		signal(SIGINT,
		       killpopen); // if sigint then kill command before exit
		printf("| KERNEL\t\t\t\t\t   | PID\t| PPID\t| CAP\t|\n");
		read_trace_pipe(); // print logs until kill
		printf("an error has occured");
		goto free_rscs;
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
			{ "version", no_argument, 0, 'v' },
			{ "help", no_argument, 0, 'h' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "c:s:dvh", long_options,
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
	printf("Usage : capable [-c command] [-s seconds] [-h] [-v]\n");
	if (long_help) {
		printf("Get every capabilities used by running program into sandbox.\n");
		printf("If you run this command for daemon please use -s to kill "
		       "automatically process\n");
		printf("Options:\n");
		printf(" -c, --command=command  launch the command to be more precise.\n");
		printf(" -s, --sleep=number		specify number of seconds before kill "
		       "program ");
		printf(" -v, --version          show the actual version of RootAsRole\n");
		printf(" -h, --help             print this help and quit.\n");
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
		kill(p_popen, SIGKILL);
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
	u_int64_t value, uid;
	pid_t key, prev_key = -1, ppid;
	int res, array_size = 1;
	pid_t *pids = calloc(array_size, sizeof(pid_t));
	pids[0] = p_popen;
	printf("Here's all capabilities intercepted :\n");
	printf("| UID\t| GID\t| PID\t| PPID\t| NAME\t\t\t| CAPABILITIES\t|\n");
	while (bpf_map_get_next_key(map_fd[0], &prev_key, &key) == 0) {
		res = bpf_map_lookup_elem(map_fd[0], &key,
					  &value); // get capabilities
		if (res < 0) {
			printf("No capabilities value for %d ??\n", key);
			continue;
		}
		res = bpf_map_lookup_elem(map_fd[1], &key, &ppid); // get ppid
		if (res < 0) {
			printf("No ppid for %d ??\n", key);
			continue;
		}
		res = bpf_map_lookup_elem(map_fd[2], &key,
					  &uid); // get uid and gid
		if (res < 0) {
			printf("No uid/gid for %d ??\n", key);
			continue;
		}
		if (p_popen >
		    -1) { // if command is specified then filter result to command
			if (filter(key, ppid, &pids, &array_size)) {
				print_caps(key, ppid, uid, value);
			}
		} else
			print_caps(key, ppid, uid,
				   value); // else print everything
		prev_key = key;
	}
	free(pids);
	return EXIT_SUCCESS;
}

/**
 * check if ppid is in array and append him, then returns true
 */
static int filter(pid_t pid, pid_t ppid, pid_t **pids, int *array_size)
{
	for (int i = 0; i < *array_size; i++) {
		if ((*pids)[i] == ppid || (*pids)[i] == pid) {
			(*array_size)++;
			if (realloc((*pids), (*array_size) * sizeof(int)) == NULL) {
				perror("error occurs");
				free(*pids);
				exit(EXIT_FAILURE);
			}
			(*pids)[(*array_size) - 1] = pid;
			return 1;
		}
		if ((*pids)[i] == pid) {
			return 1;
		}
	}
	return 0;
}

// https://dzone.com/articles/simple-popen2-implementation
// implementing popen but returning pid and getting in & out pipes asynchronous
static pid_t popen2(const char *command)
{
	pid_t pid;
	pid = fork();
	if (pid < 0)
		return pid;
	else if (pid == 0) {
		char final_command[PATH_MAX];
		sprintf(final_command, "%s", command);
		execl("/bin/sh", "sh", "-c", command, NULL);
		perror("execl");
		exit(1);
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
		if (!access("/usr/lib/RootAsRole/capable_kern.o", F_OK)) {
			free(filename);
			filename = "/usr/lib/RootAsRole/capable_kern.o";
		} else {
			free(filename);
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
	return return_code;
}

/**
 * print caps logged from map
 */
static void print_caps(int pid, int ppid, u_int64_t uid, u_int64_t caps)
{
	if (caps <= (u_int64_t)0) {
		printf("%d\t: No capabilities needed.\n", pid);
		return;
	}
	char *capslist = NULL;
	for (int pos = 0; pos < sizeof(u_int64_t) * 8;
	     pos++) { // caps > ((u_int64_t)1 << pos)&&
		if ((caps & ((u_int64_t)1 << pos)) != 0) {
			char *cap = cap_to_name(pos);
			if (capslist != NULL)
				capslist = concat(capslist, ", ");
			capslist = concat(capslist, cap);
			cap_free(cap);
		}
	}
	printf("| %d\t| %d\t| %d\t| %d\t| %s\t| %s\t|\n", (u_int32_t)uid,
	       (u_int32_t)(uid >> 32), pid, ppid, get_process_name_by_pid(pid),
	       capslist);
	free(capslist);
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
static const char *get_process_name_by_pid(const int pid)
{
	char *name = (char *)calloc(1024, sizeof(char));
	if (name) {
		sprintf(name, "/proc/%d/cmdline", pid);
		FILE *f = fopen(name, "r");
		if (f) {
			size_t size;
			size = fread(name, sizeof(char), 1024, f);
			if (size > 0) {
				if ('\n' == name[size - 1])
					name[size - 1] = '\0';
			}
			fclose(f);
		}
	}
	return name;
}