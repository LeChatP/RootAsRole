#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"

extern char *optarg;
extern int optind, opterr, optopt;

//Internal structure of input parameters
typedef struct _arguments_t {
	char *current;
    char *command;
    int version;
    int help;
} arguments_t;

/*
Parse input arguments and check arguments validity (in length)
return 0 on success, -1 on unknown arguments, -2 on invalid argument
*/
static int parse_arg(int argc, char **argv, arguments_t *args);

/*
Inject file_kern.o to kernel as bpf
return 0 on success, -1 on error occurs (cannot be known)
*/
static int load_bpf(char *file);


int main(int argc, char **argv)
{
	int return_code = EXIT_FAILURE;
	arguments_t args; //The input args
	if(load_bpf(argv[0])){
		perror("The injection into the kernel has failed");
		return return_code;
	}
	int key;
	u_int64_t value;
	int res, prev_key = -1;
	sleep(10);
	while(bpf_map_get_next_key(map_fd[0], &prev_key, &key) == 0){
		res = bpf_map_lookup_elem(map_fd[0], &key, &value);
		if(res < 0){
			printf("No value??\n");
        	continue;
		}
		printf("got pid : %d\tcaps : %016lx\n",key,value);
		prev_key=key;
	}

	return 0;
}

static int load_bpf(char *file){
	int return_code = -1;
	char *filenameFormat = "%s_kern.o";
	char *filename = malloc(strlen(file)+strlen(filenameFormat)-2+1);
	sprintf(filename,filenameFormat,file);
	if (load_bpf_file(filename)) {
		if(strlen(bpf_log_buf)>1)
		fprintf(stderr,"%s\n", bpf_log_buf);
		goto free_on_error;
	}
	return_code = 0;
	free_on_error:
	free(filename);
	return return_code;
}

static int parse_arg(int argc, char **argv, arguments_t *args){
	return 0;
}