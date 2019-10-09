#ifndef UTILS_TESTS_H

#define UTILS_TESTS_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#define READ   0
#define WRITE  1
#define OUTPUT_SYSTEM_FILE "tests/resources/output.out"
    //ask for pass if not already asked
    extern char *getpassword(void);

    /**
     * executes capable command and output pid with output pipe
     * and return pid, don't forget to kill or wait
     * Warning : pipe may not listen everything
     */
    pid_t capable_command(char *args, int *oufp);
    pid_t capable_sync_command(char *args, int *oufp);

    /**
     * executes sr command and output pid with output pipe and wait
     * and wait for exit
     * Warning : pipe may not listen everything
     */
    void sr_command(char *args, int *outfp);
    void sr_async_command(char *args, int *outfp);

    /**
     * execute echo in sr command, useful to see if configuration allow a command or not
     * and wait for exit
     */
    void sr_echo_command(char *name, int *outfp);

    /**
     * See sr_echo_command, but in async mode
     */
    void sr_async_echo_command(char *name, int *outfp);
    
    /** https://dzone.com/articles/simple-popen2-implementation
     * implementing popen but returning pid and getting in & out pipes
     * infp and outfp can be null
     */
    pid_t popen2(const char *command, int *infp, int *outfp,int async);
    
    /**
     * Copy file from old_filename to new_filename
     */
    int copy_file(char *old_filename, char  *new_filename);

    /**
     * copy file old_filename to new_filename and replace every arguments specified in document
     */
    int copy_file_args(char *old_filename, char  *new_filename,int nb_args,char **args);

    /**
     * Read file with filename
     */
    void readFile(char* file);

    /**
     * replace a matched in str to b
     */
    char* str_replace(char* str, char* a, char* b);

    /** 
     * Set a file descriptor to blocking or non-blocking mode.
     *
     * @param fd The file descriptor
     * @param blocking 0:non-blocking mode, 1:blocking mode
     *
     * @return 1:success, 0:failure.
     */
    int fd_set_blocking(int fd, int blocking);

    int strstrc(const char *haystack, char *needle);

#endif