#ifndef UTILS_TESTS_H

#define UTILS_TESTS_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <string.h>
#include <fcntl.h>
#define READ   0
#define WRITE  1

    /** https://dzone.com/articles/simple-popen2-implementation
     * implementing popen but returning pid and getting in & out pipes
     * infp and outfp can be null
     */
    pid_t popen2(const char *command, int *infp, int *outfp);
    
    /**
     * Copy file from old_filename to new_filename
     */
    int copy_file(char *old_filename, char  *new_filename);

    /**
     * copy file old_filename to new_filename and replace %s$1, %s$2, %s$3 to arg1, arg2, arg3
     */
    int copy_file_args(char *old_filename, char  *new_filename,char *arg1,char *arg2,char *arg3);
    
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

#endif