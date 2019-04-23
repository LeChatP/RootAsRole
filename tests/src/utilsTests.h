#ifndef UTILS_TESTS_H

#define UTILS_TESTS_H
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/limits.h>
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
     * Read file with filename
     */
    void readFile(char* file);

    /**
     * replace a matched in str to b
     */
    char* str_replace(char* str, char* a, char* b);

#endif