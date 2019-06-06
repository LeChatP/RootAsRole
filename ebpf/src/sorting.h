#ifndef SORTING_H
#define SORTING_H
#include <sys/types.h>

/**
 * This structure will make a sorted array of tree
 * sorted array is next from SortedCompositePids
 * trees are list of CompositePids
 */
typedef struct SortedPids SortedPids;
struct SortedPids {
    pid_t pid;
    pid_t ppid;
    SortedPids *next;
};

//add pid/ppid in the structure
extern void append_pid(SortedPids *list, pid_t pid, pid_t ppid);

//return all child of given pid
extern void get_childs(SortedPids *list, pid_t pid, pid_t *result, int *size);

#endif //SORTING_H