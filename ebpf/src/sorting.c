#include "sorting.h"
#include <unistd.h>

//if checking true then pid will filtered if not in tree
extern void append_pid(SortedPids *list, pid_t pid, pid_t ppid){
    SortedPids *elem = {NULL,pid,ppid};
    int filter = 0;
    if(list != NULL){
        SortedPids **plist = &list;
        SortedPids *last;
        while(*plist && (*plist)->pid < pid){
            if((*plist)->pid == pid) return list; // ignore entry with same pid
            last = *plist;
            plist = &(*plist)->next;
        }
        if(*plist){ // if while stopped on valid value, the inserting to the end of list
            elem->next = *plist;
            last->next = elem;
        }else{ // else last NULL pointer become elem
            *plist = elem;
        }
    }else{
        list = elem;
    }
    return list;
}

/**
 * return all child of given pid
 */
extern void get_childs(const SortedPids *list, pid_t pid, pid_t *result, int *size){
    SortedPids **plist = &list;
    while(*plist){ //on itère sur toute la liste
        if((*plist)->ppid == pid){ // si le ppid == au ppid préciser alors
            (*size)++;
            result = realloc(result,(*size)*sizeof(pid_t));
            result[(*size)-1] = (*plist)->pid;
            get_childs(list,(*plist)->pid,result,size); // on vérifie que l'élement courant a des fils
        }
        plist = &(*plist)->next;
    }
}