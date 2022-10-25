#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list_manager.h"

int account_allocation(char *accounts, account_list *al)
{
    char *token;
    account_list firstAl, temp;

    if (!al) {
        fputs("Error: al is empty", stderr);
        return -1;
    }

    firstAl = *al;
    token = strtok(accounts, ",");

    do {
        if ((*al)->prev) {
            for (temp = firstAl; temp->next != *al; temp = temp->next) {
                if (!strcmp(temp->account, token)) {
                    goto duplicate;
                }
            }
        }

        (*al)->account = (char *)malloc((strlen(token)+1) * sizeof(char));
        if (!(*al)->account) {
            fputs("Error malloc\n", stderr);
            remove_account((*al));
            return -1;
        }

        strcpy((*al)->account, token);
duplicate:
        if (!(*al)->next) {push((*al));}
    } while ( (token = strtok(NULL, ",")) != NULL );
    return 0;
}


void remove_account(account_list a)
{
    if (a != NULL) {
        while (a->next != NULL)
            a = a->next;
        while (a->prev != NULL) {
          a = a->prev;
          free(a->account);
          free(a->next);
          a->next = NULL;
        }
        free(a);
        a = NULL;
    }
}


void remove_command(command_list c)
{
    if (c != NULL) {
        while (c->next != NULL)
            c = c->next;
        while (c->prev != NULL) {
          c = c->prev;
          free(c->next);
          c->next = NULL;
        }
        free(c);
        c = NULL;
    }
}
