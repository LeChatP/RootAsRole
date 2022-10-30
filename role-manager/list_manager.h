#ifndef LIST_MANAGER_H
#define LIST_MANAGER_H

/* Fonctions de macro permettant l'allocation
 * de toutes listes contenues dans la structure
 * args_struct
 */
#define forPush(forS) \
    forS = malloc(sizeof(typeof(*forS))); \
        if (forS == NULL) { \
            perror("Error, malloc:"); \
            return -1; \
        } \
    memset(forS, 0, sizeof(typeof(*forS)));

#define push(s) \
    if (s == NULL) { \
        forPush(s); \
    } \
    else if (s->next == NULL){ \
        forPush(s->next); \
        s->next->prev = s; \
        s = s->next; \
    }


/* Déclaration de la structure args_struct */
typedef struct account_bloc *account_list;
typedef struct command_bloc *command_list;

struct account_bloc {
  account_list prev;
  char *account;
  command_list cs;
  account_list next;
};

struct command_bloc {
  command_list prev;
  uint8_t cc;          // Command count for bloc index
  int cbi;             // Command bloc index (optarg-1)
  command_list next;
};

typedef struct arguments {
  char *rolename;
  uint64_t capabilities;

  /* User */
  uint8_t uc;          // user count
  account_list ubloc;  // user bloc
  /* **** */

  /* Group */
  uint8_t gc;          // group count
  account_list gbloc;  // groub bloc
  /* ***** */

  /* Commands */
  uint8_t cc;          // command count for bloc list
  bool cg;             // general command
  command_list cbloc;  // command bloc
  /* ******** */
} args_struct;


/* Fonction permettant l'allocation de plusieurs comptes
 * dans une liste account_list
 */
int account_allocation(char *accounts, account_list *al);

/* Fonctions permettant la libération
 * de la mémoire des listes contenus
 * dans la structure args_struct
 */
void remove_account(account_list a);
void remove_command(command_list c);

#endif
