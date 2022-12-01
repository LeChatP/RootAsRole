#ifndef ROLEMANAGER_H
#define ROLEMANAGER_H

#define USER 1
#define GROUP 2

#include "xml_manager.h"

int actor_len(ACTOR *actors);

int cmd_len(CMD *actors);

void free_cmds(CMD *cmds);

void free_actors(ACTOR *actors);

void free_role(ROLE *role);

ROLE *copy_role(ROLE *to_copy);

char **get_groups(int *);

char **get_users(int *);

#endif