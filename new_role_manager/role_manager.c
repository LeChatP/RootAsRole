#include "role_manager.h"
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>



int actor_len(ACTOR *actors){
	int res = 0;
	for(ACTOR *actor = actors; actor != NULL; actor = actor->next) res++;
	return res;
}

int cmd_len(CMD *cmds){
	int res = 0;
	for(CMD *cmd = cmds; cmd != NULL; cmd = cmd->next) res++;
	return res;
}

void free_cmds(CMD *cmds){
	CMD *previous = NULL;
	for(CMD *cmd = cmds;cmd != NULL; cmd = cmd->next){
		if(previous){
			free(previous);
		}
		free(cmd->name);
		previous = cmd;
	}
}

void free_actors(ACTOR *actors){
	ACTOR *previous = NULL;
	for(ACTOR *actor = actors;actor != NULL;actor=actor->next){
		if(previous) free(previous);
		free_cmds(actor->cmds);
		free(actor->name);
		previous = actor;
	}
}

void free_role(ROLE *role){
	free_actors(role->groups);
	free_actors(role->users);
	free(role);
}

ACTOR *copy_actors(ACTOR *to_copy){
	ACTOR *root_actor = malloc(sizeof(ACTOR));
	root_actor->next = NULL;
	root_actor->cmds = NULL;
	ACTOR *new_actor = root_actor;
	for(ACTOR *actor = to_copy; actor != NULL; actor = actor->next){
		int name_size = strlen(actor->name);
		new_actor->name = (char*) malloc((name_size+1)*sizeof(char));
		strncpy(new_actor->name,actor->name,name_size);
		if(actor->cmds){
			CMD *root_cmd = malloc(sizeof(CMD));
			CMD *new_cmd = root_cmd;
			for(CMD *cmd = actor->cmds; cmd != NULL ; cmd = cmd->next){
				int str_size = strlen(cmd->name);
				new_cmd->name = (char*) malloc((str_size+1)*sizeof(char*));
				strncpy(new_cmd->name,cmd->name,str_size);
				if(cmd->next) {
					new_cmd->next = (CMD*) malloc(sizeof(CMD));
					new_cmd = new_cmd->next;
				}
			}
			new_actor->cmds = root_cmd;
		}
		if(actor->next){
			new_actor->next = (ACTOR*) malloc(sizeof(ACTOR));
			new_actor = new_actor->next;
		}
	}
	return root_actor;
}

ROLE *copy_role(ROLE *to_copy){
	
	ROLE *role = (ROLE*) malloc(sizeof(ROLE));
	role->capabilities = to_copy->capabilities;
	role->groups = NULL;
	role->users = NULL;
	if(to_copy->groups){
		role->groups = copy_actors(to_copy->groups);
	}
	if(to_copy->users){
		role->users = copy_actors(to_copy->users);
	}
	return role;
}


char **get_users(int *amount){
	char **users = (char **) malloc(sizeof (char *));
	struct passwd *p = NULL;
	*amount = 0;
	setpwent();
    while((p = getpwent())) {
		size_t pw_size = strlen(p->pw_name)* sizeof (char)+1;
		users[*amount] = (char *) malloc(pw_size);
		users = (char **) realloc(users,(*amount+2)*sizeof (char *));
		strncpy(users[*amount],p->pw_name,pw_size);
		users[*amount][pw_size] = '\0';
		(*amount)++;
    }
	return users;
}

char **get_groups(int *amount){
	char **groups = (char **) calloc(1,sizeof (char *));
	struct group *p = NULL;
	*amount = 0;
	setgrent();
    while((p = getgrent())) {
		size_t pw_size = strlen(p->gr_name)* sizeof (char)+1;
		groups[*amount] = (char *) malloc(pw_size);
		groups = (char **) realloc(groups,(*amount+2)*sizeof (char *));
		strncpy(groups[*amount],p->gr_name,pw_size);
		groups[*amount][pw_size] = '\0';
		(*amount)++;
    }
	
	groups[*amount] = NULL;
	return groups;
}