
#include <curses.h>
#include <menu.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/capability.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include "verifier.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#define CTRLD 4

#define ESC 27
#define ENTER 10

#define MAIN_MENU -1
#define CAPS_MENU 0
#define USER_MENU 1
#define GROUP_MENU 2
#define CMDS_MENU 3
#define ACTOR_SEL_MENU 4

#define QUIT 0
#define CONTINUE 1
#define PREVIOUS_MENU 2

#define ACTION_ENTER 1
#define ACTION_DELETE 2
#define ACTION_UNDO 3
#define ACTION_BACK 4
#define ACTION_SEARCH 5

static int menu_type = MAIN_MENU;
static int previous_menu = MAIN_MENU;

extern char **environ;

char *capabilities[][2] = {
{"CHOWN","Overrides the restriction of changing file ownership and group ownership."},
{"DAC_OVERRIDE","Override all DAC access, excluding immuables files."},
{"DAC_READ_SEARCH","Allow to read and search on files and directories, excluding immuables files."},
{"FOWNER","Condering process is owner of any file, but apply DAC restriction of owner."},
{"FSETID","Overrides actions on SETUID or SETGID bit on files."},
{"KILL","Overrides restrictions on sending a signal on process."},
{"SETGID","Allows setgid(2) setgroups(2) manipulation, and forged gids on socket credentials passing."},
{"SETUID","Allows setuid(2) manipulation (including fsuid) and forged pids on socket credentials passing."},
{"SETPCAP","Add any capabilities on current bounding to inheritable sets, drop any capability from bounding set."},
{"LINUX_IMMUTABLE","Allow modification of S_IMMUTABLE and S_APPEND file attributes."},
{"NET_BIND_SERVICE","Allows binding to TCP/UDP sockets below 1024, Allows binding to ATM VCIs below 32."},
{"NET_BROADCAST","Allow broadcasting, listen to multicast."},
{"NET_ADMIN","Allow manipulate and configure almost everything about networking in the entire system."},
{"NET_RAW","Allow use of RAW sockets, use of PACKET sockets, Allow binding to any address for transparent proxying."},
{"IPC_LOCK","Allow locking of shared memory segments, use mlock and mlockall."},
{"IPC_OWNER","Override IPC ownership checks."},
{"SYS_MODULE","Insert and remove kernel modules - modify kernel without limit."},
{"SYS_RAWIO","Allow ioperm/iopl access and sending USB messages to any device via /dev/bus/usb."},
{"SYS_CHROOT","Allow use of chroot(), even escape from namespaces."},
{"SYS_PTRACE","Allow ptrace() of any process."},
{"SYS_PACCT","Allow configuration of process accounting."},
{"SYS_ADMIN","is the new ROOT, allow to do almost everything including some others capabilities."},
{"SYS_BOOT","Allow use of reboot()."},
{"SYS_NICE","Change the scheduling algorithm, priority, cpu affinity, realtime ioprio class on any process."},
{"SYS_RESOURCE","Override resource, keymaps, quota limits. Override some filesystems limits and memory behaviour."},
{"SYS_TIME","Allow manipulation of system clock. Allow irix_stime on mips. Allow setting the real-time clock."},
{"SYS_TTY_CONFIG","Allow configuration of tty devices. Allow vhangup() of tty."},
{"MKNOD","Allow the privileged aspects of mknod()."},
{"LEASE","Allow taking of leases on files."},
{"AUDIT_WRITE","Allow writing the audit log via unicast netlink socket."},
{"AUDIT_CONTROL","Allow configuration of audit via unicast netlink socket."},
{"SETFCAP","Set or remove capabilities on files. Map uid=0 into a child user namespace."},
{"MAC_OVERRIDE","Override MAC access. Some MAC can ignore this capability."},
{"MAC_ADMIN","Allow MAC configuration or state changes. Some MAC configurations can ignore this capability."},
{"SYSLOG","Allow configuring the kernel's syslog (printk behaviour)."},
{"WAKE_ALARM","Allow triggering something that will wake the system."},
{"BLOCK_SUSPEND","Allow preventing system suspends."},
{"AUDIT_READ","Allow reading the audit log via multicast netlink socket."},
{"PERFMON","Allow system performance and observability privileged operation."},
{"BPF","CAP_BPF allows many BPF operations."},
{"CHECKPOINT_RESTORE","Allow checkpoint/restore related operations."}
};

char *mainmenu[] = {
	"Manage Capabilities",
	"Manage Users",
	"Manage Groups",
	"Save & Exit",
    "Exit without saving"
};
typedef struct _cmd CMD;
typedef struct _actor ACTOR;
typedef struct _context CONTEXT;


struct _cmd {
	CMD *next;
	char *name;
};
struct _actor {
	ACTOR *next;
	char *name;
	CMD *cmds;
};


typedef struct _role {
	u_int64_t capabilities;
	ACTOR *groups;
	ACTOR *users;
} ROLE;

struct _context {
	ROLE *role;
	ACTOR *actor;
	CMD *cmd;
};


u_int64_t get_xml_caps(xmlNodePtr xmlCaps){
	u_int64_t caps = 0UL;
	for(xmlNodePtr xcap = xmlCaps->children; xcap !=NULL; xcap = xcap->next){
		cap_value_t capVal;
		if(xcap->children->content[0] == '*') return ((u_int64_t) -1)>>(64-cap_max_bits());
		cap_from_name(xcap->children->content, &capVal);
		caps |= 1UL<<capVal;
	}
	return caps;
}

CMD *get_xml_cmds(xmlNodePtr xmlCmds){
	CMD *root_cmds = (CMD *)malloc(sizeof(CMD));
	CMD *cmds = root_cmds;
	for(xmlNodePtr xmlCmd = xmlCmds->children; xmlCmd !=NULL; xmlCmd = xmlCmd->next){
		int str_size = xmlStrlen(xmlCmd->children->content);
		cmds->name = malloc(str_size+1*sizeof(xmlChar));
		strncpy(cmds->name,(char*)xmlCmd->children->content,str_size);
		cmds->name[str_size] = '\0';
		if(xmlCmd->next){
			cmds->next = (CMD *)malloc(sizeof(CMD));
			cmds = cmds->next;
		}else cmds->next = NULL;
	}
	return root_cmds;
}

ACTOR *get_xml_actors(xmlNodePtr xmlActors){
	ACTOR *root_actor = (ACTOR*) malloc(sizeof(ACTOR));
	ACTOR *actor = root_actor;
	for(xmlNodePtr subcontainer = xmlActors->children; subcontainer!=NULL;subcontainer = subcontainer->next){
		actor->name = (char*)xmlStrdup(xmlGetProp(subcontainer,(xmlChar*)"name"));
		if(subcontainer->children && subcontainer->children->children)
			actor->cmds = get_xml_cmds(subcontainer->children);
		else actor->cmds = NULL;
		if(subcontainer->next){
			actor->next = (ACTOR*) malloc(sizeof(ACTOR));
			actor = actor->next;
		}else{
			actor->next = NULL;
		}
	}
	return root_actor;
}

int actor_len(ACTOR *actors){
	int res = 0;
	for(ACTOR *actor = actors; actor != NULL; actor = actor->next) res++;
	return res;
}


int get_role(ROLE *role_struct, char *role){
	role_struct->capabilities = 0;
	role_struct->groups = NULL;
	role_struct->users = NULL;
	LIBXML_TEST_VERSION
	xmlDocPtr doc;
	xmlNodePtr role_node;
    if (!(doc = xml_verifier()))
        return 0;

    if(!role_verifier(doc, &role_node, role)){
		fputs("Role doesn't exists\n",stderr);
		return 0;
	}
	for(xmlNodePtr container = role_node->children;container !=NULL;container = container->next){
		if(!strcmp(container->name,"capabilities")){
			role_struct->capabilities = get_xml_caps(container);
		}else {
			ACTOR *actor = get_xml_actors(container);
			if(container->name[0] == 'u' || container->name[0] == 'U'){
				role_struct->users = actor;
			}else{
				role_struct->groups = actor;
			}
		}
	}
	return 1;
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

typedef struct _undo UNDO;

struct _undo {
	ROLE *state;
	UNDO *previous;
};

UNDO *undo;

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

ROLE *archive_role(){
	extern UNDO* undo;
	UNDO *new_undo = (UNDO*)malloc(sizeof(UNDO));
	new_undo->state = copy_role(undo->state);
	new_undo->previous = undo;
	undo = new_undo;
	return undo->state;
}

ROLE *init_role(){
	extern UNDO* undo;
	undo = (UNDO*) malloc(sizeof(UNDO));
	undo->state = malloc(sizeof(ROLE));
	undo->previous = NULL;
	return undo->state;
}

CONTEXT *init_context(){
	CONTEXT *context = malloc(sizeof(CONTEXT));
	context->role = init_role();
	context->actor = NULL;
	context->cmd = NULL;
}

ROLE *current_role(){
	return undo->state;
}

void free_undo(UNDO *undo){
	free_role(undo->state);
	free(undo);
}

ROLE *perform_undo(){
	extern UNDO* undo;
	UNDO *undo_to_free = undo;
	undo = undo->previous;
	free_undo(undo_to_free);
}

void saveall(){
	return;
}

ACTOR *sel_menu_actor(MENU *menu, CONTEXT* context){

}

MENU* editor_commands(MENU * menu, CONTEXT *context){

}

void delete_cmd(ITEM *item,CONTEXT *context){
	
}

u_int64_t search_caps(MENU *menu, u_int64_t caps){

}

void search_cmd(MENU *menu, CONTEXT *context){

}

ACTOR *new_menu_actor(MENU *menu,int previous_menu){
	if(previous_menu == USER_MENU){

	}else{

	}
}

void search_actor(MENU *menu, CONTEXT *context){

}

void edit_cmd(MENU *item, CONTEXT *context){
	if(context->cmd == NULL){
		context->cmd = malloc(sizeof(CMD));
		CMD *tmp = context->actor->cmds;
		for(; tmp->next != NULL; tmp = tmp->next);
		tmp->next = context->cmd;
	}
}

void new_cmd(MENU *menu, CONTEXT *context){
	return edit_cmd(menu, context);
}

void unpost_free_menu(MENU *menu){
	unpost_menu(menu);
	switch (menu_type)
	{
	case MAIN_MENU:
		break;
	case GROUP_MENU:
	case USER_MENU:
		ITEM **items = menu_items(menu);
		for(int i = 0; items[i] !=NULL; i++){
			free_item(items[i]);
		}
	default:
		break;
	}
	previous_menu = menu_type;
}

WINDOW *init_main_menu(MENU *menu){
	int n_choices = ARRAY_SIZE(mainmenu);
	ITEM **MAIN_ITEMS = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));
	for(int i = 0; i < n_choices; ++i)
		MAIN_ITEMS[i] = new_item(mainmenu[i], mainmenu[i]);
	menu = new_menu(MAIN_ITEMS);
	set_menu_mark(menu, " * ");
	WINDOW *menuwin = derwin(stdscr, getmaxy(stdscr)-3, getmaxx(stdscr), 0, 0);
	box(menuwin, 0, 0);
	int yoffset = 1;
	int xoffset = 1;

	set_menu_sub(menu, derwin(menuwin,getmaxy(menuwin)-3-yoffset,getmaxx(menuwin)-xoffset,yoffset,xoffset));
	return menuwin;
}

MENU *main_menu(MENU *menu)
{
    int n_choices = ARRAY_SIZE(mainmenu);
	ITEM **MAIN_ITEMS = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));
	unpost_free_menu(menu);
	for (int i = 0; i < n_choices; ++i)
		MAIN_ITEMS[i] = new_item(mainmenu[i], NULL);
	MAIN_ITEMS[n_choices] = (ITEM *)NULL;
    set_menu_items(menu,MAIN_ITEMS);

    menu_opts_on(menu,O_ONEVALUE);
    menu_opts_off(menu,O_SHOWDESC);
	post_menu(menu);
	menu_type = MAIN_MENU;
    return menu;
}

MENU *editor_sysactors_menu(MENU *menu, int previous_menu){
	char** (*get_actors_ptr)(int*) = get_users;
	if(previous_menu == GROUP_MENU){
		get_actors_ptr = get_groups;
	}
	int amount = 0;
	char **actors = get_actors_ptr(&amount);
	ITEM **ACTOR_ITEMS = (ITEM **)calloc(amount+2, sizeof(ITEM *));
	ACTOR_ITEMS[0] = new_item("Previous Menu",NULL);
	if(menu == NULL) menu = new_menu(ACTOR_ITEMS);
    else {
		unpost_free_menu(menu);
	}
	for (int i = 1; i < amount+1; ++i){
		ACTOR_ITEMS[i] = new_item(actors[i], NULL);
	}
	ACTOR_ITEMS[amount+1] = (ITEM *)NULL;
    set_menu_items(menu,ACTOR_ITEMS);
    menu_opts_on(menu,O_ONEVALUE);
    menu_opts_off(menu,O_SHOWDESC);
	post_menu(menu);
	free(actors);
    return menu;
}



MENU *editor_actor_menu(MENU *menu, char *actor_type, ACTOR *actors, int amount){
	ITEM **ACTOR_ITEMS = (ITEM **)calloc(amount+3, sizeof(ITEM *));
	char *addactor = (char *) malloc((9+strlen(actor_type))*sizeof(char));
	ACTOR_ITEMS[0] = new_item("Return to Main Menu",NULL);
	sprintf(addactor,"Add new %s",actor_type);
	ACTOR_ITEMS[1] = new_item(addactor, NULL);
	if(menu == NULL) menu = new_menu(ACTOR_ITEMS);
    else {
		unpost_free_menu(menu);
	}
	int i = 2;
	for (ACTOR *actor = actors; actor !=NULL; actor = actor->next){
		ACTOR_ITEMS[i] = new_item(actors->name, NULL);
		i++;
	}
		
	ACTOR_ITEMS[amount+2] = (ITEM *)NULL;
    set_menu_items(menu,ACTOR_ITEMS);
    menu_opts_on(menu,O_ONEVALUE);
    menu_opts_off(menu,O_SHOWDESC);
	post_menu(menu);
    return menu;
}

MENU *editor_cmd_menu(MENU *menu, CMD *cmds, int amount){
	ITEM **CMDS_ITEMS = (ITEM **)calloc(amount+3, sizeof(ITEM *));
	CMDS_ITEMS[0] = new_item("Return to Main Menu",NULL);
	CMDS_ITEMS[1] = new_item("Add new Command", NULL);
	if(menu == NULL) menu = new_menu(CMDS_ITEMS);
    else {
		unpost_free_menu(menu);
	}
	int i = 2;
	for (CMD *actor = cmds; actor !=NULL; actor = actor->next){
		CMDS_ITEMS[i] = new_item(cmds->name, NULL);
		i++;
	}
	CMDS_ITEMS[amount+2] = (ITEM *)NULL;
    set_menu_items(menu,CMDS_ITEMS);
    menu_opts_on(menu,O_ONEVALUE);
    menu_opts_off(menu,O_SHOWDESC);
	post_menu(menu);
    return menu;
}

MENU *editor_menu(MENU *menu, CONTEXT *context,const int editor_type){
	char *actor_type_name;
	ACTOR *actors;
	if(editor_type == USER_MENU){
		actors = context->role->users;
		actor_type_name = "User";
	}else{
		actors = context->role->groups;
		actor_type_name = "Group";
	}
	int amount = actor_len(context->role->users);
	menu = editor_actor_menu(menu,actor_type_name,actors,amount);
	menu_type = editor_type;
}

MENU *caps_menu(MENU *menu,uint64_t caps)
{
    int n_choices = sizeof(capabilities)/sizeof(capabilities[0]);
	ITEM **CAPS_ITEMS = (ITEM **)calloc(n_choices + 2, sizeof(ITEM *));
	if(menu == NULL) menu = new_menu(CAPS_ITEMS);
    else {
		unpost_free_menu(menu);
	}
	menu_opts_on(menu,O_SHOWDESC);
    menu_opts_off(menu, O_ONEVALUE);
	CAPS_ITEMS[0] = new_item("Return to main menu", "");
	item_opts_off(CAPS_ITEMS[0],O_SELECTABLE);
	for (int i = 1; i < n_choices+1; ++i){
		CAPS_ITEMS[i] = new_item(capabilities[i][0], capabilities[i][1]);
	}
		
	CAPS_ITEMS[n_choices+1] = (ITEM *)NULL;
	
	if(set_menu_items(menu,CAPS_ITEMS) != E_OK) perror("unable to set menu");
	
	post_menu(menu);
	for (int i = 0; i < n_choices; ++i){	
		if(caps & (((uint64_t) 1UL)<<i)){
			if(set_item_value(CAPS_ITEMS[i+1],TRUE) != E_OK){
				perror("unable set item value");
			}
		}
	}
	
	menu_type = CAPS_MENU;
    return menu;
}

void save_caps(MENU *menu, ROLE *role){
	ITEM **items = menu_items(menu);
	u_int64_t caps = (u_int64_t) 0UL;
	for(int i = 1; items[i] != NULL; i++){
		if(items[i]->value){
			caps |= (u_int64_t)1 << (i-1);
		}
	}
	if(caps != role->capabilities){
		ROLE *role = archive_role();
		role->capabilities = caps;
	}
	
	
}

void reload_menu(MENU *menu, CONTEXT* context){
	switch (menu_type)
	{
		case MAIN_MENU:
			return;
		case CAPS_MENU:
			menu = caps_menu(menu,context->role->capabilities);
			return;
		case GROUP_MENU:
		case USER_MENU:
			editor_menu(menu,context,menu_type);
			return;
		case CMDS_MENU:
			editor_commands(menu,context);
			break;
		case ACTOR_SEL_MENU:
			menu = editor_sysactors_menu(menu,previous_menu);
			break;
		default:
			fputs("Wrong state\n",stderr);
			break;
	}
}

int main_menu_selection(MENU *menu, ITEM *item, CONTEXT *context){
	int result = CONTINUE;
	int index = item_index(item);
	switch (index)
	{
	case CAPS_MENU:
		menu = caps_menu(menu,context->role->capabilities);
		break;
	case USER_MENU:
	case GROUP_MENU:
		editor_menu(menu,context,index);
		break;
	case 3:
		saveall();
	case 4:
		result = QUIT;
		break;
	default:
		break;
	}
	return result;
}

ROLE *delete_actor(ITEM *p_actor){
	ROLE *role = archive_role();
	ACTOR *actors = role->users, *previous = NULL;
	if(menu_type == GROUP_MENU) actors = role->groups; 
	for(ACTOR *actor = actors; actor != NULL; actor = actor->next){
		if(!strcmp(actor->name,p_actor->name.str)){
			if(previous){
				previous->next = actor->next;
				actor->next = NULL;
				free_actors(actor);
			}
		}
	}
	return role;
}

int perform_action(MENU *menu,CONTEXT *context, int action){
	ITEM *current = current_item(menu);
	int index = item_index(current);
	int amount = 0;
	char **elements = NULL;
	switch (menu_type)
	{
	case MAIN_MENU:
		return main_menu_selection(menu,current,context);
	case CAPS_MENU:
		if(!index || action == ACTION_BACK) {
			save_caps(menu,context->role);
			menu = main_menu(menu);
		}else if(action == ACTION_SEARCH){
			context->role->capabilities = search_caps(menu,context->role->capabilities);
			break;
		}
		menu_driver(menu, REQ_TOGGLE_ITEM);
		break;
	case GROUP_MENU:
	case USER_MENU:
		if(!index || action == ACTION_BACK) {
			menu = main_menu(menu);
		}else if (index == 1)
		{
			menu = editor_sysactors_menu(menu,menu_type);
			menu_type = ACTOR_SEL_MENU;
		}else if(action == ACTION_DELETE){
			context->role = delete_actor(current);
			reload_menu(menu,context);
		}else if(action == ACTION_ENTER){
			context->actor = sel_menu_actor(menu,context);
			menu = editor_commands(menu,context);
		}
		break;
	case CMDS_MENU:
		if(!index || action == ACTION_BACK){
			menu = editor_sysactors_menu(menu,previous_menu);
			menu_type = ACTOR_SEL_MENU;
		}else if (index == 1){
			new_cmd(menu,context);
		}else if (action == ACTION_DELETE){
			delete_cmd(current,context);
		}else if (action == ACTION_ENTER){
			edit_cmd(menu,context);
		}else if (action == ACTION_SEARCH){
			search_cmd(menu,context);
		}
		break;
	case ACTOR_SEL_MENU:
		if(!index || action == ACTION_BACK){
			menu_type = previous_menu;
			previous_menu = MAIN_MENU;
			reload_menu(menu,context);
		} else
			switch(action){
				case ACTION_BACK:
					menu = editor_menu(menu,context,previous_menu);
					break;
				case ACTION_ENTER:
					context->actor = new_menu_actor(menu,previous_menu);
					menu = editor_commands(menu,context);
					break;
				case ACTION_SEARCH:
					search_actor(menu,context);
					break;
			}
		break;
	default:
		fputs("Wrong state\n",stderr);
		break;
	}
	return CONTINUE;
}

static int print_help(char *path, int long_help)
{
	printf("Usage : %s [role]\n",path);
	if (long_help) {
		printf("Edit a role through fancy interface.\n");
	}
	return 0;
}

int main(int argc, char *argv[])
{
	
	int status = CONTINUE, action = 0;
	
	MENU *my_menu = NULL;
	
	CONTEXT *context = init_context();
	

	if((argc < 2 && !print_help(argv[0],false)) || !get_role(context->role,argv[1])) goto free_rscs;

	/* Initialize curses */
	WINDOW *main_frame = initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	

	/* Initialize items */
	WINDOW *line = init_main_menu(my_menu);
    my_menu = main_menu(my_menu);
	

	while (status != QUIT) {
		refresh();
		switch (getch()) {
			case KEY_DOWN:
				menu_driver(my_menu, REQ_DOWN_ITEM);
				continue;
			case KEY_UP:
				menu_driver(my_menu, REQ_UP_ITEM);
				continue;
			case ' ':
			case '\n':
				action = ACTION_ENTER;
				break;
			case '\b':
				action = ACTION_BACK;
				break;
			case '/':
				action = ACTION_SEARCH;
				break;
			case 111:
				action = ACTION_DELETE;
				break;
			case 'u':
			case 'U':
				context->role = perform_undo();
				reload_menu(my_menu,context);
				break;
				
		}
		status = perform_action(my_menu,context, action);
	}
	free_rscs:
	free_menu(my_menu);
	endwin();
}

/** UNUSED */
void free_menu_items(MENU *menu)
{
    ITEM** ITEMS = menu_items(menu);
    int n_choices = ARRAY_SIZE(mainmenu);
    for (int i = 0; i < n_choices; ++i)
        free_item(ITEMS[i]);
    free_menu(menu);
}

