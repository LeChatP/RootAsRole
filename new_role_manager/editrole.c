
#include <curses.h>
#include <menu.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/capability.h>

#include <sys/types.h>
#include <unistd.h>
#include "role_manager.h"
#include "undo.h"

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
#define ACTION_INPUT 5

static int print_help(int long_help);


static int menu_type = MAIN_MENU;
static int previous_menu = MAIN_MENU;
static char current_input[4096];

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
	"Manage Users",
	"Manage Groups",
	"Manage Commands",
	"Save & Exit",
    "Exit without saving"
};



/**
 * @brief archive role but retrieve the pointers to the new actors and cmd by their type and name
*/
void save_state_context(CONTEXT *context){
	ROLE *role = archive_role(context->role);
	context->role = role;
	if(context->actor != NULL){
		ACTOR *actor = NULL;
		if(context->actor->type == USER)
			for(actor = role->groups; actor !=NULL && strcmp(actor->name,context->actor->name); actor = actor->next);
		else
			for(actor = role->users; actor !=NULL && strcmp(actor->name,context->actor->name); actor = actor->next);
		context->actor = actor;
		if(context->actor != NULL){
			if(context->cmd != NULL){
				CMD *cmd = NULL;
				for(cmd = actor->cmds; cmd !=NULL && strcmp(cmd->name,context->cmd->name); cmd = cmd->next);
				context->cmd = cmd;
			}
		}
	}
}

CONTEXT *init_context(){
	CONTEXT *context = malloc(sizeof(CONTEXT));
	context->role = init_role();
	context->actor = NULL;
	context->cmd = NULL;
	return context;
}


void delete_cmd(ITEM *item,CONTEXT *context){
	CMD * previous = NULL;
	for(CMD * cmd = context->actor->cmds; cmd != NULL && cmd == item_userptr(item); cmd = cmd->next) previous = cmd;
	if(previous != NULL) previous->next = context->cmd->next;
	else context->actor->cmds = context->cmd->next;
	
}

void add_char_in_input(char c){
	if(strlen(current_input) < 4095){
		current_input[strlen(current_input)] = c;
		current_input[strlen(current_input)+1] = '\0';
	}else {
		beep();
	}
}

void search_in_items(MENU *menu,ITEM **items,char input){
	add_char_in_input(input);
	ITEM *item = NULL;
	int i = 0;
	for(item = items[i]; item != NULL && strncasecmp(current_input,item->name.str,strlen(current_input)); item = items[++i]);
	if(item != NULL)
		set_current_item(menu,item);
	else if(strlen(current_input) > 1){
		current_input[0] = '\0';
		current_input[1] = '\0';
		search_in_items(menu,items,input);
	}
}

/**
 * @brief display window to edit one line long text dynamically
 * @param text text to edit
 * @returns true if text modified
 */
int menu_text_editor(MENU* menu,char **text){
	int xsize = getmaxx(stdscr)-4;
	unpost_menu(menu);
	
	int ch;
	int i = 0;
	int modified = 0;
	int len = 0;
	if(*text != NULL)
		len = strlen(*text);
	int BUFSIZE = len+1024;
	char *new_text = (char *) malloc(BUFSIZE);
	strncpy(new_text,*text,len);
	new_text[len] = '\0';
	//set_menu_sub(menu,win);
	
	char *title = "Press enter to validate the command, press escape to cancel";
	wmove(stdscr,1,xsize/2-strlen(title)/2);
	wprintw(stdscr,title);
	
	WINDOW *win = subwin(stdscr,getmaxy(stdscr)-4,xsize-2,2,2);
	if(*text != NULL){
		wmove(win,1,0);
		wprintw(win,*text);
		i = len;
	}
	wmove(win,1,i);
	refresh();
	while((ch = wgetch(win)) != KEY_ENTER && ch != 10 && ch != 13 && ch != 27){
		if(len >= xsize-2){
			i=0;
			wclear(win);
			wmove(win,1,i);
			waddch(win,'<');
			i++;
		}
		refresh();
		switch(ch){
			case '\b':
			case KEY_BACKSPACE:
				if(i > 0){
					i--;
					new_text[i] = '\0';
					wdelch(win);
					modified = 1;
				}
				break;
			case KEY_DC:
			case 127:
				if(i < len){
					new_text[i] = '\0';
					wmove(win,1,i);
					waddch(win,' ');
					wmove(win,1,i);
					modified = 1;
				}
				break;
			case KEY_LEFT:
				if(i > 0){
					i--;
					wmove(win,1,i);
				}
				break;
			case KEY_RIGHT:
				if(i < len){
					i++;
					wmove(win,1,i);
				}
				break;
			default:
				if(isprint(ch)){
					if(i < BUFSIZE){
						new_text[i] = ch;
						waddch(win,ch);
						i++;
						modified = 1;
					}else {
						BUFSIZE += 1024;
						new_text = (char *) realloc(new_text,BUFSIZE);
						new_text[i] = ch;
						waddch(win,ch);
						i++;
						len++;
						modified = 1;
					}
				}
				break;
		}
		box(stdscr, 0, 0);
	}
	wclear(win);
	wrefresh(win);
	delwin(win);
	wclear(stdscr);
	box(stdscr, 0, 0);
	if(modified){
		free(*text);
		*text = new_text;
	}
	post_menu(menu);
	return modified;
}



void unpost_free_menu(MENU *menu){
	unpost_menu(menu);
	ITEM **items = NULL;
	switch (menu_type)
	{
	case MAIN_MENU:
		break;
	case GROUP_MENU:
	case USER_MENU:
		items = menu_items(menu);
		for(int i = 0; items[i] !=NULL; i++){
			free_item(items[i]);
		}
	default:
		break;
	}
	//previous_menu = menu_type;
}

/**
 * @brief Editer du texte dans une WINDOW
*/
void editText(WINDOW *window, char *text){
	int x = 0;
	int y = 0;
	int ch;
	int i = 0;
	int len = strlen(text);
	int BUFSIZE = len+1024;
	char *new_text = (char *) malloc(BUFSIZE);
	strncpy(new_text,text,len);
	new_text[len] = '\0';
	wmove(window,0,0);
	wprintw(window,text);
	wmove(window,0,i);
	wrefresh(window);
	while((ch = wgetch(window)) != KEY_ENTER && ch != 10 && ch != 13 && ch != 27){
		if(len >= getmaxx(window)){
			i=0;
			wclear(window);
			wmove(window,0,i);
			waddch(window,'<');
			i++;
		}
		switch(ch){
			case '\b':
			case KEY_BACKSPACE:
				if(i > 0){
					i--;
					new_text[i] = '\0';
					wdelch(window);
				}
				break;
			case KEY_DC:
			case 127:
				if(i < len){
					new_text[i] = '\0';
					wmove(window,0,i);
					waddch(window,' ');
					wmove(window,0,i);
				}
				break;
			case KEY_LEFT:
				if(i > 0){
					i--;
					wmove(window,0,i);
				}
				break;
			case KEY_RIGHT:
				if(i < len){
					i++;
					wmove(window,0,i);
				}
				break;
			default:
				if(isprint(ch)){
					if(i < BUFSIZE){
						new_text[i] = ch;
						waddch(window,ch);
						i++;
					}else {
						BUFSIZE += 1024;
						new_text = (char *) realloc(new_text,BUFSIZE);
						new_text[i] = ch;
						waddch(window,ch);
						i++;
						len++;
					}
				}
				break;
		}
		wrefresh(window);
	}
	if(strcmp(text,new_text)){
		strncpy(text,new_text,strlen(new_text));
		text[strlen(new_text)] = '\0';
	}
	free(new_text);
}

WINDOW *init_main_menu(MENU **menu){
	int n_choices = ARRAY_SIZE(mainmenu);
	ITEM **MAIN_ITEMS = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));
	*menu = new_menu(MAIN_ITEMS);
	set_menu_mark(*menu, " * ");
	//WINDOW *menuwin = derwin(stdscr, getmaxy(stdscr)-3, getmaxx(stdscr), 0, 0);
	box(stdscr, 0, 0);
	int yoffset = 1;
	int xoffset = 1;
	set_menu_sub(*menu, derwin(stdscr,getmaxy(stdscr)-3-yoffset,getmaxx(stdscr)-xoffset,yoffset,xoffset));
	return NULL;
}

void main_menu(MENU *menu)
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
	refresh();
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
	ACTOR_ITEMS[0] = new_item("Back to main manu",NULL);
	sprintf(addactor,"Add new %s",actor_type);
	ACTOR_ITEMS[1] = new_item(addactor, NULL);
	if(menu == NULL) menu = new_menu(ACTOR_ITEMS);
    else {
		unpost_free_menu(menu);
	}
	int i = 2;
	for (ACTOR *actor = actors; actor !=NULL; actor = actor->next){
		ACTOR_ITEMS[i] = new_item(actor->name, NULL);
		set_item_userptr(ACTOR_ITEMS[i],actor);
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
	for (CMD *cmd = cmds; cmd !=NULL; cmd = cmd->next){
		CMDS_ITEMS[i] = new_item(cmds->name, NULL);
		set_item_userptr(CMDS_ITEMS[i],cmd);
		i++;
	}
	CMDS_ITEMS[amount+2] = (ITEM *)NULL;
    set_menu_items(menu,CMDS_ITEMS);
    menu_opts_on(menu,O_ONEVALUE);
    menu_opts_off(menu,O_SHOWDESC);
	post_menu(menu);
    return menu;
}

void edit_cmd(MENU *menu, CONTEXT *context){
	
	char *tmp = NULL;
	if(menu_text_editor(menu, &tmp)){
		save_state_context(context);
		if(context->cmd == NULL){
			context->cmd = malloc(sizeof(CMD));
			context->cmd->next = NULL;
			context->cmd->name = NULL;
			if(context->actor->cmds == NULL)
				context->actor->cmds = context->cmd;
			else{
				CMD *tmp = context->actor->cmds;
				for(; tmp->next != NULL; tmp = tmp->next);
				tmp->next = context->cmd;
			}
			context->cmd->next = NULL;
		}
		else free(context->cmd->name);
		context->cmd->name = tmp;
		editor_cmd_menu(menu,context->actor->cmds,cmd_len(context->actor->cmds));
	};
}

void new_cmd(MENU *menu, CONTEXT *context){
	edit_cmd(menu, context);
}

void editor_menu(MENU *menu, CONTEXT *context,int editor_type){
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
	//menu_type = editor_type;
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
			editor_cmd_menu(menu,context->cmd,cmd_len(context->cmd));
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
		menu_type = index;
		previous_menu = MAIN_MENU;
		break;
	case USER_MENU:
	case GROUP_MENU:
		editor_menu(menu,context,index);
		menu_type = index;
		previous_menu = MAIN_MENU;
		break;
	case 3:
		save_role_to_file(context->role);
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

int perform_action(MENU *menu,CONTEXT *context, int action, char input){
	ITEM *current = current_item(menu);
	int index = item_index(current);
	int amount = 0;
	char **elements = NULL;
	switch (menu_type)
	{
	case MAIN_MENU:
		return main_menu_selection(menu,current,context);
	case CAPS_MENU:
		if((!index && action ==ACTION_ENTER) || action == ACTION_BACK) {
			save_caps(menu,context->role);
			main_menu(menu);
			menu_type = MAIN_MENU;
			previous_menu = MAIN_MENU;
		}else if(action == ACTION_INPUT){
			search_in_items(menu,menu_items(menu),input);
			break;
		}else
			menu_driver(menu, REQ_TOGGLE_ITEM);
		break;
	case GROUP_MENU:
	case USER_MENU:
		if((!index && action ==ACTION_ENTER) || action == ACTION_BACK) {
			main_menu(menu);
			menu_type = MAIN_MENU;
			previous_menu = MAIN_MENU;
		}else if (index == 1) {
			previous_menu = menu_type;
			menu = editor_sysactors_menu(menu,menu_type);
			menu_type = ACTOR_SEL_MENU;
		}else if(action == ACTION_DELETE){
			context->role = delete_actor(current);
			reload_menu(menu,context);
		}else if(action == ACTION_ENTER){
			context->actor = (ACTOR *) item_userptr(current);
			menu = editor_cmd_menu(menu,context->actor->cmds,cmd_len(context->actor->cmds));
			previous_menu = menu_type;
			menu_type = CMDS_MENU;
		}
		break;
	case ACTOR_SEL_MENU: // new actor selection menu
		if(!index || action == ACTION_BACK){
			menu_type = previous_menu;
			previous_menu = MAIN_MENU;
			reload_menu(menu,context);
		} else
		{
			menu = editor_cmd_menu(menu,NULL,0);
			menu_type = CMDS_MENU;
		}
		break;
	case CMDS_MENU:
		if(!index || action == ACTION_BACK){
			menu_type = previous_menu;
			previous_menu = MAIN_MENU;
			reload_menu(menu,context);
			
		}else if (index == 1){
			new_cmd(menu,context);
		}else if (action == ACTION_DELETE){
			delete_cmd(current,context);
		}else if (action == ACTION_ENTER){
			edit_cmd(menu,context);
		}else if (action == ACTION_INPUT){
			search_in_items(menu,menu_items(menu),input);
		}
		break;

	default:
		fputs("Wrong state\n",stderr);
		break;
	}
	return CONTINUE;
}

static int print_help(int long_help)
{
	printf("Usage : editrole [role]\n");
	if (long_help) {
		printf("Edit a role through fancy interface.\n");
	}
	return 0;
}

int main(int argc, char *argv[])
{
	printf("Work in progress\n");
	exit(0);
	int status = CONTINUE, action = 0;
	
	MENU *my_menu = NULL;
	
	CONTEXT *context = init_context();
	

	if((argc < 2 && !print_help(false)) || !get_role(context->role,argv[1])) goto free_rscs;

	/* Initialize curses */
	initscr();
	cbreak();
	noecho();
	keypad(stdscr, TRUE);
	

	/* Initialize items */
	init_main_menu(&my_menu);
    main_menu(my_menu);
	int c;
	while (status != QUIT) {
		refresh();
		
		switch (c= getch()) {
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
			case 111:
				action = ACTION_DELETE;
				break;
			case 20:
				context->role = perform_undo();
				reload_menu(my_menu,context);
				break;
			default:
				action = ACTION_INPUT;
				
				break;
		}
		status = perform_action(my_menu,context, action,c);
	}
	free_rscs:
	free_menu(my_menu);
	endwin();
}

