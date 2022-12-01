#include "undo.h"
#include <stdlib.h>

static UNDO *undo;

ROLE *init_role(){
	extern UNDO* undo;
	undo = (UNDO*) malloc(sizeof(UNDO));
	undo->state = malloc(sizeof(ROLE));
	undo->previous = NULL;
	return undo->state;
}

ROLE *archive_role(){
	extern UNDO* undo;
	UNDO *new_undo = (UNDO*)malloc(sizeof(UNDO));
	new_undo->state = copy_role(undo->state);
	new_undo->previous = undo;
	undo = new_undo;
	return undo->state;
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
	return undo->state;
}

void free_undo_stack(){
	extern UNDO* undo;
	while(undo){
		perform_undo();
	}
}