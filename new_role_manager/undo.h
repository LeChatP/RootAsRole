#include "role_manager.h"

typedef struct _undo UNDO;

struct _undo {
	ROLE *state;
	UNDO *previous;
};

ROLE *init_role();

ROLE *archive_role();

ROLE *current_role();

ROLE *perform_undo();

void free_undo_stack();