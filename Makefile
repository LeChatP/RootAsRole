#Makefile for sr
#Author: Rémi Venant
COMP = gcc

SRC_DIR := src
MANAGER_DIR := new_role_manager
OBJ_DIR := obj
BIN_DIR := bin
DEBUGOPTIONS := #-g -fsanitize=address

COMPOPTIONS = -Wall -Wextra -Werror -pedantic $(shell xml2-config --cflags) $(DEBUGOPTIONS)
LDOPTIONS := -Wall -Wextra -Werror -pedantic -lcap -lcap-ng -lmenu -lncurses $(DEBUGOPTIONS)
SR_LDOPTIONS := -lpam -lpam_misc $(shell xml2-config --libs) $(DEBUGOPTIONS)
EXECUTABLES := sr

OBJS := $(addprefix $(SRC_DIR)/,capabilities.o user.o xml_manager.o env.o sr.o) $(addprefix $(MANAGER_DIR)/,help.o xml_manager.o role_manager.o undo.o list_manager.o verifier.o xmlNode.o addrole.o editrole.o deleterole.o)
BINS := $(addprefix $(BIN_DIR)/,sr)

all: $(BINS)

.PHONY: clean

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(COMP) -o $@ -c $< $(COMPOPTIONS)

$(OBJ_DIR)/%.o : $(MANAGER_DIR)/%.c | $(OBJ_DIR)
	$(COMP) -o $@ -c $< $(COMPOPTIONS)

$(OBJS): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(BIN_DIR)/sr: $(addprefix $(OBJ_DIR)/,capabilities.o xml_manager.o user.o env.o sr.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS) $(SR_LDOPTIONS)

$(BIN_DIR)/sr_aux: $(addprefix $(OBJ_DIR)/,capabilities.o sr_aux.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS)

$(BIN_DIR)/addrole: $(addprefix $(OBJ_DIR)/,help.o list_manager.o verifier.o xmlNode.o addrole.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS) $(SR_LDOPTIONS)

$(BIN_DIR)/editrole: $(addprefix $(OBJ_DIR)/,xml_manager.o role_manager.o undo.o editrole.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS) $(SR_LDOPTIONS)

$(BIN_DIR)/deleterole: $(addprefix $(OBJ_DIR)/,help.o list_manager.o verifier.o xmlNode.o deleterole.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS) $(SR_LDOPTIONS)

$(BINS): | $(BIN_DIR)

$(BIN_DIR):
	mkdir $(BIN_DIR)

#run as root
install: $(BINS) install-ebpf
	cp $(BINS) /usr/bin
	setcap "=p" /usr/bin/sr

# append debug mode for debugger
debug: $(addprefix $(BIN_DIR)/,sr sr_aux addrole editrole deleterole)

#run as user
run-test:
	sr -r root -c "/usr/bin/python3 tests/__init__.py"

build-ebpf:
#	cd ebpf && make && cd ..

install-ebpf:
#	cd ebpf && make install && cd ..
	
uninstall:
	rm -f /usr/bin/sr /usr/bin/sr_aux

clean:
	@rm -rf $(BIN_DIR) $(OBJ_DIR) ebpf/$(BIN_DIR) ebpf/$(OBJ_DIR)
	
