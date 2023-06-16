#Makefile for sr
#Author: Rémi Venant
COMP = gcc

SRC_DIR := src
MANAGER_DIR := new_role_manager
OBJ_DIR := obj
BIN_DIR := bin
TEST_DIR := tests/unit
DEBUGOPTIONS := -g -fsanitize=address
WARNINGS := -Wall -Wextra -Werror -pedantic
LIBCAP := -lcap -lcap-ng
STDOPT=-std=c11

COMPOPTIONS = $(STDOPT) $(WARNINGS) $(shell xml2-config --cflags) $(DEBUGOPTIONS)
LDOPTIONS := $(STDOPT) $(LIBCAP) $(WARNINGS) $(DEBUGOPTIONS)
SR_LDOPTIONS := $(STDOPT) -lpam -lpam_misc $(WARNINGS) $(shell xml2-config --libs) $(DEBUGOPTIONS)
UNITOPTIONS := $(STDOPT) -lcriterion -fprofile-arcs -lgcov --coverage $(LIBCAP) $(WARNINGS) -I$(SRC_DIR) $(shell xml2-config --cflags) $(shell xml2-config --libs) -g -fsanitize=address
EXECUTABLES := sr

OBJS := $(addprefix $(SRC_DIR)/,capabilities.o user.o xml_manager.o env.o sr.o params.o command.o) $(addprefix $(MANAGER_DIR)/,help.o xml_manager.o role_manager.o undo.o list_manager.o verifier.o xmlNode.o addrole.o editrole.o deleterole.o)
BINS := $(addprefix $(BIN_DIR)/,sr)

all: $(BINS)

.PHONY: clean

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(COMP) -o $@ -c $< $(COMPOPTIONS)

$(OBJ_DIR)/%.o : $(TEST_DIR)/%.c | $(OBJ_DIR)
	$(COMP) -o $@ -c $< $(UNITOPTIONS)

$(OBJS): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(BIN_DIR)/sr: $(addprefix $(OBJ_DIR)/,capabilities.o xml_manager.o user.o env.o sr.o params.o command.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS) $(SR_LDOPTIONS)

$(BIN_DIR)/unit_test: $(addprefix $(OBJ_DIR)/test_,xml_manager.o command.o params.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(UNITOPTIONS)

$(BINS): | $(BIN_DIR)

$(BIN_DIR):
	mkdir $(BIN_DIR)

#run as root
install: $(BINS)
	cp $(BINS) /usr/bin
	setcap "=p" /usr/bin/sr

build_unit_test: clean $(BIN_DIR)/unit_test

unit_test: build_unit_test
	$(BIN_DIR)/unit_test --verbose=1

uninstall:
	rm -f /usr/bin/sr
	rm -f /usr/bin/capable
	chattr -i /etc/security/rootasrole.xml
	rm -f /etc/security/rootasrole.xml

clean:
	@rm -rf $(BIN_DIR) $(OBJ_DIR) ebpf/$(BIN_DIR) ebpf/$(OBJ_DIR)
	
