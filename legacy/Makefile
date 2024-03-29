#Makefile for sr
#Author: Rémi Venant, Eddie BILLOIR
COMP = gcc

SR_VERSION = $(shell xmllint --xpath "string(/rootasrole/@version)" resources/rootasrole.xml)
SRC_DIR := src
MANAGER_DIR := new_role_manager
OBJ_DIR := obj
BIN_DIR := bin
TEST_DIR := tests/unit
WARNINGS := -Wall -Wextra
LIBCAP := -lcap -lcap-ng
LIBPAM := -lpam -lpam_misc
STDOPT = -std=c11
GDB_D = $(if $(GDB_DEBUG), -DGDB_DEBUG,)
OASAN = $(if $(ASAN),-fsanitize=address,)
ODEBUG = $(if $(DEBUG),-g $(GDB_D),-pedantic -Werror)
COVOPT := $(if $(COV),--coverage -fprofile-abs-path,)

ALLOPT := $(ODEBUG) $(OASAN) $(STDOPT) $(WARNINGS) $(COVOPT) -DSR_VERSION=\"$(SR_VERSION)\"

COMPOPTIONS = $(shell xml2-config --cflags) $(ALLOPT)
SR_LDOPTIONS := $(LIBCAP) $(LIBPAM) $(shell xml2-config --libs) $(ALLOPT)
LDUNIT := -lcriterion $(LIBCAP) -I$(SRC_DIR) $(shell xml2-config --libs) $(ALLOPT)
COMPUNIT := -lcriterion $(LIBCAP) -I$(SRC_DIR) $(shell xml2-config --cflags) $(ALLOPT)
EXECUTABLES := sr

OBJS := $(addprefix $(SRC_DIR)/,capabilities.o user.o xml_manager.o env.o sr.o params.o command.o)
BINS := $(addprefix $(BIN_DIR)/,sr)

all: $(BINS)

.PHONY: clean

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(COMP) -o $@ -c $< $(COMPOPTIONS)

$(OBJ_DIR)/%.o : $(TEST_DIR)/%.c | $(OBJ_DIR)
	$(COMP) -o $@ -c $< $(COMPUNIT)

$(OBJS): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(BIN_DIR)/sr: $(addprefix $(OBJ_DIR)/,capabilities.o xml_manager.o user.o env.o sr.o params.o command.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(SR_LDOPTIONS)

$(BIN_DIR)/unit_test: $(addprefix $(OBJ_DIR)/test_,xml_manager.o command.o params.o capabilities.o env.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDUNIT)

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

	
