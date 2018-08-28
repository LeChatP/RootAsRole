#Makefile for sr
#Author: Rémi Venant
COMP = gcc

SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin

COMPOPTIONS = -Wall -pedantic $(shell xml2-config --cflags)
LDOPTIONS := -Wall -pedantic -lcap -lcap-ng
SR_LDOPTIONS := -lpam -lpam_misc $(shell xml2-config --libs)
EXECUTABLES := sr sr_aux

OBJS := $(addprefix $(SRC_DIR)/,capabilities.o roles.o sr.o sr_aux.o sraux_management.o user.o)
BINS := $(addprefix $(BIN_DIR)/,sr sr_aux)

all: $(BINS)

.PHONY: clean

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(COMP) -o $@ -c $< $(COMPOPTIONS)

$(OBJS): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(BIN_DIR)/sr: $(addprefix $(OBJ_DIR)/,capabilities.o roles.o sr.o sraux_management.o user.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS) $(SR_LDOPTIONS)

$(BIN_DIR)/sr_aux: $(addprefix $(OBJ_DIR)/,capabilities.o sr_aux.o) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS) 

$(BINS): | $(BIN_DIR)

$(BIN_DIR):
	mkdir $(BIN_DIR)

install: $(addprefix $(BIN_DIR)/,sr sr_aux)
	cp $(BIN_DIR)/sr /usr/bin/sr
	setcap cap_setfcap,cap_setpcap+p /usr/bin/sr
	cp $(BIN_DIR)/sr_aux /usr/bin/sr_aux

uninstall:
	rm -f /usr/bin/sr /usr/bin/sr_aux

clean:
	@rm -rf $(BIN_DIR) $(OBJ_DIR)
	
