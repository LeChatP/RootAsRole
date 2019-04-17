#Makefile for tests
#Author: Eddie BILLOIR
COMP = gcc

SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin
DEBUGOPTIONS := -g

COMPOPTIONS = -Wall -Wextra -Werror -pedantic $(shell xml2-config --cflags) $(DEBUGOPTIONS)
LDOPTIONS := -Wall -Wextra -Werror -pedantic -lcap -lcap-ng $(DEBUGOPTIONS)
SR_LDOPTIONS := -Wall -Wextra -Werror -lpam -lpam_misc $(shell xml2-config --libs) $(DEBUGOPTIONS)
EXECUTABLES := runTests

OBJS := $(addprefix $(OBJ_DIR)/,test.o allTests.o testScenarios.o testObserver.o runAllTests.o)
BINS := $(BIN_DIR)/runTests

all: $(BINS)

.PHONY: clean

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(COMP) -o $@ -c $< $(COMPOPTIONS)

$(OBJS): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(BIN_DIR)/runTests: $(OBJS) | $(BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS) $(SR_LDOPTIONS)

$(BINS): | $(BIN_DIR)

$(BIN_DIR):
	mkdir $(BIN_DIR)

build: $(BIN_DIR)/runTests

clean:
	@rm -rf $(BIN_DIR) $(OBJ_DIR)
	