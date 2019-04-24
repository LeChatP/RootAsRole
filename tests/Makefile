#Makefile for tests
#Author: Eddie BILLOIR
COMP = gcc

SR_SRC_DIR:= ../src
SRC_DIR := src
SR_OBJ_DIR := ../obj
OBJ_DIR := obj
SR_BIN_DIR:= ../bin
BIN_DIR := bin
DEBUGOPTIONS := -g

COMPOPTIONS = -Wall -Wextra -Werror -pedantic $(shell xml2-config --cflags) $(DEBUGOPTIONS)
LDOPTIONS := -Wall -Wextra -Werror -pedantic -lcap -lcap-ng $(DEBUGOPTIONS)
SR_LDOPTIONS := -Wall -Wextra -Werror -lpam -lpam_misc $(shell xml2-config --libs) $(DEBUGOPTIONS)
EXECUTABLES := runTests

SR_OBJS = $(addprefix $(SR_OBJ_DIR)/, user.o)
OBJS := $(addprefix $(OBJ_DIR)/, utilsTests.o test.o allTests.o testScenarios.o testObserver.o testRoles.o runAllTests.o)
BINS := $(BIN_DIR)/runTests

all: $(BINS)

.PHONY: clean

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(COMP) -o $@ -c $< $(COMPOPTIONS)

$(SR_OBJ_DIR)/%.o: $(SR_SRC_DIR)/%.c | $(SR_OBJ_DIR)
	$(COMP) -o $@ -c $< $(COMPOPTIONS)

$(OBJS): | $(OBJ_DIR)

$(SR_OBJS): | $(SR_OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(SR_OBJ_DIR):
	mkdir $(SR_OBJ_DIR)

$(BIN_DIR)/runTests: $(OBJS) $(SR_OBJS) | $(BIN_DIR) $(SR_BIN_DIR)
	$(COMP) -o $@ $^ $(LDOPTIONS) $(SR_LDOPTIONS)

$(BINS): | $(BIN_DIR)

$(BIN_DIR):
	mkdir $(BIN_DIR)

build: $(BIN_DIR)/runTests

clean:
	@rm -rf $(BIN_DIR) $(OBJ_DIR)
	