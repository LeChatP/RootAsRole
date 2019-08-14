#Makefile for capable
#Author: Eddie BILLOIR
KERNEL ?= /lib/modules/$(shell uname -r)/build
NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include)
ARCH=$(shell uname -m | sed 's/x86_64/x86/' | sed 's/i386/x86/')

LINUXINCLUDE += -I$(KERNEL)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNEL)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNEL)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(KERNEL)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(KERNEL)/include
LINUXINCLUDE += -I$(KERNEL)/include/uapi
LINUXINCLUDE += -include $(KERNEL)/include/linux/kconfig.h
LINUXINCLUDE += -I$(KERNEL)/include/generated/uapi
LINUXINCLUDE += -I$(KER_DIR)
LINUXINCLUDE += -include asm_goto_workaround.h -D __BPF_TRACING__  # you must precisely include the file

EXTRA_CFLAGS=-Werror

LDFLAGS= -lelf

LLC ?= llc
CLANG ?= clang
CC = gcc

SRC_DIR := src
SR_SRC_DIR := ../src
OBJ_DIR := obj
SR_OBJ_DIR := ../obj
BIN_DIR := bin
SR_BIN_DIR := ../bin
KER_DIR := src/kernel

COMPOPTIONS = -O2 -Wall -pedantic -I ./ -g
LDOPTIONS := -O2 -Wall -pedantic -lcap -lcap-ng -I ./ -lelf -g 
EXECUTABLE := capable

OBJS := $(addprefix $(OBJ_DIR)/,bpf.o bpf_load.o capable.o sorting.o)
SR_OBJS:= $(addprefix $(SR_OBJ_DIR)/,capabilities.o)
BINS := $(BIN_DIR)/$(EXECUTABLE) $(addprefix $(BIN_DIR)/,capable_kern.o nscapable_kern.o)

all: $(BINS) 

.PHONY: clean

$(OBJ_DIR)/%_kern.ll: $(KER_DIR)/%_kern.c
	$(CLANG) -S $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
	    -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-gnu-variable-sized-type-not-at-end \
	    -Wno-tautological-compare \
	    -O2 -emit-llvm -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(COMPOPTIONS) -o $@ -c $<

$(SR_OBJ_DIR)/%.o : $(SR_SRC_DIR)/%.c | $(SR_OBJ_DIR)
	$(CC) $(COMPOPTIONS) -o $@ -c $<

$(BIN_DIR)/%_kern.o: $(OBJ_DIR)/%_kern.ll
	$(LLC) -march=bpf -filetype=obj -o $@ $<

$(OBJS): | $(OBJ_DIR)

$(SR_OBJS): | $(SR_OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(SR_OBJ_DIR):
	mkdir $(SR_OBJ_DIR)

$(BIN_DIR)/$(EXECUTABLE): $(SR_OBJS) $(OBJS) | $(SR_BIN_DIR) $(BIN_DIR)
	$(CC) $^ -o $@ $(LDOPTIONS)

$(BINS): | $(BIN_DIR)

$(BIN_DIR):
	mkdir $(BIN_DIR)

$(SR_BIN_DIR):
	mkdir $(SR_BIN_DIR)

build: $(BINS)


install: $(BINS)
	id -u capable &>/dev/null || useradd capable -MNr -s /usr/sbin/nologin -d /nonexistent -c "Capable from RootAsRole,,,"
	mkdir -p /usr/lib/RootAsRole&&cp $(BIN_DIR)/$(EXECUTABLE:=_kern.o) /usr/lib/RootAsRole
	cp $(BIN_DIR)/$(EXECUTABLE) /usr/bin
	cp $(BIN_DIR)/*_kern.o /usr/lib/RootAsRole
	setcap cap_dac_override,cap_sys_admin,cap_sys_ptrace+ep /usr/bin/capable

clean:
	@rm -rf $(BIN_DIR) $(OBJ_DIR) $(SR_OBJS)
