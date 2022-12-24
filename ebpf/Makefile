#Makefile for capable
#Author: Eddie BILLOIR
UNAME=$(shell uname -r)

ifeq ($(shell uname -a | grep -q debian && echo 1),1)
KERNEL ?= /usr/src/linux-headers-${UNAME}
COMMON_KERNEL ?= /usr/src/linux-headers-$(shell uname -r | sed -e 's:\(.*\)-[^-]*:\1:g')-common

LINUXINCLUDE += -I$(COMMON_KERNEL)/arch/$(INCLUDE_ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(COMMON_KERNEL)/arch/$(INCLUDE_ARCH)/include/generated
LINUXINCLUDE += -I$(COMMON_KERNEL)/arch/$(INCLUDE_ARCH)/include
LINUXINCLUDE += -I$(COMMON_KERNEL)/arch/$(INCLUDE_ARCH)/include/uapi
LINUXINCLUDE += -I$(COMMON_KERNEL)/include
LINUXINCLUDE += -I$(COMMON_KERNEL)/include/uapi
LINUXINCLUDE += -I$(COMMON_KERNEL)/include/generated/uapi
LINUXINCLUDE += -include $(COMMON_KERNEL)/include/linux/kconfig.h
else
KERNEL ?= /lib/modules/${UNAME}/build
LINUXINCLUDE += -include $(KERNEL)/include/linux/kconfig.h
endif
NOSTDINC_FLAGS ?= -nostdinc -isystem $(shell $(CC) -print-file-name=include)
ARCH=$(shell uname -m | sed 's/x86_64/x86/' | sed 's/i386/x86/')
ifeq (${ARCH},$(filter ${ARCH},arm64 aarch64))
INCLUDE_ARCH = $(shell echo '${ARCH}' | sed 's/aarch64/arm64/')
EXTRA_CFLAGS = -D__TARGET_ARCH_${ARCH}
else
INCLUDE_ARCH = ${ARCH}
EXTRA_CFLAGS = -D__ASM_SYSREG_H -fcf-protection
endif

test_kernel:
ifeq ($(wildcard ${KERNEL}),)
	@echo "$(echo -e "\033[0;31m")ERROR:	Unable to find kernel headers. Please install the kernel headers for your kernel."
	@echo "	For example, on Ubuntu, run : sudo apt install linux-headers-\`shell uname -r\`"
	@echo "	If you've just updated your kernel, you may need to reboot your system."
	@echo "	If you have already installed the kernel headers, make sure you have the correct kernel headers for your kernel."
	@echo " 	For example, if you are running a custom kernel, make sure you have the kernel headers for that kernel."
	@echo "	If you are running a custom kernel, you can specify the kernel headers directory by setting the KERNEL variable."
	@echo "	For example, if your kernel headers are in /usr/src/linux-headers-5.4.0-42-generic, run make KERNEL=/usr/src/linux-headers-5.4.0-42-generic$(echo -e "\033[0m")"
	@exit 1
endif

LINUXINCLUDE += -I$(KERNEL)/arch/$(INCLUDE_ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNEL)/arch/$(INCLUDE_ARCH)/include/generated
LINUXINCLUDE += -I$(KERNEL)/arch/$(INCLUDE_ARCH)/include
LINUXINCLUDE += -I$(KERNEL)/arch/$(INCLUDE_ARCH)/include/uapi
LINUXINCLUDE += -I$(KERNEL)/include
LINUXINCLUDE += -I$(KERNEL)/include/uapi
LINUXINCLUDE += -I$(KERNEL)/include/generated/uapi
LINUXINCLUDE += -I$(KER_DIR)
LINUXINCLUDE += -D KBUILD_MODNAME=\"capable\" -D __BPF_TRACING__  # you must precisely include the file

ifeq ($(uname -r | cut -c1-5),$(5.0.0))
EXTRA_CFLAGS+=-DK50
endif
LDFLAGS= -lelf

LLC ?= llc
CLANG ?= clang
CC = gcc

SRC_DIR := src
OBJ_DIR := obj
BIN_DIR := bin
KER_DIR := src/kernel

COMPOPTIONS = -O2 -Wall -pedantic -I ./ -g
LDOPTIONS := -O2 -Wall -pedantic -lcap -lcap-ng -I ./ -lelf -g 
EXECUTABLE := capable

OBJS := $(addprefix $(OBJ_DIR)/,bpf.o bpf_load.o capable.o sorting.o)
BINS := $(BIN_DIR)/$(EXECUTABLE) $(addprefix $(BIN_DIR)/,capable_kern.o nscapable_kern.o)

all: test_kernel $(BINS) 

.PHONY: clean

$(OBJ_DIR)/%_kern.ll: $(KER_DIR)/%_kern.c
	$(CLANG) -S $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
	    -D__KERNEL__  -Wno-unused-value -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-gnu-variable-sized-type-not-at-end \
	    -Wno-tautological-compare \
	    -O2 -emit-llvm -fno-stack-protector -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(COMPOPTIONS) -o $@ -c $<

$(BIN_DIR)/%_kern.o: $(OBJ_DIR)/%_kern.ll
	$(LLC) -march=bpf -filetype=obj -o $@ $<

$(OBJS): | $(OBJ_DIR)

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

$(BIN_DIR)/$(EXECUTABLE): $(SR_OBJS) $(OBJS) | $(SR_BIN_DIR) $(BIN_DIR)
	$(CC) $^ -o $@ $(LDOPTIONS)

$(BINS): | $(BIN_DIR)

$(BIN_DIR):
	mkdir $(BIN_DIR)

build: test_kernel $(BINS)

install: test_kernel $(BINS)
	mkdir -p /usr/lib/RootAsRole
	cp $(BIN_DIR)/$(EXECUTABLE) /usr/bin
	cp $(BIN_DIR)/*_kern.o /usr/lib/RootAsRole
	setcap cap_dac_override,cap_sys_admin,cap_sys_ptrace+ep /usr/bin/capable

clean:
	@rm -rf $(BIN_DIR) $(OBJ_DIR) $(SR_OBJS)
