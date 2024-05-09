export PATH := $(shell echo $$HOME)/.cargo/bin:$(PATH)
PROFILE ?= release
RELEASE = $(if $(filter $(PROFILE),release),--release,)
BIN_DIR := target/$(PROFILE)
BINS := $(addprefix $(BIN_DIR)/,sr chsr capable)
PRIV_EXE ?= /usr/bin/sudo
.PHONY: $(BIN_DIR)/sr $(BIN_DIR)/chsr $(BIN_DIR)/capable
$(BIN_DIR)/sr:
	cargo build $(RELEASE) --bin sr || true

$(BIN_DIR)/chsr:
	cargo build $(RELEASE) --bin chsr || true

$(BIN_DIR)/capable:
	cargo xtask build-ebpf $(RELEASE) || true
	cargo build --package capable $(RELEASE) || true

$(BINS): | $(BIN_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

build: $(BINS)

install: build
ifneq (0, $(filter $(shell capsh --has-p=CAP_DAC_OVERRIDE,CAP_CHOWN 2&>/dev/null; echo $?), $(shell id -u)))
	$(PRIV_EXE) cp -f $(BINS) /usr/bin
	$(PRIV_EXE) chown root:root /usr/bin/sr /usr/bin/chsr /usr/bin/capable
	$(PRIV_EXE) chmod 0555 /usr/bin/sr /usr/bin/chsr /usr/bin/capable
	$(PRIV_EXE) setcap "=p" /usr/bin/sr
	$(PRIV_EXE) setcap cap_dac_override,cap_sys_admin,cap_sys_ptrace+ep /usr/bin/capable
else ifneq (0, $(shell capsh --has-p=CAP_SETFCAP 2&>/dev/null; echo $?))
	@echo "You must have CAP_SETFCAP privilege to perform installation."
else
	cp -f $(BINS) /usr/bin
	chown root:root /usr/bin/sr /usr/bin/chsr /usr/bin/capable
	chmod 0555 /usr/bin/sr /usr/bin/chsr /usr/bin/capable
	setcap "=p" /usr/bin/sr
	setcap cap_dac_override,cap_sys_admin,cap_sys_ptrace+ep /usr/bin/capable
endif


test:
	cargo test

cov:
	cargo tarpaulin --bin chsr --bin sr --exclude-files capable* capable-ebpf/src/vmlinux.rs capable/src/main.rs build.rs --out Lcov --out Html

uninstall:
ifneq (0, $(filter $(shell capsh --has-p=CAP_DAC_OVERRIDE 2&>/dev/null; echo $?), $(shell id -u)))
	@echo "You must have CAP_DAC_OVERRIDE privilege or be root"
else ifneq (0, $(shell capsh --has-p=CAP_LINUX_IMMUTABLE 2&>/dev/null; echo $?))
	@echo "You must have CAP_LINUX_IMMUTABLE privilege"
else
	rm -f /usr/bin/sr
	rm -f /usr/bin/chsr
	rm -f /usr/bin/capable
	chattr -i /etc/security/rootasrole.json
	rm -f /etc/security/rootasrole.json
endif

clean:
	cargo clean