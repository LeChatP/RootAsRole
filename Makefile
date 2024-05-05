CARGO ?= /usr/bin/cargo
PROFILE ?= release
RELEASE = $(if $(filter $(PROFILE),release),--release,)
BIN_DIR := target/$(PROFILE)
BINS := $(addprefix $(BIN_DIR)/,sr chsr capable)
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
	cp -f $(BINS) /usr/bin
	chown root:root /usr/bin/sr /usr/bin/chsr /usr/bin/capable
	chmod 0555 /usr/bin/sr /usr/bin/chsr /usr/bin/capable
	setcap "=p" /usr/bin/sr
	setcap cap_dac_override,cap_sys_admin,cap_sys_ptrace+ep /usr/bin/capable

test:
	cargo test

cov:
	cargo tarpaulin --bin chsr --bin sr --exclude-files capable* capable-ebpf/src/vmlinux.rs capable/src/main.rs build.rs --out Lcov --out Html

uninstall:
	rm -f /usr/bin/sr
	rm -f /usr/bin/chsr
	rm -f /usr/bin/capable
	chattr -i /etc/security/rootasrole.xml
	rm -f /etc/security/rootasrole.xml

clean:
	cargo clean