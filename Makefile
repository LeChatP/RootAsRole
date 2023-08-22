
PROFILE ?= debug
RELEASE = $(if $(filter $(PROFILE),release),--release,)
BIN_DIR := target/$(PROFILE)
SR_VERSION = $(shell xmllint --xpath "string(/rootasrole/@version)" resources/rootasrole.xml)
BINS := $(addprefix $(BIN_DIR)/,sr chsr)
.PHONY: $(BIN_DIR)/sr $(BIN_DIR)/chsr
$(BIN_DIR)/sr:
	cargo build $(RELEASE) --bin sr

$(BIN_DIR)/chsr:
	cargo build $(RELEASE) --bin chsr

$(BINS): | $(BIN_DIR)

$(BIN_DIR):
	mkdir $(BIN_DIR)

install: $(BINS)
	cp $(BINS) /usr/bin
	setcap "=p" /usr/bin/sr

test:
	cargo test

uninstall:
	rm -f /usr/bin/sr
	rm -f /usr/bin/capable
	chattr -i /etc/security/rootasrole.xml
	rm -f /etc/security/rootasrole.xml

clean:
	cargo clean