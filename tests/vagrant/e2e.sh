#!/bin/bash
# End-to-end checks of an installed RootAsRole, as root, in a throwaway virtual machine (see the
# Vagrantfile). It adds a user, a systemd unit and policy files, and removes them at the end.
# Each check prints PASS, SKIP or FAIL; the script fails if one check fails.
set -u

ROOT_FILE=/etc/security/rootasrole.json
POLICY_DIR=/etc/security/rootasrole.d
E2E_POLICY="$POLICY_DIR/e2e.json"
PLANTED_POLICY="$POLICY_DIR/planted.json"
TEST_USER=rar-e2e
UNIT=rar-e2e
FAILED=0

# 0: pass, 77: skip, anything else: fail
check() {
    local name=$1
    shift
    "$@"
    case $? in
        0) echo "PASS: $name" ;;
        77) echo "SKIP: $name" ;;
        *)
            echo "FAIL: $name"
            FAILED=1
            ;;
    esac
}

# the test user has no role but those of this script
as_user() {
    runuser -u "$TEST_USER" -- "$@"
}

immutable_policy() {
    grep -q '"immutable": *true' "$ROOT_FILE"
}

has_immutable_flag() {
    lsattr -d "$1" 2>/dev/null | awk '{print $1}' | grep -q i
}

# write a policy file like chsr: with the immutable flag when the policy is immutable
write_policy() {
    chattr -i "$POLICY_DIR" "$1" 2>/dev/null
    printf '%s\n' "$2" >"$1"
    chmod 600 "$1"
    if immutable_policy; then
        chattr +i "$1" "$POLICY_DIR"
    fi
}

remove_policy() {
    [ -e "$1" ] || return 0
    chattr -i "$POLICY_DIR" "$1" 2>/dev/null
    rm -f "$1"
    if immutable_policy; then
        chattr +i "$POLICY_DIR"
    fi
}

setup() {
    id "$TEST_USER" >/dev/null 2>&1 || useradd -m "$TEST_USER"
    printf '%s\n' "[Unit]" "Description=RootAsRole end-to-end test unit" \
        "[Service]" "ExecStart=/bin/sleep infinity" >"/etc/systemd/system/$UNIT.service"
    systemctl daemon-reload
    write_policy "$E2E_POLICY" "$(
        cat <<EOF
{
  "options": {
    "authentication": "skip",
    "path": { "default": "delete", "add": ["/usr/sbin", "/usr/bin", "/sbin", "/bin"] }
  },
  "roles": [{
    "name": "e2e",
    "actors": [{ "user": "$TEST_USER" }],
    "tasks": [
      { "name": "shell", "commands": ["/usr/bin/sh ^.*$"] },
      { "name": "date", "commands": ["/usr/bin/date"] },
      { "name": "echo", "commands": ["/usr/bin/echo ^hello( world)?$"] },
      {
        "name": "service",
        "cred": { "setuid": "root", "capabilities": [] },
        "commands": ["/usr/bin/systemctl ^(start|stop|restart) $UNIT$"]
      },
      {
        "name": "net-bind",
        "cred": { "capabilities": ["CAP_NET_BIND_SERVICE"] },
        "commands": ["/usr/bin/python3 ^-c .*$"]
      },
      {
        "name": "net-raw",
        "cred": { "capabilities": ["CAP_NET_RAW"] },
        "commands": ["/usr/bin/true"]
      }
    ]
  }]
}
EOF
    )"
}

cleanup() {
    systemctl stop "$UNIT" 2>/dev/null
    rm -f "/etc/systemd/system/$UNIT.service"
    systemctl daemon-reload
    remove_policy "$PLANTED_POLICY"
    remove_policy "$E2E_POLICY"
    userdel -r "$TEST_USER" 2>/dev/null
}

# the installation sets the immutable flag on the policy, its directory included
policy_is_immutable() {
    immutable_policy || return 77
    has_immutable_flag "$ROOT_FILE" &&
        has_immutable_flag "$POLICY_DIR" &&
        has_immutable_flag "$POLICY_DIR/default.json" &&
        has_immutable_flag "$E2E_POLICY"
}

# a policy file added without the immutable flag is refused, the same file with it is used
planted_policy_is_refused() {
    immutable_policy || return 77
    chattr -i "$POLICY_DIR"
    cat >"$PLANTED_POLICY" <<EOF
{
  "options": { "authentication": "skip" },
  "roles": [{
    "name": "planted",
    "actors": [{ "user": "$TEST_USER" }],
    "tasks": [{ "name": "id", "cred": { "setuid": "root" }, "commands": ["/usr/bin/id ^-u$"] }]
  }]
}
EOF
    chmod 600 "$PLANTED_POLICY"
    chattr +i "$POLICY_DIR"
    local without_flag with_flag
    without_flag=$(as_user dosr /usr/bin/id -u 2>/dev/null)
    chattr +i "$PLANTED_POLICY"
    with_flag=$(as_user dosr /usr/bin/id -u 2>/dev/null)
    remove_policy "$PLANTED_POLICY"
    [ -z "$without_flag" ] && [ "$with_flag" = 0 ]
}

# dosr ends like the command: killed by SIGTERM, the shell sees 143
signal_is_forwarded() {
    as_user dosr -r e2e -t shell /usr/bin/sh -c 'kill -TERM $$'
    [ $? -eq 143 ]
}

# a regular expression on the arguments, written without quotes
unquoted_regex() {
    [ "$(as_user dosr /usr/bin/echo hello world)" = "hello world" ] &&
        ! as_user dosr /usr/bin/echo hello there >/dev/null 2>&1
}

# a command written without arguments allows none
command_without_arguments_allows_none() {
    as_user dosr /usr/bin/date >/dev/null &&
        ! as_user dosr /usr/bin/date +%s >/dev/null 2>&1
}

# uid 0 without any capability manages a unit: systemd authorizes uid 0
root_without_capabilities_manages_a_unit() {
    as_user dosr /usr/bin/systemctl restart "$UNIT" &&
        systemctl is-active --quiet "$UNIT" &&
        ! as_user dosr /usr/bin/systemctl restart "$UNIT-other" >/dev/null 2>&1
}

# CAP_NET_BIND_SERVICE binds a port below 1024, the user alone cannot
capability_is_granted() {
    local bind='import socket; s = socket.socket(); s.bind(("127.0.0.1", 80))'
    if [ "$(sysctl -n net.ipv4.ip_unprivileged_port_start)" -gt 80 ] &&
        as_user /usr/bin/python3 -c "$bind" 2>/dev/null; then
        return 1
    fi
    as_user dosr -r e2e -t net-bind /usr/bin/python3 -c "$bind"
}

# a capability out of the bounding set is refused before the command runs
bounding_set_is_checked_first() {
    local out
    out=$(capsh --drop=cap_net_raw --user="$TEST_USER" -- -c 'dosr -r e2e -t net-raw /usr/bin/true' 2>&1)
    [ $? -ne 0 ] && grep -q 'cannot obtain' <<<"$out"
}

trap cleanup EXIT
setup
check "the policy, its directory included, is immutable" policy_is_immutable
check "a policy file without the immutable flag is refused" planted_policy_is_refused
check "dosr ends like a command killed by a signal" signal_is_forwarded
check "a regular expression without quotes" unquoted_regex
check "a command written without arguments allows none" command_without_arguments_allows_none
check "uid 0 without capabilities manages a unit" root_without_capabilities_manages_a_unit
check "CAP_NET_BIND_SERVICE is granted" capability_is_granted
check "the bounding set is checked before running the command" bounding_set_is_checked_first
exit "$FAILED"
