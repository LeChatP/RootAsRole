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
TEST_PASSWORD=rar-e2e-password
UNIT=rar-e2e
PAM_SERVICE=/etc/pam.d/dosr
PAM_SERVICE_BACKUP=/etc/pam.d/.dosr.rar-e2e
PAM_ENV_FILE=/etc/rar-e2e.env
BIG_GROUP=rar-e2e-big
GROUP_BACKUP=/etc/.group.rar-e2e
GSHADOW_BACKUP=/etc/.gshadow.rar-e2e
TTY_SCRIPT=/tmp/rar-e2e-tty.sh
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
    # the version of the installed policy, without which chsr does not edit the file
    local version
    version=$(sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$ROOT_FILE" | head -n 1)
    write_policy "$E2E_POLICY" "$(
        cat <<EOF
{
  "version": "$version",
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
        "options": { "execinfo": "show" },
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
      },
      {
        "name": "env",
        "options": {
          "env": { "default": "delete", "keep": ["RAR_E2E_KEPT"], "check": ["RAR_E2E_CHECKED"] }
        },
        "commands": ["/usr/bin/env"]
      },
      {
        "name": "target-groups",
        "cred": { "setuid": "nobody" },
        "commands": ["/usr/bin/id ^-G$"]
      },
      {
        "name": "caller-groups",
        "cred": { "setuid": "nobody", "setgid": { "from": "caller" } },
        "commands": ["/usr/bin/id ^-G$"]
      },
      { "name": "alternation", "commands": ["/usr/bin/echo ^one|two$"] },
      {
        "name": "missing-group",
        "cred": { "setgid": "rar-e2e-missing" },
        "commands": ["/usr/bin/whoami"]
      },
      {
        "name": "tty-caller",
        "cred": { "setuid": "nobody" },
        "commands": ["/usr/bin/sh $TTY_SCRIPT"]
      },
      {
        "name": "tty-target",
        "options": { "tty": { "owner": "target" } },
        "cred": { "setuid": "nobody" },
        "commands": ["/usr/bin/sh $TTY_SCRIPT"]
      },
      {
        "name": "password",
        "options": {
          "authentication": "perform",
          "password": { "tries": 3, "delay": "00:00:01" }
        },
        "commands": ["/usr/bin/true"]
      }
    ]
  }, {
    "name": "e2e-guarded",
    "actors": [{ "user": "$TEST_USER" }],
    "ssd": ["e2e-other"],
    "tasks": [{ "name": "gid", "commands": ["/usr/bin/id ^-g$"] }]
  }, {
    "name": "e2e-other",
    "actors": [{ "group": "$BIG_GROUP" }],
    "tasks": []
  }]
}
EOF
    )"
}

# the PAM service of dosr as installed, without the line added by pam_env_is_filtered
restore_pam_service() {
    if [ -e "$PAM_SERVICE_BACKUP" ]; then
        mv -f "$PAM_SERVICE_BACKUP" "$PAM_SERVICE"
    fi
    rm -f "$PAM_ENV_FILE"
}

# /etc/group and /etc/gshadow as they were before ssd_role_disabled_by_a_failed_lookup
restore_groups() {
    if [ -e "$GROUP_BACKUP" ]; then
        mv -f "$GROUP_BACKUP" /etc/group
    fi
    if [ -e "$GSHADOW_BACKUP" ]; then
        mv -f "$GSHADOW_BACKUP" /etc/gshadow
    fi
}

cleanup() {
    restore_pam_service
    restore_groups
    systemctl stop "$UNIT" 2>/dev/null
    rm -f "/etc/systemd/system/$UNIT.service"
    systemctl daemon-reload
    remove_policy "$PLANTED_POLICY"
    remove_policy "$E2E_POLICY"
    rm -f "$TTY_SCRIPT"
    userdel -r "$TEST_USER" 2>/dev/null
}

# the installed binaries are files of root, not shared with the build tree (one link), and dosr
# has its file capabilities
installed_binaries_belong_to_root() {
    [ "$(stat -c '%u %h' /usr/bin/dosr)" = "0 1" ] &&
        [ "$(stat -c '%u %h' /usr/bin/chsr)" = "0 1" ] &&
        getcap /usr/bin/dosr | grep -q '=p'
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

# the variables that PAM modules set reach the command through the env filter of the task, and
# never replace the variables of dosr nor the ones of the user that the task keeps; pam_env is
# added for this check, since the PAM service of Debian does not run it
pam_env_is_filtered() {
    local out user_out
    cp -p "$PAM_SERVICE" "$PAM_SERVICE_BACKUP" || return 1
    printf '%s\n' RAR_E2E_KEPT=pam RAR_E2E_DROPPED=pam RAR_E2E_CHECKED=/unsafe PATH=/tmp/rar-e2e \
        >"$PAM_ENV_FILE"
    echo "session optional pam_env.so readenv=1 envfile=$PAM_ENV_FILE user_readenv=0" \
        >>"$PAM_SERVICE"
    out=$(as_user dosr -r e2e -t env /usr/bin/env)
    user_out=$(as_user env RAR_E2E_KEPT=user dosr -r e2e -t env /usr/bin/env)
    restore_pam_service
    grep -qx RAR_E2E_KEPT=pam <<<"$out" &&
        ! grep -q '^RAR_E2E_DROPPED=' <<<"$out" &&
        ! grep -q '^RAR_E2E_CHECKED=' <<<"$out" &&
        ! grep -qx PATH=/tmp/rar-e2e <<<"$out" &&
        grep -qx RAR_E2E_KEPT=user <<<"$user_out"
}

# a fresh authentication: no timestamp cookie, no failure counted by pam_faillock (Arch)
forget_authentications() {
    as_user dosr -K >/dev/null 2>&1
    if command -v faillock >/dev/null; then
        faillock --user "$TEST_USER" --reset
    fi
}

# a wrong password is asked again, up to the tries of the policy; the cookie of a successful
# authentication would skip the password, so the refusal is checked first
password_is_asked_again() {
    local out
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd || return 1
    forget_authentications
    if printf '%s\n' wrong wrong wrong "$TEST_PASSWORD" |
        as_user dosr -S -r e2e -t password /usr/bin/true >/dev/null 2>&1; then
        return 1
    fi
    forget_authentications
    out=$(printf '%s\n' wrong wrong "$TEST_PASSWORD" |
        as_user dosr -S -r e2e -t password /usr/bin/true 2>&1) || return 1
    forget_authentications
    [ "$(grep -c 'Sorry, try again.' <<<"$out")" -eq 2 ]
}

# a task that skips the authentication (date) gives no cookie: the task password, run after it
# from the same shell (same parent and session, the scope of the cookie), still asks the
# password and refuses wrong ones
skipped_authentication_gives_no_cookie() {
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd || return 1
    forget_authentications
    if as_user sh -c "dosr -r e2e -t date /usr/bin/date >/dev/null && printf '%s\\n' wrong wrong wrong | dosr -S -r e2e -t password /usr/bin/true" >/dev/null 2>&1; then
        forget_authentications
        return 1
    fi
    forget_authentications
}

# a failed lookup of an actor disables the roles with a separation of duties: the members of
# a group take more than the 1 MiB that the lookups of dosr allow, getgrnam_r fails with ERANGE
ssd_role_disabled_by_a_failed_lookup() {
    local gid before after members since
    # not id -u, which planted_policy_is_refused checks: this role would be chosen for it
    gid=$(id -g "$TEST_USER")
    cp -p /etc/group "$GROUP_BACKUP" && cp -p /etc/gshadow "$GSHADOW_BACKUP" || return 1
    groupadd "$BIG_GROUP" || {
        restore_groups
        return 1
    }
    before=$(as_user dosr -r e2e-guarded -t gid /usr/bin/id -g 2>/dev/null)
    # one argument is limited to 128 KiB: the member list goes through a file
    members=$(mktemp)
    seq -f 'rar%07g' 1 120000 | paste -sd, >"$members"
    awk -F: -v OFS=: -v group="$BIG_GROUP" -v list="$members" \
        'BEGIN { getline all < list } $1 == group { $4 = all } { print }' \
        /etc/group >"$members.group"
    cat "$members.group" >/etc/group
    since=$(date +%s)
    after=$(as_user dosr -r e2e-guarded -t gid /usr/bin/id -g 2>/dev/null)
    rm -f "$members" "$members.group"
    restore_groups
    [ "$before" = "$gid" ] && [ "$after" != "$gid" ] || return 1
    # the refusal comes from the lookup, when the journal tells
    if command -v journalctl >/dev/null; then
        journalctl -q --since "@$since" | grep -q "Cannot look up the group $BIG_GROUP"
    fi
}

# with the policy directory of the installation, chsr edits default.json, and leaves the root
# file and the other policy files as they are
chsr_edits_the_default_file() {
    local root_before e2e_before found
    [ -f "$POLICY_DIR/default.json" ] || return 77
    root_before=$(sha256sum <"$ROOT_FILE")
    e2e_before=$(sha256sum <"$E2E_POLICY")
    chsr role rar-e2e-chsr create || return 1
    found=$(grep -c '"rar-e2e-chsr"' "$POLICY_DIR/default.json")
    chsr role rar-e2e-chsr delete || return 1
    [ "$found" -ge 1 ] &&
        ! grep -q '"rar-e2e-chsr"' "$POLICY_DIR/default.json" &&
        [ "$(sha256sum <"$ROOT_FILE")" = "$root_before" ] &&
        [ "$(sha256sum <"$E2E_POLICY")" = "$e2e_before" ] &&
        chsr list | grep -q "$POLICY_DIR/default.json"
}

# a regular expression of several words written with chsr is matched by dosr: chsr used to quote
# each of its words, and dosr never matched it
chsr_regex_is_matched_by_dosr() {
    local typed='/usr/bin/echo ^chsr (one|two) [^ ]+$' result=1
    chsr file e2e.json r e2e t chsr-regex add || return 1
    if chsr file e2e.json r e2e t chsr-regex cmd wl add "$typed" &&
        grep -qF "\"$typed\"" "$E2E_POLICY" &&
        [ "$(as_user dosr -r e2e -t chsr-regex /usr/bin/echo chsr two words)" = "chsr two words" ] &&
        ! as_user dosr -r e2e -t chsr-regex /usr/bin/echo chsr three words >/dev/null 2>&1; then
        result=0
    fi
    chsr file e2e.json r e2e t chsr-regex del || return 1
    return "$result"
}

# the executions are logged under the name dosr, no longer sr
dosr_logs_under_its_name() {
    local since
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    as_user dosr /usr/bin/date >/dev/null || return 1
    for _ in 1 2 3 4 5; do
        if journalctl -t dosr --since "$since" -o cat | grep -q 'TASK=date ;.*COMMAND=/usr/bin/date'; then
            ! journalctl -t sr --since "$since" -o cat | grep -q 'COMMAND=/usr/bin/date'
            return
        fi
        sleep 1
    done
    return 1
}

# chsr is confined by Landlock, even without vim: one missing optional path made the whole ruleset
# fail; root itself cannot make chsr read a file outside the policy
chsr_is_confined_by_landlock() {
    local since out
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    out=$(chsr convert --from json /etc/hostname json "$POLICY_DIR/rar-e2e-convert.json" 2>&1)
    remove_policy "$POLICY_DIR/rar-e2e-convert.json"
    if journalctl -t chsr --since "$since" -o cat | grep -q 'Failed to apply landlock' ||
        ! grep -qi 'permission denied' <<<"$out"; then
        echo "$out" >&2
        return 1
    fi
}

# the groups of id -G, sorted
sorted_groups() {
    tr ' ' '\n' | sort -n | tr '\n' ' '
}

# a task that changes the user without setgid gives the groups of the target user, as a login
# does, not the ones of the caller
groups_of_the_target_user() {
    local got expected
    got=$(as_user dosr -r e2e -t target-groups /usr/bin/id -G | sorted_groups)
    expected=$(id -G nobody | sorted_groups)
    [ "$got" = "$expected" ] && [ "$got" != "$(as_user id -G | sorted_groups)" ]
}

# "from": "caller" keeps the groups of the caller
groups_of_the_caller_with_from() {
    local got
    got=$(as_user dosr -r e2e -t caller-groups /usr/bin/id -G | sorted_groups)
    [ "$got" = "$(as_user id -G | sorted_groups)" ]
}

# a task whose group does not exist is left out, and the log says why: the group was dropped, so
# the command ran with the primary group of the caller
missing_group_leaves_the_task_out() {
    local since
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    as_user dosr -r e2e -t missing-group /usr/bin/whoami >/dev/null 2>&1 && return 1
    for _ in 1 2 3 4 5; do
        journalctl -t dosr --since "$since" -o cat |
            grep -q 'e2e/missing-group cannot run: the group rar-e2e-missing does not exist' &&
            return 0
        sleep 1
    done
    return 1
}

# a top-level alternation is anchored on both sides: ^one|two$ allows one or two alone, no longer
# any arguments that start with one or end with two
alternation_is_anchored() {
    [ "$(as_user dosr -r e2e -t alternation /usr/bin/echo one)" = "one" ] &&
        ! as_user dosr -r e2e -t alternation /usr/bin/echo one more >/dev/null 2>&1 &&
        ! as_user dosr -r e2e -t alternation /usr/bin/echo say two >/dev/null 2>&1
}

# -- ends the options of dosr
double_dash_ends_the_options() {
    as_user dosr -r e2e -t date -- /usr/bin/date >/dev/null
}

# dosr -i shows None for a task whose capabilities are an empty set
info_shows_no_capabilities_as_none() {
    as_user dosr -i -r e2e -t service /usr/bin/systemctl start "$UNIT" |
        grep -qx 'With capabilities: None'
}

# the owner of the terminal of a task run as nobody through a terminal, and whether the command
# can reopen it by its name, as pinentry does through GPG_TTY
terminal_seen_by() {
    printf '%s\n' 't=$(tty)' 'stat -c %U "$t"' \
        'if { true <>"$t"; } 2>/dev/null; then echo reopened; else echo refused; fi' >"$TTY_SCRIPT"
    chmod 644 "$TTY_SCRIPT"
    # no input: script would copy into the terminal what is left on the input of the provisioner
    as_user script -qec "dosr -r e2e -t $1 /usr/bin/sh $TTY_SCRIPT" /dev/null </dev/null |
        tr -d '\r'
}

# by default, the terminal stays with the caller: nobody cannot reopen it
terminal_stays_with_the_caller() {
    local out
    out=$(terminal_seen_by tty-caller)
    [ "$out" = "$(printf '%s\n' "$TEST_USER" refused)" ] || {
        echo "$out" >&2
        return 1
    }
}

# "tty": {"owner": "target"} gives the terminal to the user that the command runs as
terminal_given_to_the_target() {
    local out
    out=$(terminal_seen_by tty-target)
    [ "$out" = "$(printf '%s\n' nobody reopened)" ] || {
        echo "$out" >&2
        return 1
    }
}

trap cleanup EXIT
setup
check "the installed binaries belong to root, dosr has its capabilities" installed_binaries_belong_to_root
check "the policy, its directory included, is immutable" policy_is_immutable
check "a policy file without the immutable flag is refused" planted_policy_is_refused
check "dosr ends like a command killed by a signal" signal_is_forwarded
check "a regular expression without quotes" unquoted_regex
check "a command written without arguments allows none" command_without_arguments_allows_none
check "uid 0 without capabilities manages a unit" root_without_capabilities_manages_a_unit
check "CAP_NET_BIND_SERVICE is granted" capability_is_granted
check "the bounding set is checked before running the command" bounding_set_is_checked_first
check "the variables of pam_env go through the env filter of the task" pam_env_is_filtered
check "a wrong password is asked again, up to the tries of the policy" password_is_asked_again
check "a task that skips the authentication gives no cookie" skipped_authentication_gives_no_cookie
check "a failed lookup of an actor disables the roles with ssd" ssd_role_disabled_by_a_failed_lookup
check "chsr edits default.json of the policy directory" chsr_edits_the_default_file
check "a regular expression written with chsr is matched by dosr" chsr_regex_is_matched_by_dosr
check "the executions are logged under the name dosr" dosr_logs_under_its_name
check "chsr is confined by Landlock" chsr_is_confined_by_landlock
check "-- ends the options of dosr" double_dash_ends_the_options
check "dosr -i shows None for a task without capabilities" info_shows_no_capabilities_as_none
check "a task that changes the user gives the groups of the target user" groups_of_the_target_user
check "from: caller keeps the groups of the caller" groups_of_the_caller_with_from
check "a task whose group does not exist is left out" missing_group_leaves_the_task_out
check "a top-level alternation is anchored on both sides" alternation_is_anchored
check "the terminal of a command run as another user stays with the caller" terminal_stays_with_the_caller
check "tty owner target gives the terminal to the user of the command" terminal_given_to_the_target
exit "$FAILED"
