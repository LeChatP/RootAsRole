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
TERMINAL_SCRIPT=/tmp/rar-e2e-terminal.sh
OUTER_TTY=/tmp/rar-e2e-outer-tty
# a command that the policy allows and that exec refuses: mode 0644
NOT_EXECUTABLE=/var/tmp/rar-e2e-not-executable
# a PAM module built for echo_on_question_is_answered, in the directory of pam_unix.so
ECHO_ON_MODULE=pam_rar_e2e_echo_on.so
# a PAM module built for pam_messages_stay_out_of_the_output
MESSAGE_MODULE=pam_rar_e2e_message.so
# the command that dosr names to read why it refused the policy (RAR_LOG_COMMAND)
LOG_COMMAND=(journalctl -t dosr -p info)
# where dosr keeps the cookies of the authentications (RAR_TIMEOUT_STORAGE)
TIMESTAMP_DIR=/var/run/rar/ts
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

# the version of the installed policy, without which chsr does not edit a file, and dosr does
# not read it
installed_version() {
    sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$ROOT_FILE" | head -n 1
}

setup() {
    id "$TEST_USER" >/dev/null 2>&1 || useradd -m "$TEST_USER"
    printf '#!/bin/sh\n' >"$NOT_EXECUTABLE"
    chmod 644 "$NOT_EXECUTABLE"
    printf '%s\n' "[Unit]" "Description=RootAsRole end-to-end test unit" \
        "[Service]" "ExecStart=/bin/sleep infinity" >"/etc/systemd/system/$UNIT.service"
    systemctl daemon-reload
    local version
    version=$(installed_version)
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
      { "name": "not-executable", "commands": ["$NOT_EXECUTABLE"] },
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
      },
      { "name": "sleep-root", "cred": { "setuid": "root" }, "commands": ["/usr/bin/sleep ^41$"] },
      { "name": "sleep-nobody", "cred": { "setuid": "nobody" }, "commands": ["/usr/bin/sleep ^41$"] },
      {
        "name": "once",
        "options": {
          "authentication": "perform",
          "password": { "tries": 1 },
          "timeout": { "type": "ppid", "duration": "00:01:00", "max_usage": 1 }
        },
        "commands": ["/usr/bin/id ^-un$"]
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
    rm -f "$TTY_SCRIPT" "$NOT_EXECUTABLE"
    find /lib /usr/lib -name "$ECHO_ON_MODULE" -path '*security*' -delete 2>/dev/null
    find /lib /usr/lib -name "$MESSAGE_MODULE" -path '*security*' -delete 2>/dev/null
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

# a policy file of the version $1, which lets the test user run id -u as root
planted_policy() {
    cat <<EOF
{
  "version": "$1",
  "options": { "authentication": "skip" },
  "roles": [{
    "name": "planted",
    "actors": [{ "user": "$TEST_USER" }],
    "tasks": [{ "name": "id", "cred": { "setuid": "root" }, "commands": ["/usr/bin/id ^-u$"] }]
  }]
}
EOF
}

# a policy file added without the immutable flag is refused, the same file with it is used; the
# user is told where to read why, but not after a plain denial
planted_policy_is_refused() {
    immutable_policy || return 77
    chattr -i "$POLICY_DIR"
    planted_policy "$(installed_version)" >"$PLANTED_POLICY"
    chmod 600 "$PLANTED_POLICY"
    chattr +i "$POLICY_DIR"
    local without_flag with_flag terminal denied
    without_flag=$(as_user dosr /usr/bin/id -u 2>/dev/null)
    terminal=$(as_user dosr /usr/bin/id -u 2>&1 >/dev/null)
    chattr +i "$PLANTED_POLICY"
    with_flag=$(as_user dosr /usr/bin/id -u 2>/dev/null)
    remove_policy "$PLANTED_POLICY"
    denied=$(as_user dosr /usr/bin/id -u 2>&1 >/dev/null)
    [ -z "$without_flag" ] && [ "$with_flag" = 0 ] &&
        grep -qF "${LOG_COMMAND[*]}" <<<"$terminal" &&
        grep -qF "Permission denied" <<<"$denied" && ! grep -qF 'journalctl' <<<"$denied"
}

# a policy file of a version that gives it another meaning is refused, the immutable flag
# included: 4.0.3, which chsr upgrade did not migrate, or none
old_policy_is_refused() {
    local version out since terminal logged=1 allowed=0
    for version in 4.0.3 ""; do
        write_policy "$PLANTED_POLICY" "$(planted_policy "$version" | sed '/"version": ""/d')"
        out=$(as_user dosr /usr/bin/id -u 2>/dev/null)
        [ -z "$out" ] || allowed=1
    done
    # the reason is in the log only: dosr shows nothing of the policy to the user who runs it,
    # only the command that shows the log, with which this user reads it
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    terminal=$(as_user dosr /usr/bin/id -u 2>&1 >/dev/null)
    for _ in 1 2 3 4 5; do
        if as_user "${LOG_COMMAND[@]}" --since "$since" -o cat |
            grep -qF "$PLANTED_POLICY: the policy has no version"; then
            logged=0
            break
        fi
        sleep 1
    done
    write_policy "$PLANTED_POLICY" "$(planted_policy "$(installed_version)")"
    out=$(as_user dosr /usr/bin/id -u 2>/dev/null)
    remove_policy "$PLANTED_POLICY"
    [ "$allowed" -eq 0 ] && [ "$out" = 0 ] && [ "$logged" -eq 0 ] &&
        ! grep -q "version" <<<"$terminal" &&
        grep -qF "dosr: see the reason with \`${LOG_COMMAND[*]}\`" <<<"$terminal"
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

# two commands of the same shell, the first one with the password, the second one with a wrong
# password: "first=0 second=0" when the cookie of the first one spares the password
two_authentications() {
    as_user sh -c "printf '%s\\n' '$TEST_PASSWORD' | dosr -S -r e2e -t password /usr/bin/true >/dev/null 2>&1
        echo first=\$?
        printf '%s\\n' wrong wrong wrong | dosr -S -r e2e -t password /usr/bin/true >/dev/null 2>&1
        echo second=\$?" | tr '\n' ' '
}

# the cookie of an authentication is written as root, in the directory of the build, the
# privileged path that the unit tests replace (cfg(test) in timeout.rs): it belongs to root,
# only root reads it, and it spares the password to the next command of the same shell
cookie_is_written_by_root() {
    local out cookie dir file
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd || return 1
    forget_authentications
    cookie="$TIMESTAMP_DIR/$(id -u "$TEST_USER")"
    [ ! -e "$cookie" ] || return 1
    out=$(two_authentications)
    dir=$(stat -c '%u:%g %a' "$TIMESTAMP_DIR")
    file=$(stat -c '%u:%g %a %h' "$cookie")
    forget_authentications
    [ "$out" = "first=0 second=0 " ] && [ "$dir" = "0:0 700" ] && [ "$file" = "0:0 600 1" ] || {
        echo "$out, directory $dir, cookie $file" >&2
        return 1
    }
}

# a cookie is used when it is checked, under the lock of the cookie file: of two runs at once (no
# terminal lock with -S), each checked the cookie before the other counted its use, and a cookie
# that serves once spared both
cookie_that_serves_once_spares_one_run() {
    local out
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd || return 1
    forget_authentications
    out=$(as_user sh -c "printf '%s\\n' '$TEST_PASSWORD' | dosr -S -r e2e -t once /usr/bin/id -un >/dev/null 2>&1
        echo first=\$?
        dosr -S -r e2e -t once /usr/bin/id -un </dev/null >/dev/null 2>&1 & a=\$!
        dosr -S -r e2e -t once /usr/bin/id -un </dev/null >/dev/null 2>&1 & b=\$!
        wait \$a; ra=\$?; wait \$b; rb=\$?
        echo spared=\$(( (ra == 0) + (rb == 0) ))" | tr '\n' ' ')
    forget_authentications
    [ "$out" = "first=0 spared=1 " ] || {
        echo "$out" >&2
        return 1
    }
}

# a cookie whose use cannot be written does not spare the password: the caller ignores SIGXFSZ and
# sets RLIMIT_FSIZE to 0, which dosr inherits, so that the write of the cookie fails (EFBIG); in
# the shell of the first run, not in a subshell: the cookie is for the parent process (bash forks
# for a subshell, dash does not for the last command)
unwritten_use_of_a_cookie_does_not_spare_the_password() {
    local out
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd || return 1
    forget_authentications
    out=$(as_user sh -c "printf '%s\\n' '$TEST_PASSWORD' | dosr -S -r e2e -t once /usr/bin/id -un >/dev/null 2>&1
        echo first=\$?
        trap '' XFSZ; ulimit -f 0; dosr -S -r e2e -t once /usr/bin/id -un </dev/null >/dev/null 2>&1
        echo second=\$?" | tr '\n' ' ')
    forget_authentications
    [ "$out" = "first=0 second=1 " ] || {
        echo "$out" >&2
        return 1
    }
}

# a directory of cookies that the user owns is not trusted: the user could plant a cookie in
# it; the password is asked again, and the cookie is not written there
cookie_directory_of_the_user_is_refused() {
    local out
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd || return 1
    forget_authentications
    chown "$TEST_USER" "$TIMESTAMP_DIR" || return 1
    out=$(two_authentications)
    chown root "$TIMESTAMP_DIR"
    forget_authentications
    [ "$out" = "first=0 second=1 " ] &&
        [ ! -e "$TIMESTAMP_DIR/$(id -u "$TEST_USER")" ] || {
        echo "$out" >&2
        return 1
    }
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

# a uid typed in chsr, for an actor or a setuid, is the uid for dosr: chsr wrote the actor as a
# string, which dosr took for the name of a user that nobody has, so the role was granted to
# nobody until another chsr command read the file and wrote it again as a number; the grant is
# the last command here
chsr_uids_are_uids_for_dosr() {
    local uid nobody result=1
    uid=$(id -u "$TEST_USER")
    nobody=$(id -u nobody)
    chsr file e2e.json r e2e-uid add || return 1
    if chsr file e2e.json r e2e-uid t uid add &&
        chsr file e2e.json r e2e-uid t uid cmd wl add '/usr/bin/id -u' &&
        chsr file e2e.json r e2e-uid t uid cred set --setuid "$nobody" &&
        chsr file e2e.json r e2e-uid grant -u "$uid" &&
        [ "$(as_user dosr -r e2e-uid -t uid /usr/bin/id -u 2>&1)" = "$nobody" ]; then
        result=0
    else
        grep -A12 '"e2e-uid"' "$E2E_POLICY" >&2
    fi
    chsr file e2e.json r e2e-uid del || return 1
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

# what the user reads with the command that dosr names: the lines of dosr, and dosr logs no debug
# line in release; pam_unix no longer logs that it cannot setuid(0), at any priority, since PAM
# checks the account with the effective uid of root
log_command_shows_the_lines_of_dosr() {
    local since view all
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    as_user dosr /usr/bin/date >/dev/null || return 1
    for _ in 1 2 3 4 5; do
        view=$(as_user "${LOG_COMMAND[@]}" --since "$since" -o cat)
        grep -q 'TASK=date ;.*COMMAND=/usr/bin/date' <<<"$view" && break
        sleep 1
    done
    all=$(journalctl -t dosr --since "$since" -o cat)
    grep -q 'TASK=date ;.*COMMAND=/usr/bin/date' <<<"$view" &&
        ! grep -q 'setuid failed' <<<"$all" && ! grep -q 'match_path' <<<"$all"
}

# dosr is not a login: its PAM service opens no logind session and writes no wtmp entry, like the
# one of sudo, whose modules fail for a caller that is not root (pam_systemd: Access denied,
# pam_wtmpdb: SQLITE_READONLY) and were shown by the command of the hint at each run (Debian)
pam_opens_no_login_session() {
    local since view
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    as_user dosr /usr/bin/date >/dev/null || return 1
    for _ in 1 2 3 4 5; do
        view=$(as_user "${LOG_COMMAND[@]}" --since "$since" -o cat)
        grep -q 'TASK=date ;.*COMMAND=/usr/bin/date' <<<"$view" && break
        sleep 1
    done
    grep -q 'TASK=date ;.*COMMAND=/usr/bin/date' <<<"$view" &&
        ! grep -qE 'pam_(systemd|wtmpdb|mkhomedir)\(dosr' <<<"$view" &&
        ! grep -qx '@include common-session' "$PAM_SERVICE"
}

# the failures of dosr are counted by pam_faillock, even for a user without a tally file yet:
# PAM checks the password with the effective uid of root, as under sudo; as the caller, it could
# not create /run/faillock/<user>, and its audit record was refused (Arch)
failures_are_counted_by_pam_faillock() {
    local since failures
    grep -qs pam_faillock /etc/pam.d/system-auth /etc/pam.d/common-auth || return 77
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd || return 1
    forget_authentications
    rm -f "/run/faillock/$TEST_USER"
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    printf '%s\n' wrong wrong wrong |
        as_user dosr -S -r e2e -t password /usr/bin/true >/dev/null 2>&1
    failures=$(faillock --user "$TEST_USER" | grep -c ' dosr ')
    forget_authentications
    [ "$failures" -eq 3 ] &&
        ! journalctl -t dosr --since "$since" -o cat | grep -q 'Error sending audit message'
}

# pam_rootok lets in a caller whose real uid is root: PAM runs with the effective uid of root
# only, so a service that starts with pam_rootok still asks the password of the caller
pam_rootok_does_not_let_the_caller_in() {
    cp -p "$PAM_SERVICE" "$PAM_SERVICE_BACKUP" || return 1
    sed -i '1a auth sufficient pam_rootok.so' "$PAM_SERVICE"
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd
    forget_authentications
    if printf '%s\n' wrong wrong wrong |
        as_user dosr -S -r e2e -t password /usr/bin/true >/dev/null 2>&1; then
        restore_pam_service
        forget_authentications
        return 1
    fi
    restore_pam_service
    forget_authentications
}

# a question that a PAM module shows in clear (PAM_PROMPT_ECHO_ON, as pam_duo asks its passcode)
# gets its answer: the answer held the NULs that follow it in the buffer, which PAM refuses, so
# the module got PAM_BUF_ERR and nobody could authenticate; the module built here asks "Code: "
# and accepts 1234
echo_on_question_is_answered() {
    local dir src out rc=0
    command -v gcc >/dev/null || return 77
    dir=$(dirname "$(find /lib /usr/lib -name pam_unix.so -path '*security*' 2>/dev/null | head -n 1)")
    [ -d "$dir" ] || return 77
    src=$(mktemp --suffix=.c)
    cat >"$src" <<'EOF'
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdlib.h>
#include <string.h>
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char *answer = NULL;
    int ok = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &answer, "Code: ") == PAM_SUCCESS &&
             answer && strcmp(answer, "1234") == 0;
    free(answer);
    return ok ? PAM_SUCCESS : PAM_AUTH_ERR;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
EOF
    gcc -shared -fPIC -o "$dir/$ECHO_ON_MODULE" "$src" -lpam || rc=1
    rm -f "$src"
    [ $rc = 0 ] || return 1
    cp -p "$PAM_SERVICE" "$PAM_SERVICE_BACKUP" || return 1
    sed -i "1a auth requisite $ECHO_ON_MODULE" "$PAM_SERVICE"
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd
    forget_authentications
    out=$(printf '1234\n%s\n' "$TEST_PASSWORD" | as_user dosr -S -r e2e -t password /usr/bin/true 2>&1) || rc=1
    restore_pam_service
    rm -f "${dir:?}/$ECHO_ON_MODULE"
    forget_authentications
    [ $rc = 0 ] || echo "dosr: $(head -c 300 <<<"$out")" >&2
    return $rc
}

# the messages of PAM modules (PAM_TEXT_INFO, PAM_ERROR_MSG) go to the user's terminal, like
# the prompts, or to stderr without one: on stdout, they went into the output of the command
# (dosr cmd >file); the module built here tells both from the account stack, which runs for a
# task that skips the authentication, without heeding PAM_SILENT, as some modules do
pam_messages_stay_out_of_the_output() {
    local dir src out err tty_out rc=0
    command -v gcc >/dev/null || return 77
    dir=$(dirname "$(find /lib /usr/lib -name pam_unix.so -path '*security*' 2>/dev/null | head -n 1)")
    [ -d "$dir" ] || return 77
    src=$(mktemp --suffix=.c)
    cat >"$src" <<'EOF'
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdlib.h>
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    pam_info(pamh, "rar-e2e information");
    pam_error(pamh, "rar-e2e warning");
    return PAM_SUCCESS;
}
EOF
    gcc -shared -fPIC -o "$dir/$MESSAGE_MODULE" "$src" -lpam || rc=1
    rm -f "$src"
    [ $rc = 0 ] || return 1
    cp -p "$PAM_SERVICE" "$PAM_SERVICE_BACKUP" || return 1
    sed -i "1a account optional $MESSAGE_MODULE" "$PAM_SERVICE"
    err=$(mktemp)
    out=$(as_user dosr -r e2e -t echo /usr/bin/echo hello 2>"$err")
    : >"$OUTER_TTY"
    chmod 666 "$OUTER_TTY"
    tty_out=$(no_input | as_user script -qec "dosr -r e2e -t echo /usr/bin/echo hello >$OUTER_TTY" /dev/null |
        tr -d '\r')
    restore_pam_service
    rm -f "${dir:?}/$MESSAGE_MODULE"
    [ "$out" = hello ] && grep -q 'rar-e2e information' "$err" && grep -q 'rar-e2e warning' "$err" &&
        [ "$(cat "$OUTER_TTY")" = hello ] && grep -q 'rar-e2e information' <<<"$tty_out" &&
        grep -q 'rar-e2e warning' <<<"$tty_out" || rc=1
    [ $rc = 0 ] || printf '%s\n' "stdout: $out" "stderr: $(cat "$err")" \
        "into a file, from a terminal: $(cat "$OUTER_TTY")" "terminal: $tty_out" >&2
    rm -f "$err" "$OUTER_TTY"
    return $rc
}

# the runs of dosr that stop between the password and the command: -i, a task whose
# capabilities are outside the bounding set, and a command that exec refuses
show_a_task() {
    as_user dosr -i -r e2e -t service /usr/bin/systemctl start "$UNIT"
}

refuse_a_task_outside_the_bounding_set() {
    capsh --drop=cap_net_raw --user="$TEST_USER" -- -c 'dosr -r e2e -t net-raw /usr/bin/true'
}

start_a_command_that_cannot_start() {
    as_user dosr -r e2e -t not-executable "$NOT_EXECUTABLE"
}

# the types of the audit records of dosr that the function $1 adds
audit_records_of() {
    local lines
    lines=$(wc -l </var/log/audit/audit.log)
    "$1" >/dev/null 2>&1
    sleep 1
    tail -n +"$((lines + 1))" /var/log/audit/audit.log | grep 'exe="/usr/bin/dosr"' |
        grep -o '^type=[A-Z_]*' | sort -u | tr '\n' ' '
}

give_the_password() {
    printf '%s\n' "$TEST_PASSWORD" | as_user dosr -S -r e2e -t password /usr/bin/true
}

# a password that is not UTF-8 (typed on a Latin-1 terminal, where é is the byte 0xe9) is given to
# PAM as typed: dosr took it as text and refused it, the right one included
password_that_is_not_utf8_is_accepted() {
    local rc=0
    printf '%s:p\351ss-rar-e2e\n' "$TEST_USER" | chpasswd || return 1
    forget_authentications
    printf 'p\351ss-rar-e2e\n' | as_user dosr -S -r e2e -t password /usr/bin/true >/dev/null 2>&1 || rc=1
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd
    forget_authentications
    return $rc
}

# the audit records of PAM name dosr, like those of sudo: libpam sends them with CAP_AUDIT_WRITE,
# which dosr only has in the effective set during the PAM calls (Arch, whose auditd is started
# for the check); a command that is started has the records of its session; -i and a refusal
# after the password have none, like sudo -l, and a command that cannot start has the end of its
# session too
audit_records_name_dosr() {
    local started='' records shown refused not_started
    command -v auditctl >/dev/null && systemctl cat auditd.service >/dev/null 2>&1 || return 77
    if ! systemctl is-active -q auditd; then
        systemctl start auditd || return 1
        started=1
        sleep 1
    fi
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd
    forget_authentications
    records=$(audit_records_of give_the_password)
    forget_authentications
    shown=$(audit_records_of show_a_task)
    refused=$(audit_records_of refuse_a_task_outside_the_bounding_set)
    not_started=$(audit_records_of start_a_command_that_cannot_start)
    if [ -n "$started" ]; then
        auditctl --signal stop >/dev/null
        auditctl -e 0 >/dev/null
    fi
    [ "$records" = "type=CRED_ACQ type=CRED_DISP type=USER_ACCT type=USER_AUTH type=USER_END type=USER_START " ] &&
        [ "$shown" = "type=USER_ACCT " ] && [ "$refused" = "type=USER_ACCT " ] &&
        [ "$not_started" = "type=CRED_ACQ type=CRED_DISP type=USER_ACCT type=USER_END type=USER_START " ] || {
        echo "audit records of dosr: $records; -i: $shown; refused: $refused; not started: $not_started" >&2
        return 1
    }
}

# pam_unix logs no session opened without its close: -i and a refusal after the password open
# none, a command that cannot start closes its own, like a command that runs
pam_session_only_for_a_command_that_is_started() {
    local since out sessions
    # --since takes whole seconds: the sessions of the check before, in the same second, would count
    sleep 1
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    show_a_task >/dev/null || return 1
    out=$(refuse_a_task_outside_the_bounding_set 2>&1) && return 1
    grep -q 'cannot obtain' <<<"$out" || return 1
    out=$(start_a_command_that_cannot_start 2>&1) && return 1
    grep -qF "$NOT_EXECUTABLE : " <<<"$out" || return 1
    as_user dosr -r e2e -t date /usr/bin/date >/dev/null || return 1
    for _ in 1 2 3 4 5; do
        sessions=$(journalctl --since "$since" -o cat |
            sed -n 's/^pam_unix(dosr:session): session \(opened\|closed\) .*/\1/p' | tr '\n' ' ')
        [ "$sessions" = "opened closed opened closed " ] && return 0
        sleep 1
    done
    echo "sessions of pam_unix: $sessions" >&2
    return 1
}

# a line of dosr longer than a datagram of /dev/log (212992 bytes) is cut into lines that fit,
# not lost: a refused attempt with long arguments is in the journal, and nothing but dosr
# records it (no task allows the command, no PAM)
long_refused_attempt_is_logged() {
    local pad marker since lines=0
    pad=$(head -c 120000 /dev/zero | tr '\0' a)
    marker="rar-e2e-refused-$RANDOM"
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    as_user dosr /usr/bin/rar-e2e-not-allowed "$marker" "$pad" "$pad" >/dev/null 2>&1 && return 1
    for _ in 1 2 3 4 5; do
        lines=$(journalctl -t dosr --since "$since" -o cat | grep -c 'aaaaaaaaaa')
        if [ "$lines" -ge 250 ] && journalctl -t dosr --since "$since" -o cat | grep -q "$marker"; then
            return 0
        fi
        sleep 1
    done
    echo "lines of the attempt in the journal: $lines" >&2
    return 1
}

# a command with 1 MB of arguments runs and is logged: RAR_COMMAND and SUDO_COMMAND hold the start
# of its command line, 4096 bytes at most (the whole command line in a variable made the execve
# fail beyond 128 KB, the longest string of an environment)
long_command_runs_and_is_logged() {
    local pad marker since out args=()
    pad=$(head -c 100000 /dev/zero | tr '\0' a)
    for _ in $(seq 10); do args+=("$pad"); done
    marker="rar-e2e-long-$RANDOM"
    since=$(date '+%Y-%m-%d %H:%M:%S')
    sleep 1
    # shellcheck disable=SC2016 # expanded by the shell of the command
    out=$(as_user dosr -r e2e -t shell /usr/bin/sh -c 'echo ran $# ${#RAR_COMMAND} ${#SUDO_COMMAND}' \
        "$marker" "${args[@]}" 2>&1)
    read -r _ count rar sudo <<<"$out"
    if [ "$count" != 10 ] || ! [ "$rar" -gt 0 ] 2>/dev/null || [ "$rar" -gt 4096 ] ||
        ! [ "$sudo" -gt 0 ] 2>/dev/null || [ "$sudo" -gt 4096 ]; then
        echo "dosr: $(head -c 200 <<<"$out")" >&2
        return 1
    fi
    for _ in 1 2 3 4 5; do
        journalctl -t dosr --since "$since" -o cat | grep -q "COMMAND=.*$marker" && return 0
        sleep 1
    done
    echo "the execution is not in the journal" >&2
    return 1
}

# after the PAM calls, the command starts with the identity that its task gives: a task without
# setuid nor capabilities gives the uids, the capabilities and the securebits of the caller
command_starts_with_the_identity_of_its_task() {
    local probe with without
    probe='grep -E "^(Uid|Gid|CapInh|CapPrm|CapEff|CapAmb):" /proc/self/status
python3 -c "import ctypes; print(\"Securebits:\", ctypes.CDLL(None).prctl(27, 0, 0, 0, 0))"'
    with=$(as_user dosr -r e2e -t shell /usr/bin/sh -c "$probe") || return 1
    without=$(as_user /usr/bin/sh -c "$probe") || return 1
    [ "$with" = "$without" ] || {
        printf 'with dosr:\n%s\nwithout:\n%s\n' "$with" "$without" >&2
        return 1
    }
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

# chsr editor with one editor of the build's list, under its sandbox (the two Landlock domains and
# seccomp): an edit reaches chsr, which finds that the copy no longer parses, and an unchanged copy
# is saved on a yes; skipped when the editor is not installed or not in the list of this build
chsr_editor_works_with() {
    local editor=/usr/bin/$1
    [ -x "$editor" ] || return 77
    RAR_EDITOR=$editor python3 - "$1" "$editor" <<'EOF'
import os, pty, select, signal, sys, time

name, editor = sys.argv[1], os.path.realpath(sys.argv[2])
# the keys that insert "x" before the first character, save and quit, then the ones that quit
# without a change; sent one chunk at a time
KEYS = {
    "vim": ([b"i", b"x", b"\x1b", b":wq\r"], [b":q\r"]),
    # ^O, Enter to keep the name, ^X
    "nano": ([b"x", b"\x0f", b"\r", b"\x18"], [b"\x18"]),
    # C-x C-s, C-x C-c
    "emacs": ([b"x", b"\x18\x13", b"\x18\x03"], [b"\x18\x03"]),
    # ^K x saves and exits
    "joe": ([b"x", b"\x0bx"], [b"\x0bx"]),
    # ^S, ^Q
    "micro": ([b"x", b"\x13", b"\x11"], [b"\x11"]),
}
edit, leave = KEYS[name]
settle = 4 if name == "emacs" else 1.5


def child_of(pid):
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/stat") as f:
                    if int(f.read().rsplit(")", 1)[1].split()[1]) == pid:
                        return int(entry)
            except (OSError, ValueError, IndexError):
                pass
    return None


def run(keys, marker, answer):
    """chsr editor in a pty: None when chsr runs another editor, else (marker seen, status, out)"""
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm"
        os.execvp("chsr", ["chsr", "editor"])
    out = bytearray()

    def drain(seconds):
        end = time.time() + seconds
        while time.time() < end:
            if select.select([fd], [], [], 0.2)[0]:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    return False
                if not data:
                    return False
                out.extend(data)
        return True

    def wait(seconds):
        end = time.time() + seconds
        while time.time() < end:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                return status
            time.sleep(0.2)
        return None

    child = exe = status = None
    try:
        # the editor is the child of chsr, once chsr has run it
        for _ in range(50):
            drain(0.2)
            child = child_of(pid)
            try:
                exe = os.readlink(f"/proc/{child}/exe") if child else None
            except OSError:
                exe = None
            if exe == editor:
                break
        if exe != editor:
            if exe and not exe.endswith("/chsr"):
                print(f"{name}: chsr runs {exe}, {editor} is not in its list", file=sys.stderr)
                return None
            return False, None, out
        drain(settle)
        for chunk in keys:
            os.write(fd, chunk)
            drain(0.6)
        end = time.time() + 20
        while marker not in out and time.time() < end and drain(0.3):
            pass
        seen = marker in out
        if seen:
            drain(0.5)
            os.write(fd, answer)
            drain(3)
            status = wait(10)
        return seen, status, out
    finally:
        # only what still runs: a pid that was reaped may be another process's by now
        if status is None:
            if child is not None and child_of(pid) == child:
                os.kill(child, signal.SIGKILL)
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(fd)


failed = False
for keys, marker, answer, what in (
    (edit, b"Your modifications are invalid", b"a\r", "an edit reaches chsr"),
    (leave, b"Resulting configuration", b"Y\r", "an unchanged copy is saved"),
):
    result = run(keys, marker, answer)
    if result is None:
        sys.exit(77)
    seen, status, out = result
    if not seen or (marker == b"Resulting configuration" and status != 0):
        tail = out[-600:].decode(errors="replace")
        print(f"{name}: not {what} (status {status}): {tail!r}", file=sys.stderr)
        failed = True
sys.exit(1 if failed else 0)
EOF
}

# the binary of the editor that chsr editor runs without RAR_EDITOR; the editor is killed, so chsr
# saves nothing
editor_that_chsr_runs() {
    env -u RAR_EDITOR python3 - <<'EOF'
import os, pty, select, signal, time

chsr = os.path.realpath("/usr/bin/chsr")
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.execvp("chsr", ["chsr", "editor"])


def drain(seconds):
    end = time.time() + seconds
    while time.time() < end:
        if select.select([fd], [], [], 0.2)[0]:
            try:
                if not os.read(fd, 65536):
                    return
            except OSError:
                return


def child_of(pid):
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/stat") as f:
                    if int(f.read().rsplit(")", 1)[1].split()[1]) == pid:
                        return int(entry)
            except (OSError, ValueError, IndexError):
                pass
    return None


exe = child = None
for _ in range(50):
    drain(0.2)
    child = child_of(pid)
    try:
        exe = os.readlink(f"/proc/{child}/exe") if child else None
    except OSError:
        exe = None
    if exe and exe != chsr:
        break
    exe = None
if exe:
    os.kill(child, signal.SIGKILL)
for _ in range(50):
    drain(0.2)
    if os.waitpid(pid, os.WNOHANG)[0]:
        break
else:
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
os.close(fd)
print(exe or "")
EOF
}

# without RAR_EDITOR, chsr editor runs the editor of the system, /usr/bin/editor, which root chooses
# with update-alternatives, when it is an editor of its list, by its path in the list (jpico is a
# link to joe); another one, like vim.tiny, is ignored for the first editor of the list
chsr_editor_follows_the_system_editor() {
    command -v update-alternatives >/dev/null && [ -L /usr/bin/editor ] || return 77
    local status value alternative expected got rc=0
    status=$(update-alternatives --query editor | sed -n 's/^Status: //p')
    value=$(update-alternatives --query editor | sed -n 's/^Value: //p')
    for alternative in /bin/nano /usr/bin/joe /usr/bin/jpico /usr/bin/vim.basic /usr/bin/micro \
        /usr/bin/emacs /usr/bin/vim.tiny; do
        update-alternatives --list editor | grep -qx "$alternative" || continue
        update-alternatives --set editor "$alternative" >/dev/null || {
            rc=1
            continue
        }
        case $alternative in
            */vim.tiny) expected=$(readlink -f /usr/bin/vim) ;;
            *) expected=$(readlink -f "$alternative") ;;
        esac
        got=$(editor_that_chsr_runs)
        [ "$got" = "$expected" ] || {
            echo "editor -> $alternative: chsr runs ${got:-nothing}, not $expected" >&2
            rc=1
        }
    done
    if [ "$status" = auto ]; then
        update-alternatives --auto editor >/dev/null
    else
        update-alternatives --set editor "$value" >/dev/null
    fi
    return "$rc"
}

# chsr removes its temporary folder, the editor's included: Landlock let it empty the folder but
# not remove it from /tmp, and every chsr command left one there
chsr_removes_its_temporary_folder() {
    local before after rc
    before=$(ls -d /run/chsr/* /tmp/chsr_* 2>/dev/null | sort)
    chsr list >/dev/null 2>&1 || return 1
    if [ -x /usr/bin/vim ]; then
        chsr_editor_works_with vim 2>/dev/null
        rc=$?
        [ "$rc" -eq 0 ] || return "$rc"
    fi
    after=$(ls -d /run/chsr/* /tmp/chsr_* 2>/dev/null | sort)
    [ "$before" = "$after" ] || {
        comm -13 <(echo "$before") <(echo "$after") >&2
        return 1
    }
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

# no input for script, which would copy into the terminal what is left on the input of the
# provisioner; an empty pipe, open longer than the command: at the end of its input, script
# writes a NUL in the terminal, which the terminal of the command echoes (^@)
no_input() {
    sleep 2
}

# the owner of the terminal of a task run as nobody through a terminal, and whether the command
# can reopen it by its name, as pinentry does through GPG_TTY
terminal_seen_by() {
    printf '%s\n' 't=$(tty)' 'stat -c %U "$t"' \
        'if { true <>"$t"; } 2>/dev/null; then echo reopened; else echo refused; fi' >"$TTY_SCRIPT"
    chmod 644 "$TTY_SCRIPT"
    no_input | as_user script -qec "dosr -r e2e -t $1 /usr/bin/sh $TTY_SCRIPT" /dev/null |
        tr -d '\r'
}

# the settings of a terminal that matter to a command: line editing, echo, signals, line ends
terminal_script() {
    printf '%s\n' \
        'flags() { stty -a "$@" | tr " " "\n" | grep -xE -- "-?(icanon|echo|isig|opost|onlcr|icrnl|ixon)" | tr "\n" " "; }' \
        'echo "terminal: $(flags </dev/tty)$(grep -E "^Sig(Blk|Ign):" /proc/self/status | tr -s "\t\n" "  ")"' \
        '[ ! -s /tmp/rar-e2e-outer-tty ] || echo "user: $(flags -F "$(cat /tmp/rar-e2e-outer-tty)")"' \
        >"$TERMINAL_SCRIPT"
    chmod 644 "$TERMINAL_SCRIPT"
}

# $1 run in a terminal, as the user; the terminal of the user is written in OUTER_TTY
in_a_terminal() {
    no_input | as_user script -qec "tty >$OUTER_TTY; $1" /dev/null | tr -d '\r'
}

# the command gets the settings of the user's terminal, which dosr copies before it makes its own
# terminal raw (it copied the raw settings: no echo, no line editing), and starts with the signals
# of the caller (sudo-rs ddc4030e): alone, with its input from a pipe, with its output into a pipe,
# and without a terminal
command_gets_the_terminal_and_the_signals_of_the_user() {
    local alone plain piped_in piped_out signals no_tty
    terminal_script
    : >"$OUTER_TTY"
    chmod 666 "$OUTER_TTY"
    alone=$(in_a_terminal "/usr/bin/sh $TERMINAL_SCRIPT" | grep '^terminal:')
    plain=$(in_a_terminal "dosr -r e2e -t shell /usr/bin/sh $TERMINAL_SCRIPT" | grep '^terminal:')
    piped_in=$(in_a_terminal "echo x | dosr -r e2e -t shell /usr/bin/sh $TERMINAL_SCRIPT" | grep '^terminal:')
    piped_out=$(in_a_terminal "dosr -r e2e -t shell /usr/bin/sh $TERMINAL_SCRIPT | cat" | grep '^terminal:')
    signals='grep -E "^Sig(Blk|Ign):" /proc/self/status | tr -s "\t\n" "  "'
    no_tty=$(as_user dosr -r e2e -t shell /usr/bin/sh -c "$signals" </dev/null)
    rm -f "$TERMINAL_SCRIPT" "$OUTER_TTY"
    [ -n "$alone" ] && grep -q ' icanon echo ' <<<"$alone" && [ "$plain" = "$alone" ] &&
        [ "$piped_in" = "$alone" ] && [ "$piped_out" = "$alone" ] &&
        [ "$no_tty" = "$(as_user /usr/bin/sh -c "$signals" </dev/null)" ] || {
        printf '%s\n' "alone: $alone" "dosr: $plain" "input from a pipe: $piped_in" \
            "output into a pipe: $piped_out" "without a terminal: $no_tty" >&2
        return 1
    }
}

# with its output into a pipe, dosr leaves the user's terminal as it is: another program of the
# pipeline uses it (a bug of sudo-rs, on the output flags)
terminal_of_a_pipeline_is_left_alone() {
    local alone piped_out
    terminal_script
    : >"$OUTER_TTY"
    chmod 666 "$OUTER_TTY"
    alone=$(in_a_terminal "/usr/bin/sh $TERMINAL_SCRIPT" | grep '^user:')
    piped_out=$(in_a_terminal "dosr -r e2e -t shell /usr/bin/sh $TERMINAL_SCRIPT | cat" | grep '^user:')
    rm -f "$TERMINAL_SCRIPT" "$OUTER_TTY"
    [ -n "$alone" ] && grep -q ' opost onlcr ' <<<"$alone" && [ "$piped_out" = "$alone" ] || {
        printf '%s\n' "alone: $alone" "output into a pipe: $piped_out" >&2
        return 1
    }
}

# with its output into a pipe, dosr reads nothing of the user's terminal: what the user types goes
# to the next program of the pipeline (a bug of sudo-rs: keystrokes lost in `sudo dmesg | less`)
keystrokes_go_to_the_end_of_the_pipeline() {
    local out
    out=$({
        sleep 1
        printf 'hello\n'
        sleep 3
    } | as_user script -qec "dosr -r e2e -t shell /usr/bin/sh -c 'sleep 2' | { read -r line </dev/tty; echo \"got=\$line\"; }" /dev/null | tr -d '\r')
    grep -qx 'got=hello' <<<"$out" || {
        echo "$out" >&2
        return 1
    }
}

# a python harness that runs $1 in a terminal, as the test user, types the keys of $2, and prints
# what the terminal got; shared by the checks of the terminal of a command run by dosr
in_a_python_terminal() {
    TEST_USER=$TEST_USER python3 - "$@" <<'EOF'
import os, pty, select, sys, time

argv, keys = sys.argv[1], sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp("runuser", ["runuser", "-u", os.environ["TEST_USER"], "--", "/bin/sh", "-c", argv])
out = b""


def read_until(needle, timeout):
    global out
    end = time.time() + timeout
    while needle not in out and time.time() < end:
        if select.select([fd], [], [], 0.1)[0]:
            try:
                data = os.read(fd, 4096)
            except OSError:
                return
            if not data:
                return
            out += data


read_until(b"READY", 10)
time.sleep(0.5)
# each key, or "wait:<text>" to wait for a text before the next key
for key in keys:
    if key.startswith("wait:"):
        read_until(key[5:].encode(), 8)
        time.sleep(0.3)
    else:
        os.write(fd, key.encode().decode("unicode_escape").encode("latin-1"))
        time.sleep(0.3)
read_until(b"\x00", 8)
os.waitpid(pid, 0)
# what the terminal got after READY, before the OSC 3008 sequence that systemd 258 writes at the
# end of a session
sys.stdout.buffer.write(out.split(b"READY", 1)[-1].split(b"\x1b]3008", 1)[0])
EOF
}

# a command that makes its terminal raw, as an editor does, gets the keys as they are typed: Enter
# as a carriage return (C-j and Enter differ in emacs or fzf), ^S and ^Q (save and quit in nano and
# micro), ^C, ^Z and ^\ (C-c starts the commands of emacs), which the user's terminal must not
# take for flow control or signals while dosr relays it, as sudo leaves it
raw_command_gets_the_keys_as_typed() {
    local got
    command -v python3 >/dev/null || return 77
    # timeout in the foreground: in its own process group, dd would be stopped by SIGTTIN
    got=$(in_a_python_terminal "dosr -r e2e -t shell /usr/bin/sh -c 'stty raw -echo; echo READY; \
timeout --foreground 5 dd bs=1 count=6 2>/dev/null | od -An -tx1; stty sane'" \
        '\r' '\x13' '\x11' '\x03' '\x1a' '\x1c' | tr -s ' \r\n' ' ')
    [ "$got" = " 0d 13 11 03 1a 1c " ] || {
        echo "the command got '$got' for Enter, ^S, ^Q, ^C, ^Z, ^\\" >&2
        return 1
    }
}

# what the command writes reaches the user's terminal as the pty of the command sets it: a newline
# becomes CR LF in cooked mode, once (not CR CR LF), and stays LF in raw mode, where a program
# that draws the screen moves the cursor down with it
command_output_reaches_the_terminal_as_written() {
    local got
    command -v python3 >/dev/null || return 77
    got=$(in_a_python_terminal "dosr -r e2e -t shell /usr/bin/sh -c 'echo READY; \
printf \"a\\nb\\n\"; stty raw; printf \"c\\nd\\n\"; stty sane'" | od -An -c | tr -s ' \n' ' ')
    [ "$got" = ' \r \n a \r \n b \r \n c \n d \n ' ] || {
        echo "the terminal got '$got'" >&2
        return 1
    }
}

# ^Z stops a command that dosr runs in a pty, with dosr, like a job of the shell, and fg resumes
# it, which reads what the user types next (RUN""NING: the echo of the typed line is not the
# output of the command)
suspended_command_resumes_with_fg() {
    local got
    command -v python3 >/dev/null || return 77
    got=$(in_a_python_terminal "PS1='READY\$ ' bash --norc --noprofile -i" \
        "dosr -r e2e -t shell /usr/bin/sh -c 'echo RUN\"\"NING; read line; echo GOT=\$line'\\r" \
        'wait:RUNNING' '\x1a' 'wait:Stopped' 'fg\r' 'hello\r' 'wait:GOT=' 'exit\r' | tr -d '\r')
    grep -q '^GOT=hello$' <<<"$got" || {
        echo "the terminal got: $got" >&2
        return 1
    }
}

# dosr dumps no core while it holds the policy and the PAM handle, whatever fs.suid_dumpable and
# kernel.core_pattern say: killed by SIGQUIT at its prompt (with the effective uid of root),
# it leaves no core, through a file (RLIMIT_CORE) or a pipe (not dumpable), even with
# fs.suid_dumpable = 1 and the core limit of the caller unlimited (raised by root first: the
# hard limit of root is 0 on the Arch box); SIGQUIT is given its default action, which a job in
# the background of a script ignores, and dosr must end by it
dosr_dumps_no_core() {
    local suid pattern core=/tmp/rar-e2e-core rc=0 job status
    suid=$(cat /proc/sys/fs/suid_dumpable)
    pattern=$(cat /proc/sys/kernel/core_pattern)
    echo 1 >/proc/sys/fs/suid_dumpable
    forget_authentications
    for to in "$core.%p" "|/usr/bin/dd of=$core.pipe.%p"; do
        rm -f "$core".*
        printf '%s' "$to" >/proc/sys/kernel/core_pattern
        (ulimit -c unlimited && sleep 4 | runuser -u "$TEST_USER" -- env --default-signal=QUIT \
            sh -c 'ulimit -c unlimited; exec dosr -S -r e2e -t password /usr/bin/true') >/dev/null 2>&1 &
        job=$!
        sleep 1.5
        pkill -QUIT -n -x dosr
        wait "$job"
        status=$?
        sleep 1
        if [ "$status" != 131 ]; then
            echo "dosr did not end by SIGQUIT through $to: $status" >&2
            rc=1
        fi
        if ls "$core".* >/dev/null 2>&1; then
            echo "a core of dosr through $to: $(ls "$core".*)" >&2
            rc=1
        fi
    done
    rm -f "$core".*
    printf '%s' "$pattern" >/proc/sys/kernel/core_pattern
    echo "$suid" >/proc/sys/fs/suid_dumpable
    return $rc
}

# the command gets the core limit of the caller, soft and hard, while dosr runs with 0 (the limit
# of the caller raised by root first, as above)
command_gets_the_core_limit_of_the_caller() {
    local with without dosr_limit
    without=$(ulimit -c unlimited && as_user sh -c 'ulimit -S -c 12345; sh -c "ulimit -S -c; ulimit -H -c"')
    with=$(ulimit -c unlimited && as_user sh -c 'ulimit -S -c 12345; dosr -r e2e -t shell /usr/bin/sh -c "ulimit -S -c; ulimit -H -c"')
    (ulimit -c unlimited && as_user dosr -r e2e -t shell /usr/bin/sh -c 'sleep 2') &
    sleep 1
    dosr_limit=$(grep 'Max core file size' "/proc/$(pgrep -n -x dosr)/limits" | awk '{print $5, $6}')
    wait
    if [ -z "$with" ] || [ "$with" != "$without" ] || [ "$dosr_limit" != "0 0" ]; then
        echo "with dosr: $with; without: $without; dosr: $dosr_limit" >&2
        return 1
    fi
}

# a signal sent to dosr reaches its command when it runs as root or as another user, with a
# terminal (the monitor forwards it) and without (dosr does), as under sudo: they have the uids of
# the caller and raise CAP_KILL for the kill of their child only; the kill failed with EPERM, and
# the command went on (timeout(1), kill $! in a script, a supervisor)
signal_reaches_a_command_of_another_user() {
    local mode task dosr target rc=0
    for mode in terminal none; do
        for task in sleep-root sleep-nobody; do
            if [ $mode = terminal ]; then
                as_user script -qec "dosr -r e2e -t $task /usr/bin/sleep 41" /dev/null \
                    </dev/null >/dev/null 2>&1 &
            else
                as_user setsid dosr -r e2e -t $task /usr/bin/sleep 41 </dev/null >/dev/null 2>&1 &
            fi
            sleep 1.5
            # the oldest dosr of the run: the one that the caller knows, not its monitor
            dosr=$(pgrep -o -f "^dosr -r e2e -t $task ")
            target=$(pgrep -f "^/usr/bin/sleep 41$")
            if [ -z "$dosr" ] || [ -z "$target" ]; then
                echo "$mode $task: the command did not start" >&2
                rc=1
            else
                as_user kill -TERM "$dosr"
                sleep 2
                if ps -p "$target" >/dev/null; then
                    echo "$mode $task: the command still runs after SIGTERM to dosr" >&2
                    rc=1
                fi
            fi
            pkill -f "^/usr/bin/sleep 41$"
            wait
        done
    done
    return $rc
}

# a signal that dosr gives the command, through a pty, reaches its process group, as under sudo:
# the processes of sh -c 'a | b' end with it; the monitor sent it to sh only, and the others
# stayed, holding the pty
signal_reaches_every_process_of_the_command() {
    local dosr left rc=0
    as_user script -qec "dosr -r e2e -t shell /usr/bin/sh -c 'sleep 42 | cat'" /dev/null \
        </dev/null >/dev/null 2>&1 &
    sleep 1.5
    dosr=$(pgrep -o -f "^dosr -r e2e -t shell /usr/bin/sh -c sleep 42")
    if [ -z "$dosr" ] || ! pgrep -f "^sleep 42$" >/dev/null; then
        echo "the command did not start" >&2
        rc=1
    else
        as_user kill -TERM "$dosr"
        sleep 2
        left=$(pgrep -a -f "^sleep 42$")
        [ -z "$left" ] || {
            echo "still running after SIGTERM to dosr: $left" >&2
            rc=1
        }
    fi
    pkill -f "^sleep 42$"
    wait
    return $rc
}

# a command that ignores SIGHUP (nohup, trap '' HUP) goes on when the user's terminal is gone, as
# under sudo: dosr stopped at the first error of the terminal, writing what the command printed
# after the hangup, and its monitor terminated the command; dosr is the controlling process of
# the terminal here (setpriv execs it), which gets the SIGHUP of the hangup
command_that_ignores_sighup_survives_the_terminal() {
    local out=/tmp/rar-e2e-hup
    command -v python3 >/dev/null && command -v setpriv >/dev/null || return 77
    rm -f "$out"
    TEST_USER=$TEST_USER OUT=$out python3 - <<'EOF'
import os, pty, pwd, select, time
user = pwd.getpwnam(os.environ["TEST_USER"])
pid, fd = pty.fork()
if pid == 0:
    os.execvp("setpriv", ["setpriv", f"--reuid={user.pw_uid}", f"--regid={user.pw_gid}",
                          "--init-groups", "dosr", "-r", "e2e", "-t", "shell", "/usr/bin/sh", "-c",
                          f"trap '' HUP; echo READY; sleep 2; echo more; sleep 1; "
                          f"echo alive > {os.environ['OUT']}"])
out, end = b"", time.time() + 10
while b"READY" not in out and time.time() < end:
    if select.select([fd], [], [], 0.1)[0]:
        try:
            out += os.read(fd, 4096)
        except OSError:
            break
# the terminal hangs up
os.close(fd)
time.sleep(6)
EOF
    [ "$(cat "$out" 2>/dev/null)" = alive ] || {
        echo "the command did not go on after the hangup" >&2
        rm -f "$out"
        return 1
    }
    rm -f "$out"
}

# the signals that the caller ignores stay ignored by the command, with a terminal and without:
# nohup (SIGHUP) and trap '' INT, as under sudo; dosr gave every signal its default action (the
# output into a file: nohup sends that of a command on a terminal to nohup.out)
command_keeps_the_signals_that_the_caller_ignores() {
    local out=/tmp/rar-e2e-sigign mode run line mask without rc=0
    for mode in terminal none; do
        without=''
        for run in "" "dosr -r e2e -t shell"; do
            rm -f "$out"
            line="trap '' INT; nohup $run /usr/bin/sh -c 'grep SigIgn /proc/self/status >$out' 2>/dev/null"
            if [ $mode = terminal ]; then
                as_user script -qec "sh -c \"$line\"" /dev/null </dev/null >/dev/null 2>&1
            else
                as_user setsid sh -c "$line" </dev/null >/dev/null 2>&1
            fi
            mask=$(sed -n 's/^SigIgn:[[:space:]]*//p' "$out" 2>/dev/null)
            if [ -z "$run" ]; then
                without=$mask
            elif [ -z "$mask" ] || [ "$mask" != "$without" ]; then
                echo "$mode: ignored by the command $mask, without dosr $without" >&2
                rc=1
            fi
        done
    done
    rm -f "$out"
    return $rc
}

# the password prompt under ^Z and fg, and under ^C, in an interactive shell of the test user on a
# pseudo-terminal: after fg the prompt shows again and the password is not echoed (bash gives the
# terminal its echo back while dosr is stopped); ^C ends dosr by SIGINT, so that the shell drops
# the rest of the line, with the echo of the terminal back (dash leaves the terminal as dosr left
# it; sh is bash on Arch)
prompt_gives_the_echo_back_on_signals() {
    local rc
    command -v python3 >/dev/null || return 77
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd
    forget_authentications
    TEST_USER=$TEST_USER TEST_PASSWORD=$TEST_PASSWORD python3 - <<'EOF'
import os, pty, select, sys, time
user, password = os.environ["TEST_USER"], os.environ["TEST_PASSWORD"].encode()

def read_until(fd, needle, timeout=8):
    buf, end = b"", time.time() + timeout
    while time.time() < end:
        if select.select([fd], [], [], 0.1)[0]:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            buf += data
            if needle in buf:
                break
    return buf

def shell(argv):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("runuser", ["runuser", "-u", user, "--"] + argv)
    os.write(fd, b"PS1='READY> '\n")
    read_until(fd, b"READY> ")
    read_until(fd, b"READY> ", 1)
    return fd

failed = False
for name, argv in (("bash", ["bash", "--norc", "--noprofile", "-i"]), ("sh", ["sh", "-i"])):
    fd = shell(argv)
    os.write(fd, b"dosr -K; dosr -r e2e -t password /usr/bin/true\n")
    read_until(fd, b"Password:")
    time.sleep(0.3)
    os.write(fd, b"\x1a")
    read_until(fd, b"READY> ")
    os.write(fd, b"fg; echo FG=$?\n")
    prompt = read_until(fd, b"Password:")
    time.sleep(0.3)
    os.write(fd, password + b"\n")
    out = read_until(fd, b"READY> ")
    if b"Password:" not in prompt or password in prompt + out or b"FG=0" not in out:
        print(f"{name}, ^Z and fg: {prompt + out!r}", file=sys.stderr)
        failed = True
    os.write(fd, b"exit\n")

    fd = shell(argv)
    os.write(fd, b"dosr -K; dosr -r e2e -t password /usr/bin/true; echo RC=$?\n")
    read_until(fd, b"Password:")
    time.sleep(0.3)
    os.write(fd, b"\x03")
    out = read_until(fd, b"READY> ")
    os.write(fd, b"stty -a | grep -o -- ' -\\?echo ' | head -1\n")
    out += read_until(fd, b"READY> ")
    if b"RC=" in out or b" -echo " in out or b" echo " not in out:
        print(f"{name}, ^C: {out!r}", file=sys.stderr)
        failed = True
    os.write(fd, b"exit\n")
sys.exit(1 if failed else 0)
EOF
    rc=$?
    forget_authentications
    return $rc
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
check "a policy file without the immutable flag is refused, the user told where the reason is" planted_policy_is_refused
check "a policy file of an older version, or without one, is refused, the user told where the reason is" old_policy_is_refused
check "dosr ends like a command killed by a signal" signal_is_forwarded
check "a regular expression without quotes" unquoted_regex
check "a command written without arguments allows none" command_without_arguments_allows_none
check "uid 0 without capabilities manages a unit" root_without_capabilities_manages_a_unit
check "CAP_NET_BIND_SERVICE is granted" capability_is_granted
check "the bounding set is checked before running the command" bounding_set_is_checked_first
check "the variables of pam_env go through the env filter of the task" pam_env_is_filtered
check "a wrong password is asked again, up to the tries of the policy" password_is_asked_again
check "a task that skips the authentication gives no cookie" skipped_authentication_gives_no_cookie
check "the cookie of an authentication is written by root and spares the next password" cookie_is_written_by_root
check "a directory of cookies that the user owns is not trusted" cookie_directory_of_the_user_is_refused
check "a cookie that serves once spares one of two runs at once" cookie_that_serves_once_spares_one_run
check "a cookie whose use cannot be written does not spare the password" unwritten_use_of_a_cookie_does_not_spare_the_password
check "a failed lookup of an actor disables the roles with ssd" ssd_role_disabled_by_a_failed_lookup
check "chsr edits default.json of the policy directory" chsr_edits_the_default_file
check "a regular expression written with chsr is matched by dosr" chsr_regex_is_matched_by_dosr
check "a uid typed in chsr, for an actor or a setuid, is the uid for dosr" chsr_uids_are_uids_for_dosr
check "the executions are logged under the name dosr" dosr_logs_under_its_name
check "the command that dosr names shows its lines, without the debug lines of PAM" log_command_shows_the_lines_of_dosr
check "the PAM service of dosr opens no login session" pam_opens_no_login_session
check "pam_faillock counts the failures of dosr" failures_are_counted_by_pam_faillock
check "pam_rootok does not let the caller in" pam_rootok_does_not_let_the_caller_in
check "a question that PAM shows in clear gets its answer" echo_on_question_is_answered
check "the messages of PAM go to the terminal or stderr, not into the output of the command" pam_messages_stay_out_of_the_output
check "a password that is not UTF-8 is given to PAM as typed" password_that_is_not_utf8_is_accepted
check "the audit records of PAM name dosr, with a session only for a command that is started" audit_records_name_dosr
check "pam_unix logs a session only for a command that is started, and its close" pam_session_only_for_a_command_that_is_started
check "a refused attempt with long arguments is logged, cut into lines" long_refused_attempt_is_logged
check "a command with 1 MB of arguments runs and is logged" long_command_runs_and_is_logged
check "the command starts with the identity that its task gives" command_starts_with_the_identity_of_its_task
check "chsr is confined by Landlock" chsr_is_confined_by_landlock
check "chsr editor works with vim, under its sandbox" chsr_editor_works_with vim
check "chsr editor works with nano, under its sandbox" chsr_editor_works_with nano
check "chsr editor works with emacs, under its sandbox" chsr_editor_works_with emacs
check "chsr editor works with joe, under its sandbox" chsr_editor_works_with joe
check "chsr editor works with micro, under its sandbox" chsr_editor_works_with micro
check "chsr editor runs the editor of the system when it is one of its list" chsr_editor_follows_the_system_editor
check "chsr removes its temporary folder, the one of the editor included" chsr_removes_its_temporary_folder
check "-- ends the options of dosr" double_dash_ends_the_options
check "dosr -i shows None for a task without capabilities" info_shows_no_capabilities_as_none
check "a task that changes the user gives the groups of the target user" groups_of_the_target_user
check "from: caller keeps the groups of the caller" groups_of_the_caller_with_from
check "a task whose group does not exist is left out" missing_group_leaves_the_task_out
check "a top-level alternation is anchored on both sides" alternation_is_anchored
check "the terminal of a command run as another user stays with the caller" terminal_stays_with_the_caller
check "tty owner target gives the terminal to the user of the command" terminal_given_to_the_target
check "the command gets the terminal settings and the signals of the user" command_gets_the_terminal_and_the_signals_of_the_user
check "with its output into a pipe, dosr leaves the user's terminal as it is" terminal_of_a_pipeline_is_left_alone
check "with its output into a pipe, the keystrokes go to the next program" keystrokes_go_to_the_end_of_the_pipeline
check "a command in raw mode gets Enter, ^S, ^Q, ^C, ^Z and ^\\ as they are typed" raw_command_gets_the_keys_as_typed
check "the output of a command reaches the terminal as its pty sets it, raw or not" command_output_reaches_the_terminal_as_written
check "^Z stops a command run in a pty with dosr, and fg resumes it" suspended_command_resumes_with_fg
check "the password prompt gives the echo back on ^Z and ^C, and shows again after fg" prompt_gives_the_echo_back_on_signals
check "dosr dumps no core, through a file or a pipe, even with fs.suid_dumpable = 1" dosr_dumps_no_core
check "a signal sent to dosr reaches a command that runs as root or as another user" signal_reaches_a_command_of_another_user
check "the signals that the caller ignores stay ignored by the command" command_keeps_the_signals_that_the_caller_ignores
check "a signal given to the command through a pty reaches its process group" signal_reaches_every_process_of_the_command
check "a command that ignores SIGHUP goes on when the terminal is gone" command_that_ignores_sighup_survives_the_terminal
check "the command gets the core limit of the caller" command_gets_the_core_limit_of_the_caller
exit "$FAILED"
