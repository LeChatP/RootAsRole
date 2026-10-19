# Configuration

<blockquote class="caroot-stare">
This section is written by human and AI-enhanced for covering edges and simplifying the content.
</blockquote>

This chapter explains how to configure RootAsRole (RaR) efficiently and safely. It covers the structure of the policy, every field in it, and the reasons behind each of them. The policy format is the result of a long engineering effort grounded in research and security rationale, so most fields exist to answer a concrete risk.

To make these risks tangible, the whole chapter follows a single example: a small administration team, the **WebOps** team, migrating from `sudo` to RaR. Each section introduces a concept, then applies it to the WebOps team. At the end of the chapter, you will have built their complete policy step by step.

Keep one idea in mind along the way: dangerous permissions are sometimes necessary, and they are rarely obvious. The goal is not to remove every risk, but to identify each risk and make a deliberate decision about it.

## Introduction with the WebOps scenario

### The team and the system

The WebOps team is made of 3 administrators who manage a web infrastructure: servers, applications and related services. Their daily tasks include restarting services, checking logs and applying updates.

The machine runs a Linux distribution with systemd as init system, and Caddy as webserver:

- websites are served from `/srv/www/`;
- Caddy runs as `www-data`, and its configuration lives in `/etc/caddy/`;
- Caddy logs are written to `/var/log/caddy/`, readable by the `adm` group.

The system has the following users: `alice`, `bob`, `charly`, `sshd`, `www-data` and of course `root`. The administrators have distinct responsibilities: Alice manages website content, Bob operates the webserver and its configuration and logs, and Charly handles system and webserver updates.

### The starting point: sudo

Initially, the team used `sudo` with the following sudoers configuration:

```
Cmnd_Alias WEB_CONTENT = /usr/bin/install -d -m * -o * -g * /srv/www/*

Cmnd_Alias CADDY_MGMT  = /bin/systemctl restart caddy, \
                         /bin/systemctl reload caddy, \
                         /bin/systemctl start caddy, \
                         /bin/systemctl stop caddy, \
                         /bin/systemctl status caddy, \
                         /usr/bin/journalctl -u caddy*, \
                         /bin/journalctl -u caddy*, \
                         /usr/local/bin/caddy-probe

Cmnd_Alias CADDY_LOGS  = /usr/bin/tail -n * /var/log/caddy/*, \
                         /usr/bin/tail -f /var/log/caddy/*, \
                         /usr/bin/less /var/log/caddy/*

Cmnd_Alias SYS_UPDATES = /usr/bin/apt update, \
                         /usr/bin/apt upgrade, \
                         /usr/bin/apt --only-upgrade install caddy, \
                         /usr/bin/apt dist-upgrade, \
                         /usr/bin/reboot


alice   ALL = (ALL) WEB_CONTENT

bob     ALL = (ALL) CADDY_MGMT, CADDY_LOGS

charly  ALL = (ALL) SYS_UPDATES
```

`caddy-probe` is a custom tool used by bob to diagnose the Caddy configuration and to capture network traffic. This configuration looks restrictive, but it is not. Let's review it.

**Alice.** In sudoers, `*` also matches spaces, so it can swallow additional arguments. Alice can run `install -d -m 777 -o alice -g alice /srv/www/x /etc`: since `install -d` changes the owner and mode of directories that already exist, she now owns `/etc`. On top of that, `(ALL)` allows her to run the command as any user she wants.

**Bob.** `less` lets the user open other files (`:e /etc/shadow`) and spawn a shell (`!sh`). The same applies to `systemctl status` and `journalctl`, which open a pager by default. The wildcard is also exposed to path traversal: `/var/log/caddy/../../../etc/shadow` matches `/var/log/caddy/*`. Every one of these escapes runs as root.

**Charly.** `apt` is root-equivalent by nature: package maintainer scripts run arbitrary code as root. Restricting the arguments does not change that. Moreover, `apt` reads the `APT_CONFIG` environment variable: if it reaches the command, an `APT::Update::Pre-Invoke` hook spawns a root shell. Finally, charly can reboot the system at any time. This is not a privilege escalation, but it is an availability risk, and it is a different kind of action than updating packages.

**caddy-probe.** The tool only needs to read the Caddy configuration and to capture packets, but sudo runs it with full root privileges.

### The incident

One day, the team got attacked: the attacker stole bob's credentials. Then, they found a vulnerability in `caddy-probe` that allowed them to execute arbitrary commands. Since the tool ran as root with all privileges, the attacker immediately became root.

The vulnerability itself was not avoidable by configuration. However, its impact was. If the principle of least privilege had been applied, the tool would have had only the privileges required to listen to the network and to read a few files, and the attacker would have gained almost nothing.

### What the team needs

After this incident, the team decided to replace sudo with RootAsRole. The rest of this chapter follows them as they build their policy, one need at a time.
 
We first see [where the policy lives](#where-the-policy-lives) on the system and how it is protected. Then, since sudo tied every permission to an individual, the team turns its responsibilities into [roles](#roles-and-actors) and assigns them to groups instead of users. Each role is made of [tasks](#tasks), and each task answers two questions. The first one is *what* can be run: the [commands](#commands) section shows how to allow exactly the intended commands and arguments, without the loopholes of sudoers wildcards. The second one is *with which privileges*: the [credentials](#credentials-cred) section gives each command the minimal user, groups and capabilities it needs, so that an escape or a vulnerability like the one in `caddy-probe` yields almost nothing.
 
A command also runs in a context. The [options](#options-and-inheritance) section explains how to stop the caller's environment from crossing the privilege boundary, as `APT_CONFIG` did, and how to set safe defaults once for the whole policy. Then, [hierarchy and separation of duty](#hierarchy-and-separation-of-duty) organise the roles together, and keep the most exposed account away from the most critical role. After a tour of the [other plugins](#other-plugins-and-extensions), we assemble [the complete WebOps policy](#the-complete-webops-policy) and check it against every issue listed above. Finally, we look at what remains open, root-equivalent tasks, and how [Zero Trust](#going-further-towards-zero-trust) addresses it.

## Where the policy lives

The data is split into two parts: the **root file**, which tells RaR where the policy is stored, and the **policy** itself. The root file is `/etc/security/rootasrole.json`:

```json
{
  "version": "4.1.0",
  "storage": {
    "method": "json",
    "settings": {
      "path": "/etc/security/rootasrole.d",
      "immutable": true
    }
  }
}
```

- `version`: policy schema version written by tooling. It is mainly used to facilitate migrations during upgrades.
- `storage`: describes where the policy data is stored.
- `method`: can be `json` or `cbor`. To migrate from one format to another, use the `chsr convert` command. See [File Format Conversion](cli/chsr.md#file-format-conversion) for more details.
- `settings`: parameters of the storage method. JSON and CBOR are both file-based, so they have a `path` parameter. If `path` points to the root file itself, the roles declared directly in the root file are used. Otherwise, the policy files found at `path` are loaded.
- `immutable`: enforces the IMMUTABLE flag on the policy directory and files, to prevent accidental overwriting. Only privileged users with `CAP_LINUX_IMMUTABLE` can modify the policy. Therefore, **this capability becomes a highly sensitive one**: we will make sure no WebOps task grants it.

For the WebOps team, the policy will be stored in `/etc/security/rootasrole.d/default.json`. A policy file has the following skeleton:

```json
{
  "version": "4.1.0",
  "options": { },
  "roles": [ ]
}
```

When your policy is ready, you can convert it to CBOR, which is much faster to load.

## Roles and actors

The policy is based on Role-Based Access Control (RBAC). Permissions are not given to users or groups, but to roles. Users and groups are then assigned to roles as **actors**. This subtle change gives better control over permissions and a better separation of duties.

A role is composed of actors and tasks. Each task defines which commands can be run, and with which credentials.

### Role engineering for WebOps

The first step is a role-engineering process: listing responsibilities. From the scenario, the WebOps team needs four roles:

| Role          | Purpose                                     | Initially assigned to |
|---------------|---------------------------------------------|-----------------------|
| `webadmin`    | Publish website content                     | alice                 |
| `caddy-audit` | Read Caddy logs                             | bob                   |
| `caddy-admin` | Operate and diagnose the webserver          | bob                   |
| `sys-admin`   | Apply system updates and reboot the machine | charly                |

Splitting `caddy-audit` from `caddy-admin` may look excessive for now. It will pay off when we introduce role hierarchy.

We can draft the `webadmin` role as follows:

```json
{
  "name": "webadmin",
  "actors": [
    { "user": "alice" }
  ],
  "tasks": []
}
```

But alice may leave her job, and someone else will take over her responsibilities. Instead of editing the policy every time the team changes, we assign a group to the role, and add alice to that group:

```json
{
  "name": "webadmin",
  "actors": [
    { "group": ["webadmin"] }
  ],
  "tasks": []
}
```

Note that `group` accepts a list: when several groups are listed, the user must belong to **all** of them to be an actor of the role.

One question arises then: "Why use roles if there is a group with the same name?". The answer is organisational. Roles define *what* can be done, groups gather *who* can do it. A role can apply to several groups, and rather than creating a new group that unites the members of several groups, it is better to have a role that focuses on the contextualisation of tasks.

## Tasks

A task is a set of commands that can be run with specific credentials. Let's define the `web-push` task of the `webadmin` role, which allows alice to publish website content:

```json
{
  "name": "web-push",
  "purpose": "Publish website content from the staging area",
  "commands": [
    "/usr/bin/install ^-d -m 0?[0-7]{3} /srv/www/[^ ]+$",
    "/usr/bin/rsync ^-rlt --delete /srv/staging/[^ ]+/ /srv/www/[^ ]+/$"
  ],
  "cred": {
    "setuid": "www-data",
    "setgid": "www-data",
    "capabilities": []
  }
}
```

- `name` identifies the task. When a user has several tasks matching the same command, the name is the only element that allows selecting one explicitly. If omitted, the task is identified by its index in the role.
- `purpose` is a human-readable description. It is not used by the engine, but it documents *why* the permission exists.
- `commands` and `cred` are detailed in the next two sections.

## Commands

`commands` supports 3 forms:

1. String policy:

    ```json
    "commands": "all"
    ```

2. Explicit allow-list:

    ```json
    "commands": ["/usr/bin/systemctl restart caddy"]
    ```

3. Full object (selector):

    ```json
    "commands": {
      "default": "none",
      "add": ["/usr/bin/systemctl restart caddy"]
    }
    ```

Supported `default` values are `all` and `none`. `sub` (alias `del`) removes commands from the set.

### Command matching

Commands in the policy must be absolute paths. However, you can use globs to match multiple binary paths. [See globset syntax for details](https://docs.rs/globset/latest/globset/#syntax).

To match a command typed without its path (like `ls`), the `path` option must include the directory containing the command (see [The `path` option](#the-path-option)). Otherwise, the user can still run the command, but only by writing its absolute path, for example `/usr/bin/ls` instead of `ls`.

Arguments can be matched in two ways:

- **exact match**: the arguments are written as a plain string, and must be typed exactly as written, for example `/usr/bin/systemctl status --no-pager caddy`;
- **regular expression**: the arguments are written in the `^...$` format, for example:

    ```
    /usr/bin/install ^-d -m 0?[0-7]{3} /srv/www/[^ ]+$
    ```

Regular expressions follow the syntax of the Rust [`regex`](https://docs.rs/regex/latest/regex/#syntax) crate. Note that this syntax does not support look-around nor backreferences.

<blockquote class="caroot">
We are still working on the way to express a regular expression safely on the arguments.
</blockquote>

### Applying it to WebOps

Remember alice's sudoers rule: the wildcard swallowed extra arguments. A naive regex translation, `^-d -m .+ -o .+ -g .+ /srv/www/.+$`, has the exact same flaw, because `.+` also matches spaces. This is why the `web-push` task uses:

- `0?[0-7]{3}` for the mode, which only accepts an octal mode;
- `[^ ]+` for paths, which cannot contain a space and thus cannot introduce another argument;
- no `-o` and `-g` options at all: as we'll see in the next section, the command already runs as `www-data`.

The same reasoning applies to bob's commands. We force `--no-pager` to remove the pager shell escape, and we forbid `/` in log file names to prevent path traversal:

```json
"commands": [
  "/usr/bin/systemctl ^(start|stop|restart|reload) caddy$",
  "/usr/bin/systemctl status --no-pager caddy"
]
```

```json
"commands": [
  "/usr/bin/tail ^(-n [0-9]+|-f) /var/log/caddy/[^/ ]+$",
  "/usr/bin/less ^/var/log/caddy/[^/ ]+$",
  "/usr/bin/journalctl --no-pager -u caddy"
]
```

Whenever the arguments are fixed, prefer an exact match: it leaves no room for interpretation.

`less` is still allowed and still has a shell escape. Command matching alone cannot fix that: the next section will make this escape worthless, and the [environment section](#environment-variables-env) will disable it.

## Credentials (`cred`)

One big strength of RaR is its ability to enforce fine-grained execution credentials. The `cred` section of a task defines the user, groups and capabilities the command runs with. This completely shifts away from the "all-or-nothing" model of `sudo`: users can now run commands with a subset of privileges, while keeping their identity. Even the root user can run commands with no privileges at all (see the [`root` option](#other-options)).

The `cred` section is optional. If omitted, the command runs with the credentials of the user invoking it. This can be useful to require authentication for a command without granting any additional privilege.

### `setuid`

The `setuid` field sets the user the command runs as. In security terms, this is **impersonation**. Impersonation is a powerful tool for administrators, but also for attackers. The general advice is to avoid it, and when it is needed, to impersonate a user who owns exactly the resources required by the task.

Most administrators want to be a single user: root, because the system's discretionary access control (DAC) is built around it. RaR suggests another approach: when impersonating root is needed, grant it **without capabilities**. Root then only has the rights given by file permissions, like a regular user. Going further, system configuration that administrators need should have a segregated DAC, owned by a dedicated user, so that bypassing it requires an explicit Linux capability.

### `setgid`

The `setgid` field makes DAC configuration easier. You can define a single group, or a list of groups. If a list is defined, the first group is the primary group, and the others are supplementary groups.

### `capabilities`

Linux divides the privileges of the superuser into distinct units called capabilities. Unlike DAC permissions tied to files, capabilities are assigned to processes. They allow granting a specific privilege to a task without running it as root.

Some capabilities are very powerful and can be used to gain more privileges than intended. For example, `CAP_SYS_ADMIN` gathers privileged features that were not worth a dedicated capability; combining all of them is close to a second definition of root. Many other capabilities can be abused to exploit the system. You can read more on the [HackTricks](https://hacktricks.wiki/en/linux-hardening/interesting-files-permissions/linux-capabilities.html) reference.

### Applying it to WebOps

Let's give each task the minimal credentials it needs:

| Task (role)                   | `setuid`   | `setgid`                 | `capabilities` | Why                                                                               |
|-------------------------------|------------|--------------------------|----------------|-----------------------------------------------------------------------------------|
| `web-push` (webadmin)         | `www-data` | `www-data`               | none           | `/srv/www` is owned by `www-data`: no privilege is needed, only the right owner.  |
| `read-logs` (caddy-audit)     | —          | `adm`, `systemd-journal` | none           | Bob stays bob; the groups are enough to read the logs.                            |
| `caddy-service` (caddy-admin) | `root`     | —                        | none           | systemd authorizes service management for uid 0. No capability is required.      |
| `caddy-probe` (caddy-admin)   | —          | `www-data`               | `CAP_NET_RAW`  | Reading `/etc/caddy` needs the group; capturing packets needs `CAP_NET_RAW` only. |
| `apt` (sys-admin)             | `root`     | `root`                   | all            | Package installation is root-equivalent. We accept it, and constrain it elsewhere.|
| `reboot` (sys-admin)          | `root`     | —                        | none           | `systemctl reboot` is authorized for uid 0, without capabilities.                 |

Now let's replay the issues found earlier:

- If alice abuses `install` or `rsync` (for example with `--rsh`), she only obtains a shell as `www-data`: the rights the task already grants her.
- If bob escapes from `less`, he obtains a shell as bob with the `adm` and `systemd-journal` groups. `/etc/shadow` stays unreadable.
- If the attacker exploits `caddy-probe` again, they get bob's identity, the `www-data` group and `CAP_NET_RAW`. They can sniff traffic, but they are not root anymore. If the tool needs promiscuous mode, add `CAP_NET_ADMIN`, knowing it also allows changing firewall and routing rules.
- `apt` remains root-equivalent. This is an honest limit: some tasks cannot be made safe by configuration. What we can do is identify them, isolate them in their own role, and protect the role (environment, authentication, separation of duties).

This is the main lesson of this section: **when you cannot prevent an escape, make it worthless.**

### Selector forms

So far, credentials were forced: the user has no choice. RaR also allows users to choose a user or a group among a set allowed by the policy, with the `-u` and `-g` options of `dosr`. The following forms describe these sets.

#### `capabilities`

```json
"capabilities": "all"
```

Gives all Linux capabilities to the command. One subtlety: `all` is limited to the capabilities available to the invoking process. Once a capability is dropped from the bounding set, it cannot be regained, so `all` will not give it back.

```json
"capabilities": ["CAP_NET_BIND_SERVICE", "CAP_SYS_BOOT"]
```

Gives a list of capabilities. Again, they must be available to the invoking process, otherwise the command results in a permission denied.

```json
"capabilities": {
  "default": "all",
  "del": ["CAP_SYS_ADMIN", "CAP_LINUX_IMMUTABLE"]
}
```

Gives every capability, except `CAP_SYS_ADMIN` and `CAP_LINUX_IMMUTABLE`. Remember that denylists are fragile: many other capabilities lead to root.

```json
"capabilities": {
  "default": "none",
  "add": ["CAP_NET_BIND_SERVICE"]
}
```

Gives no capability, except `CAP_NET_BIND_SERVICE`. This is a common use case for network services, because `CAP_NET_BIND_SERVICE` allows binding to ports below 1024.

#### `setuid`

```json
"setuid": {
  "default": "none",
  "fallback": "root",
  "add": ["alice"]
}
```

```json
"setuid": {
  "default": "all",
  "fallback": "root",
  "del": ["bob"]
}
```

`fallback` is the user used when the caller does not specify `-u`. The first example is the good practice, because it respects the fail-safe default principle. The second one has to exist for very specific use cases. Use it with care.

#### `setgid`

`setgid` follows the same philosophy. Each entry is a group set, the first group of a set being the primary group:

```json
"setgid": {
  "default": "none",
  "fallback": ["root"],
  "add": [["wheel"]]
}
```

`setuid` and `setgid` can also be written in their compact mandatory form (a single user, or a group/group list), as in the WebOps tasks.

## Options and inheritance

Commands and credentials define *what* runs. **Options** define *in which context* it runs: environment variables, `PATH`, authentication, working directory, etc.

Options can be set at three levels: the policy file (global), a role, or a task. The most specific level wins: **Task → Role → Policy file → Built-in defaults**. This lets the WebOps team set safe defaults once, globally, and only harden the tasks that need it.

### Environment variables (`env`)

The `env` option decides which variables the command receives. Passing unvetted environment variables across privilege boundaries is one of the most common vectors of local privilege escalation. Charly's `APT_CONFIG` issue is a perfect example. For this reason, `dosr` processes the environment through several filters, fail-safe checks and layers of inheritance.

#### Allowlisting and denylisting

The main field is `default`, which can be set to one of three modes:

* **`delete` mode (allowlist):** The environment starts empty. Variables are only passed if they are named in the `keep` list, or named in the `check` list and validated as safe. As it is impossible to maintain an exhaustive list of every dangerous variable, this is the built-in default, following the fail-safe default principle.
* **`keep` mode (denylist):** The environment starts with the user's full environment. Variables are passed unless they match the `delete` list. Variables matching `check` are verified before they can pass. Use this mode only in trusted environments.
* **`inherit` mode:** Preserves the mode chosen by the level above. If every level omits `default` or sets it to `inherit`, the built-in default `delete` mode applies.

With these modes, the policy manages environment variables like mathematical sets.

#### Pattern matching and the evaluation pipeline

Entries in `keep`, `check` and `delete` support simple wildcard matching with `*` (such as `LC_*` or `*_PROXY`). Since version 4.1, regular expressions have been replaced entirely by these wildcard patterns.

Regardless of the mode, every execution goes through this filtering pipeline:

1. **Shellshock hardening:** any variable whose value begins with `()` is dropped.
1. **`check` list:** a feature inherited from sudo. A value is deemed safe only if it contains neither slashes (`/`) nor percent signs (`%`). In the early 2000s, these characters were exploited through poorly written printf-based programs; this check is a legacy safeguard.
1. **Timezone validation:** `TZ` is an exception, and accepts values like `Europe/Paris`, provided they do not start with a slash, contain path traversal sequences like `..`, or include spaces and control characters.
1. **Set combination:** in `delete` mode, a variable matched by both `keep` and `check` must pass the check. In `keep` mode, a variable matched by both `delete` and `check` is deleted.
1. **Target and execution context:** `dosr` populates `PATH` strictly from the [`path` option](#the-path-option) (overriding any existing `PATH`), sets the identity variables of the target user (`USER`, `LOGNAME`, `HOME` and `SHELL`), and adds audit variables describing the caller and the command (`RAR_UID`, `RAR_GID`, `RAR_USER`, `RAR_COMMAND`, and their `SUDO_*` counterparts). `TERM` defaults to `unknown` if no valid terminal was passed.
1. **`set` directive:** finally, the key-value assignments under `set` (for example `{"NAME": "value"}`) are applied. They take absolute precedence, overriding anything from earlier stages, including `PATH` and `HOME`.

#### Level inheritance: preserving protections by default

`dosr` resolves the configuration hierarchically, starting from built-in defaults (set at compilation time via `RAR_ENV_*`), then global, role and task options.

To prevent security regressions, inheritance follows one rule: **a protection must never disappear simply because a lower level failed to mention it.**

The most specific level that defines `default` (`delete` or `keep`) sets the mode. For the lists (`keep`, `check`, `delete` and `set`):

* If a level defines a list **without** declaring `default`, its entries are merged with the inherited list.
* If a level defines a list **and** sets `default` to `delete` or `keep`, its list replaces the inherited one.
* Unmentioned lists are always inherited. If a lower level switches to `keep` mode but omits the `delete` list, it still inherits the dangerous variables blocked upstream. The only way to strip an inherited restriction is a deliberate empty list (`[]`).

#### Concrete behavior example

Consider global options configured as:

```json
{"env": {"default": "delete", "keep": ["EDITOR"]}}
```

A user invokes `dosr` with the following environment:
`EDITOR=vim PAGER=less FOO=bar LD_PRELOAD=/tmp/x.so LANG=fr_FR.UTF-8 LC_ALL=../x TZ=Europe/Paris`, along with an exported shell function.

Depending on the task definition, the command receives:

* **Task defines no `env` options:** `EDITOR`, `LANG` and `TZ`. `EDITOR` comes from the global allowlist, while `LANG` and `TZ` pass the built-in `check` list. `PAGER` and `FOO` are discarded by the allowlist, `LC_ALL` is rejected by the check because of the `/`.
* **Task specifies `{"keep": ["PAGER"]}`:** no mode is declared, so `PAGER` is added to the inherited allowlist. The command receives `EDITOR`, `PAGER`, `LANG` and `TZ`.
* **Task specifies `{"default": "delete", "keep": ["PAGER"]}`:** the mode is re-declared, so the upstream `keep` list is replaced. The command receives `PAGER`, `LANG` and `TZ`, losing `EDITOR`.
* **Task specifies `{"default": "delete", "keep": [], "check": []}`:** the empty lists suppress both the allowlist and the check list. The command receives none of the caller's variables.
* **Task specifies `{"default": "keep"}`:** the task switches to denylist mode, passing `EDITOR`, `PAGER`, `FOO`, `LANG` and `TZ`. Since the inherited `delete` list was not cleared, built-in protections still block `LD_PRELOAD`.

#### Preserving the environment with `dosr -E`

`-E` asks for `keep` mode. It is only accepted when `override_behavior` is `true` on the most specific level that sets it (built-in default: `RAR_ENV_OVERRIDE_BEHAVIOR`, `false`). A task that does not allow it is not selected: `dosr` chooses another task, or answers "Permission denied".

`-E` is `keep` mode, not "everything": the `delete` list, the `check` list and the shell function rule still apply. The `-E` option does not aim to silently allow everything, but to let the user keep some of their variables. RaR enforces trust boundaries, and allowing everything *by default* would break them. If you really want to pass everything, set `delete` and `check` to empty lists in the task, so that it is explicit in the configuration.

#### Applying it to WebOps

The global level keeps the built-in `delete` mode, which already drops `APT_CONFIG`: charly's hook escalation is gone without writing a single line. The team simply makes it explicit:

```json
"options": {
  "env": { "default": "delete" }
}
```

For bob's `read-logs` task, the `set` directive disables the shell escape of `less` and any pager:

```json
"options": {
  "env": {
    "set": {
      "LESSSECURE": "1",
      "SYSTEMD_PAGER": ""
    }
  }
}
```

Since no `default` is declared at the task level, the global mode and lists are inherited, and these values are added on top.

### The `path` option

The `PATH` variable is a colon-separated list of directories searched for executables. The `path` option controls it and must be carefully configured to avoid privilege escalation.

One question could be: "Why isn't `path` part of `env`?". Because this option is also used to **find the command** typed by the user: it is not only the resulting `PATH` variable, it is part of the task selection process.

This option works, again, like mathematical sets, with `add` and `sub` (alias `del`) lists. Its `default` mode can be:

- `delete`: start from an empty list and add directories. This is the recommended mode.
- `keep-safe`: start from the caller's `PATH`, and remove relative paths (such as `.` or `bin`). Absolute directories are kept as is, even if they are writable by the caller.
- `keep-unsafe`: start from the caller's `PATH` as is. Avoid it.
- `inherit`: use the mode of the level above.

For WebOps, the global level only allows system directories, including `/usr/local/bin` where `caddy-probe` lives:

```json
"path": {
  "default": "delete",
  "add": ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
}
```

These directories must only be writable by root; otherwise, anyone able to write to them could plant a binary that a task would run.

### Other options

| Option           | Values                          | Description                                                                                                       |
|------------------|---------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `authentication` | `perform` \| `skip`             | Whether the user must authenticate before running the command.                                                    |
| `timeout`        | `type`, `duration`, `max_usage` | How long, and how many times, an authentication remains valid, and its scope (`ppid`, `tty` or `uid`).           |
| `root`           | `privileged` \| `user`          | `user` sets the `SECBIT_*` securebits that disable the special privileges of uid 0: root becomes a regular user, and gets only the capabilities granted by the task. `privileged` keeps the legacy root behavior. |
| `bounding`       | `strict` \| `ignore`            | `strict` enforces the granted capabilities on the bounding set: the command and its children can never regain any other capability. |
| `execinfo`       | `show` \| `hide`                | Whether `dosr --info` may disclose the existence of the matching policy element to the user.                       |
| `workdir`        | path \| selector                | Working directory of the command, or the set of directories the user may choose.                                  |
| `umask`          | string                          | File creation mask of the command.                                                                                |

The `root` option deserves attention. On Linux, a process running as uid 0 that executes a binary automatically obtains all capabilities. Without `"root": "user"`, a task with `"setuid": "root"` and `"capabilities": []` would get them back as soon as the command runs another program. This is what makes the WebOps `caddy-service` and `reboot` tasks really unprivileged, so the team sets `root` to `user` and `bounding` to `strict` globally.

`execinfo` also has a security impact: listing what the policy allows is valuable information for an attacker who stole an account. The team sets it to `hide` globally.

For `sys-admin`, the most critical role, the team requires authentication on every use, with a short and non-reusable timeout:

```json
"options": {
  "authentication": "perform",
  "timeout": { "type": "tty", "duration": "00:01:00", "max_usage": 1 }
}
```

### Migrating configurations from version 4.0

Upgrading from version 4.0 requires running `chsr upgrade` as root. Package maintenance scripts run it automatically during updates.

This utility addresses differences in pattern syntax and list inheritance:

* It converts legacy regex syntax into wildcards, translating patterns like `X.*` into `X*` and stripping anchors (`^`, `$`). More complex regular expressions that cannot be adapted automatically are reported in the logs for manual review.
* It updates legacy global `delete` definitions containing the old 6-entry default to the current, expanded default set.
* To ensure existing security profiles do not change under the new inheritance model, it injects explicit `"keep": []` and `"check": []` into legacy `delete`-mode levels that left them undefined.

Tasks still using unmigrated regular expressions are rejected by `dosr` at runtime until the upgrade has been completed.

## Hierarchy and separation of duty

Hierarchy and separation of duty (SoD) are designed as plugins on top of the core RBAC-0 model. They are not part of the core model, but they are implemented in the RaR project.

- The **hierarchy** plugin lets a role declare its parent roles, through the `parents` field. The role inherits the tasks of its parents.
- The **static separation of duty** plugin declares conflicting roles, through the `ssd` field: a user should never be an actor of two conflicting roles.

### Applying it to WebOps

Bob operates Caddy, so he also needs to read its logs. Instead of duplicating the `read-logs` task, `caddy-admin` declares `caddy-audit` as its parent, and inherits its tasks:

```json
{
  "name": "caddy-admin",
  "parents": ["caddy-audit"],
  ...
}
```

Later, when a security auditor joins the team, they can be assigned `caddy-audit` alone, without getting the ability to restart the webserver. This is why we split these roles earlier.

The incident also taught the team that bob's account is the most exposed one: it uses `caddy-probe`, a custom tool that parses untrusted network traffic. This account must never accumulate the root-equivalent `sys-admin` role, even if bob replaces charly during his holidays:

```json
{
  "name": "sys-admin",
  "ssd": ["caddy-admin"],
  ...
}
```

### Conflict resolution

<blockquote class="caroot">
There are currently some issues on the combination of role hierarchy and static separation of duties.
</blockquote>

Both plugins have fail-safe behaviors:

- If a user is an actor of two conflicting roles, they cannot execute any task from either role.
- If a role inherits from roles that are in conflict with each other, the user cannot execute any task from the inherited roles.

In other words, a misconfiguration denies access rather than granting it.

## Other plugins and extensions

RaR supports extension fields, such as `parents` and `ssd` above. These fields are preserved by the policy model and consumed by the relevant tooling and plugins.

### `files` with Landlock

The `files` field of `cred` defines a Landlock sandbox for the command. Landlock is a Linux security module that allows unprivileged processes to confine themselves to a limited set of resources, such as specific directories or files. In RaR, `files` maps paths to their access rights (read, write, execute), enforced by Landlock when the command is executed.

This is a natural next step for the WebOps team: the `web-push` task could, for instance, be denied write access anywhere outside `/srv/www`, even as `www-data`. Keep in mind that the sandboxed command still needs to read and execute its own libraries.

### `dbus` for D-Bus/Polkit enforcement

`dbus` entries are primarily used by `gensr`-driven workflows to generate D-Bus/Polkit enforcement artifacts.

### Deprecation of the hashchecker plugin

The `hashchecker` plugin was deprecated in version 4.1.0. It verified the integrity of executed binaries by comparing their cryptographic hashes against an allowlist defined in the policy. RaR now recommends the IPE LSM (Integrity Policy Enforcement) for binary integrity verification. As RaR handles privileged operations, only the IPE LSM can completely avoid TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities.

A TOCTOU vulnerability is a race condition where an attacker modifies data between the time it is checked and the time it is used. In RaR's case, an attacker with enough privileges could modify the binary between the hash check and its execution, giving a false sense of security. This is because RaR runs in userspace. A kernel-level security module is required, which is why the IPE LSM is the recommended way to enforce binary integrity.

## The complete WebOps policy

Here is the resulting `/etc/security/rootasrole.d/default.json`:

```json
{
  "version": "4.1.0",
  "options": {
    "path": {
      "default": "delete",
      "add": ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
    },
    "env": { "default": "delete" },
    "root": "user",
    "bounding": "strict",
    "execinfo": "hide",
    "authentication": "perform"
  },
  "roles": [
    {
      "name": "webadmin",
      "actors": [{ "group": ["webadmin"] }],
      "tasks": [
        {
          "name": "web-push",
          "purpose": "Publish website content from the staging area",
          "commands": [
            "/usr/bin/install ^-d -m 0?[0-7]{3} /srv/www/[^ ]+$",
            "/usr/bin/rsync ^-rlt --delete /srv/staging/[^ ]+/ /srv/www/[^ ]+/$"
          ],
          "cred": {
            "setuid": "www-data",
            "setgid": "www-data",
            "capabilities": []
          }
        }
      ]
    },
    {
      "name": "caddy-audit",
      "actors": [{ "group": ["caddy-audit"] }],
      "tasks": [
        {
          "name": "read-logs",
          "purpose": "Read Caddy access logs and journal",
          "commands": [
            "/usr/bin/tail ^(-n [0-9]+|-f) /var/log/caddy/[^/ ]+$",
            "/usr/bin/less ^/var/log/caddy/[^/ ]+$",
            "/usr/bin/journalctl --no-pager -u caddy"
          ],
          "cred": {
            "setgid": ["adm", "systemd-journal"],
            "capabilities": []
          },
          "options": {
            "env": {
              "set": { "LESSSECURE": "1", "SYSTEMD_PAGER": "" }
            }
          }
        }
      ]
    },
    {
      "name": "caddy-admin",
      "parents": ["caddy-audit"],
      "actors": [{ "group": ["caddy-admin"] }],
      "tasks": [
        {
          "name": "caddy-service",
          "purpose": "Manage the Caddy systemd unit",
          "commands": [
            "/usr/bin/systemctl ^(start|stop|restart|reload) caddy$",
            "/usr/bin/systemctl status --no-pager caddy"
          ],
          "cred": {
            "setuid": "root",
            "capabilities": []
          }
        },
        {
          "name": "caddy-probe",
          "purpose": "Diagnose Caddy configuration and capture traffic",
          "commands": ["/usr/local/bin/caddy-probe"],
          "cred": {
            "setgid": "www-data",
            "capabilities": ["CAP_NET_RAW"]
          }
        }
      ]
    },
    {
      "name": "sys-admin",
      "ssd": ["caddy-admin"],
      "actors": [{ "group": ["sys-admin"] }],
      "options": {
        "timeout": { "type": "tty", "duration": "00:01:00", "max_usage": 1 }
      },
      "tasks": [
        {
          "name": "apt",
          "purpose": "Apply system and Caddy updates (root-equivalent)",
          "commands": [
            "/usr/bin/apt update",
            "/usr/bin/apt upgrade",
            "/usr/bin/apt dist-upgrade",
            "/usr/bin/apt --only-upgrade install caddy"
          ],
          "cred": {
            "setuid": "root",
            "setgid": "root",
            "capabilities": "all"
          }
        },
        {
          "name": "reboot",
          "purpose": "Reboot the machine after updates",
          "commands": ["/usr/bin/systemctl reboot"],
          "cred": {
            "setuid": "root",
            "capabilities": []
          }
        }
      ]
    }
  ]
}
```

Let's wrap up this policy from compared to before. The policy replaces permissions tied to individuals with roles assigned to groups. Compared to sudo-rs, it also removes the unrestricted `(ALL)` target-user selection by forcing `setuid` and `setgid` for each task. Strict regular expressions prevent wildcards from swallowing extra arguments in `install`, while log-file patterns reject `/` so that paths cannot traverse outside the Caddy log directory.

Pager escapes are addressed by requiring `--no-pager` for `systemctl` and `journalctl`, setting `LESSSECURE=1` for `less`, and ensuring that any escape only retains Bob's own identity and group privileges. The vulnerable `caddy-probe` no longer runs as root: it runs with the `www-data` group and `CAP_NET_RAW` only. The global `"root": "user"` and `"bounding": "strict"` options also prevent a root process from regaining every privilege after executing another program.

Finally, the built-in `delete` environment mode blocks the `APT_CONFIG` hook. The root-equivalent `apt` task is isolated in its own role, protected by strict authentication and separation of duty from `caddy-admin`. Rebooting is a separate task with its own purpose and runs as root without capabilities.

## Going further: towards Zero Trust

One issue remains open: charly's `apt` task is root-equivalent, and nobody verifies what he does with it. Zero Trust follows the principle "never trust, always verify". When an action cannot be prevented, it must at least be **attributed** and **verified** by someone else.

The system ships with a configured `auditd` service. The idea is to let charly keep his root-equivalent task, while making sure he cannot tamper with the audit trail of his own actions.

First, we remove the audit-related capabilities from the `apt` task:

```json
"capabilities": {
  "default": "all",
  "del": ["CAP_AUDIT_CONTROL", "CAP_AUDIT_WRITE", "CAP_AUDIT_READ", "CAP_LINUX_IMMUTABLE"]
}
```

- `CAP_AUDIT_CONTROL` allows changing the audit rules, and changing the login uid of a process. Removing it keeps every action attributed to charly, even after the switch to root.
- `CAP_AUDIT_WRITE` allows forging audit records.
- `CAP_AUDIT_READ` allows reading the audit stream.
- `CAP_LINUX_IMMUTABLE`, as seen in [Where the policy lives](#where-the-policy-lives), protects the policy itself.

Then, the audit rules should be locked with `auditctl -e 2`, so that they cannot be changed until the next reboot.

However, this is a denylist on a root-equivalent task, and we warned earlier that denylists are fragile. A malicious package can still stop `auditd`, edit `/var/log/audit/` through root's DAC ownership, or load a kernel module (`CAP_SYS_MODULE`). And the `reboot` task unlocks the audit rules. The local audit trail is therefore not enough on its own. This is why:

1. audit logs must be **exported in real time** to a remote collector (including RaR logs too), ideally a SOC, so that they leave the machine before they can be altered;
2. they must be retrieved and verified by **someone outside the WebOps team**. If this person is given a role on the machine, this role should be declared in `ssd` with `sys-admin`.

The result is not a prevention mechanism: charly can still do anything as root. But nothing he does can go unnoticed, and this is the best guarantee available for a root-equivalent task.

## The final configuration structure in UML

<div class="diagram-container">
  <object class="zoomable-svg" type="image/svg+xml" data="assets/policy.svg">
    Your browser does not support the SVG format.
  </object>
</div>

<blockquote class="caroot-stare">
This section is AI-generated based on the schema.
</blockquote>

This diagram brings all the previous structures together to show how a complete policy is assembled. Rather than re-explaining how each feature works, this view focuses on how the components connect, how elements reference each other, and where each setting lives.

### Files and loading (`Root file`)

Everything starts with `RootFile` (`rootasrole.json`), which holds a `Storage` block to locate policy data. Both `RootFile` and standalone `PolicyFile` structures share the same foundation via the abstract `PolicyContent` structure: a format version, an optional set of options, and a list of roles.

As indicated by the note on `StorageSettings`, the `path` attribute drives how the policy is loaded. If it points back to the root file itself, the roles declared directly inside `RootFile` are used. If it points elsewhere (a file or a directory), the engine loads external `PolicyFile` resources instead.

### Authorization model (`Policy`)

The `Policy` package contains the core entities for access control:

* **`Role`** acts as the central link. It ties who can run commands (`Actor`) to what can actually be run (`Task`). The `parents` and `ssd` fields represent hooks for role hierarchy and separation of duties.
* **`Actor`** branches into either a single `UserActor` or a `GroupActor` (which requires all specified groups).
* **`Task`** pairs an execution context (`Credentials`) with allowed commands (`CommandRepresentation`).
* **`Credentials`** defines the target execution identity (`setuid`, `setgid`), the Linux `capabilities`, and a file sandbox map managed by the Landlock plugin.
* **`CommandRepresentation`** handles how commands are matched: either as blanket rules (`all`, `none`), a simple list of `Command` objects, or a dynamic `CommandSelector`.

### Granular filtering (`Selectors`)

At the bottom of the policy package, the `Selectors` group (`UserSelector`, `GroupSelector`, `CapSelector`, and `CommandSelector`) provides a standard way to build sets of allowed values, as explained earlier. Each selector uses a `default` baseline, adds or subtracts specific items via `add` and `sub` (aliased as `del`), and provides an optional `fallback` where applicable.

### Configuration scope (`Inheritable Settings`)

The `Inheritable Settings` package defines runtime configurations through the `Options` structure. It groups several specialized sub-options:

* `PathOptions` and `EnvOptions` manage paths and environment variables.
* `WorkdirOptions` controls directory handling.
* `Timeout` manages credential caching and expiration limits.
* Direct fields handle system toggles like `root`, `bounding`, `authentication`, `execinfo`, and `umask`.

As shown by the three composition links originating from `PolicyContent`, `Role`, and `Task`, an `Options` block can be attached at any of these levels. The resolution follows the cascade indicated by the note: options set on a specific `Task` override those defined on its parent `Role`, which in turn override global policy options and built-in defaults.

## See also

- [chsr command overview](cli/chsr.md)
- [File Format Conversion](cli/chsr.md#file-format-conversion)