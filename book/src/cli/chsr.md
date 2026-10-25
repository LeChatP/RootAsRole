# `chsr`

<blockquote class="caroot-stare">
This section is AI-generated and reviewed by human.
</blockquote>

`chsr` (change switch role) is the tool that writes the policy that `dosr` reads. It manages roles, tasks, commands, credentials and options, and it refuses the values that `dosr` would not accept, instead of writing them.

The policy is protected: its files belong to root, and when the file system supports it, they are immutable. So `chsr` needs privileges too, and you run it through `dosr`. At the installation, the default policy gives the installer a role for that:

```bash
dosr chsr list
```

<blockquote class="caroot-stare">
Whoever can run chsr can give themselves any privilege. The role that allows it is root-equivalent: grant it to as few people as possible, and keep it away from the most exposed accounts with a separation of duty.
</blockquote>

In the rest of this chapter, we omit `dosr` before `chsr`.

## How a `chsr` command reads

A `chsr` command walks down the policy, like a path in a file system. Each word narrows where the change applies:

```bash
chsr role ops task reboot options root user
```

reads as: in the role `ops`, in its task `reboot`, set the option `root` to `user`. The same command without `task reboot` applies to the whole role, and without `role ops`, to the whole policy.

Most keywords have a short form. The following commands are the same:

```bash
chsr role ops task reboot options root user
chsr r ops t reboot o root user
```

| Long form | Short form |
|-----------|------------|
| `role` | `r` |
| `task` | `t` |
| `options` | `o` |
| `command` | `cmd` |
| `credentials` | `cred` |
| `list`, `show` | `l` |
| `whitelist`, `blacklist` | `wl`, `bl` |
| `checklist`, `setlist` | `cl`, `sl` |
| `add` | `create` |
| `delete` | `del`, `d`, `rm`, `unset` |

When you are lost, `chsr --help` shows the main commands, and `-h` after an option shows its own help, like `chsr options path -h`. When a command is wrong, `chsr` tells which word it did not expect, and shows the help of that part. The complete grammar is available at <https://github.com/LeChatP/RootAsRole/tree/main/src/chsr/cli/cli.pest>.

## Look before you change

Before modifying anything, look at what is there. Every view is printed in JSON, exactly as it is stored:

```bash
chsr list                                # the whole policy, file by file
chsr r caddy-audit l all                 # a role: its actors, tasks, or all
chsr r caddy-audit t read-logs l cmd     # a task: its cmd, cred, or all
chsr o l env                             # an option of the whole policy
chsr r sys-admin o l timeout             # an option of a role
```

The options that you can show are `all`, `path`, `env`, `root`, `bounding`, `timeout`, `password`, `authentication`, `execinfo`, `umask` and `workdir`.

## Building the WebOps policy

The [Configuration](../configuration.md) chapter writes the WebOps policy in JSON. Here is the same policy, built with `chsr`, one need at a time.

### 1. Safe defaults for the whole policy

The team starts with the options that every role inherits: a fixed `PATH`, an environment that keeps nothing by default, root as a regular user, a strict bounding set, and no disclosure of the policy to users.

```bash
chsr o path setpolicy delete-all
chsr o path wl set /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
chsr o env setpolicy delete-all
chsr o root user
chsr o bounding strict
chsr o execinfo hide
chsr o auth perform
```

Most of these values are already the defaults of RaR. Setting them explicitly is a good practice anyway: a reader of the policy does not have to know the defaults of the version that was installed.

### 2. Roles and actors

Each responsibility becomes a role, granted to a group rather than to a person:

```bash
chsr r webadmin add
chsr r webadmin grant -g webadmin
chsr r caddy-audit add
chsr r caddy-audit grant -g caddy-audit
chsr r caddy-admin add
chsr r caddy-admin grant -g caddy-admin
chsr r sys-admin add
chsr r sys-admin grant -g sys-admin
```

`grant -u alice` would grant a user instead. `-g` also accepts a combination of groups, `-g webadmin,staff`: the user must then be a member of all of them. `revoke` takes the same arguments.

### 3. Tasks and their purpose

A task is created inside its role. Give it a purpose: in six months, the purpose is what tells you why this task exists.

```bash
chsr r webadmin t web-push add
chsr r webadmin t web-push purpose set Publish website content from the staging area
```

<blockquote class="caroot">
Keep your tasks narrow! One operational action per task is the golden rule.
</blockquote>

### 4. Commands

The `cmd` of a task is a whitelist of command lines, and a blacklist that takes precedence over it. The command is written after `add`, as you would type it, with its absolute path:

```bash
chsr r caddy-audit t read-logs cmd wl add /usr/bin/journalctl --no-pager -u caddy
```

When the arguments are a regular expression, quote the whole command line, so that your shell does not interpret `(`, `|`, `[` or `$`:

```bash
chsr r caddy-audit t read-logs cmd wl add '/usr/bin/tail ^(-n [0-9]+|-f) /var/log/caddy/[^/ ]+$'
chsr r caddy-audit t read-logs cmd wl add '/usr/bin/less ^/var/log/caddy/[^/ ]+$'
```

A regular expression always applies to the whole arguments: `^start|stop$` allows `start` or `stop` alone, not any arguments that start with `start`. A command written without arguments allows no argument. To allow any of them, write it explicitly with `^.*$`. `del` removes a command, `purge` empties the list, and `cmd setpolicy allow-all` or `deny-all` sets what is allowed by default.

<blockquote class="caroot-stare">
Do not forget that setting <code>cmd setpolicy allow-all</code> allows every command of the system to this task. You never know what a user is able to run, and what it can do with it. The default <code>deny-all</code> is the safe choice.
</blockquote>

### 5. Credentials

The credentials say with which user, groups and capabilities the command runs. `cred set` forces them:

```bash
chsr r webadmin t web-push cred set --setuid www-data --setgid www-data
chsr r webadmin t web-push cred caps setpolicy deny-all
chsr r caddy-audit t read-logs cred set --setgid adm,systemd-journal
chsr r caddy-audit t read-logs cred caps setpolicy deny-all
```

The capabilities have their own whitelist and blacklist. `caddy-probe` only needs to capture packets:

```bash
chsr r caddy-admin t caddy-probe add
chsr r caddy-admin t caddy-probe cmd wl add /usr/local/bin/caddy-probe
chsr r caddy-admin t caddy-probe cred set --setgid www-data
chsr r caddy-admin t caddy-probe cred caps wl add CAP_NET_RAW
```

The `CAP_` prefix is optional, and `cred unset` removes what `cred set` wrote. `cred set` forces one user and one set of groups. To let users choose with `dosr -u` or `dosr -g` among several ones, write a [selector](../configuration.md#selector-forms) with `chsr editor`.

A task that changes the user without `--setgid` gives the command the groups of that user, as a login does. To keep the groups of the person who runs `dosr` instead, say it:

```bash
chsr r ops t backup cred set --setuid backup --setgid-from caller
```

`--setgid-from target` comes back to the default, and `cred unset --setgid-from target` removes it.

### 6. Options of a role or a task

Options are set at the level where they apply, and inherited below. `less` must not open other files or a shell, and the pagers of systemd must be disabled:

```bash
chsr r caddy-audit t read-logs o env set LESSSECURE=1,SYSTEMD_PAGER=
```

The root-equivalent `sys-admin` role requires a fresh authentication for each command:

```bash
chsr r sys-admin o timeout set --type tty --duration 00:01:00 --max-usage 1
```

### 7. Hierarchy and separation of duty

`caddy-admin` inherits the tasks of `caddy-audit`, and `sys-admin` must never be held together with `caddy-admin`:

```bash
chsr r caddy-admin parents add caddy-audit
chsr r sys-admin ssd add caddy-admin
```

Both take a list of roles separated by commas, with `add`, `del`, `set` or `purge`.

### 8. Check the result

```bash
chsr r caddy-audit l all
```

```json
{
  "name": "caddy-audit",
  "actors": [
    {
      "type": "group",
      "groups": "caddy-audit"
    }
  ],
  "tasks": [
    {
      "name": "read-logs",
      "options": {
        "env": {
          "set": {
            "LESSSECURE": "1",
            "SYSTEMD_PAGER": ""
          }
        }
      },
      "purpose": "Read Caddy access logs and journal",
      "cred": {
        "setgid": [
          "adm",
          "systemd-journal"
        ],
        "capabilities": "none"
      },
      "commands": [ … ]
    }
  ]
}
```

`chsr` writes the long form of the actors, `{"type": "group", …}`, and `"none"` for an empty set of capabilities. `dosr` reads both forms, so you can keep the short ones in the files that you write by hand.

## Options reference

Each option can be set on the whole policy (`chsr o …`), on a role (`chsr r <role> o …`) or on a task (`chsr r <role> t <task> o …`). `unset` (or `del`) removes the value of this level, so that the level above applies again.

| Option | Commands | |
|--------|----------|---|
| `path` | `setpolicy delete-all\|keep-safe\|keep-unsafe\|inherit`, `set`, `wl`/`bl` `add\|del\|set\|purge` | The `PATH` of the command. Entries are separated by `:`. |
| `env` | `setpolicy delete-all\|keep-all\|inherit`, `wl`/`bl`/`cl` `add\|del\|set\|purge`, `keep-only`, `delete-only`, `set`, `sl`, `override allow\|deny\|unset` | The environment of the command. `override` decides whether `dosr -E` is accepted. |
| `workdir` | `setpolicy all\|none\|inherit`, `set`, `wl`/`bl` | The working directory. |
| `root` | `user\|privileged\|unset` | Whether uid 0 keeps its special privileges. |
| `bounding` | `strict\|ignore\|unset` | Whether the capabilities that are not granted are removed from the bounding set. |
| `authentication` | `perform\|skip\|unset` | Whether the user must authenticate. |
| `timeout` | `set\|unset` `--type tty\|ppid\|uid` `--duration HH:MM:SS` `--max-usage N` | How long, and how many times, an authentication is reused. |
| `password` | `set\|unset` `--tries 1-255` `--delay HH:MM:SS` | How many times the password is asked, and the delay after a wrong one. |
| `execinfo` | `show\|hide\|unset` | Whether `dosr -i` may show the execution context. |
| `umask` | `022`, `del` | The file creation mask, in octal. |

For the meaning of each value, see [Options and inheritance](../configuration.md#options-and-inheritance).

## Policy directories: `chsr file`

When the policy is a directory, like `/etc/security/rootasrole.d/`, a command edits one file of it: `default.json`, or the only file when there is one. To work on another file of the directory, here `monitoring.json`, name it with `chsr file`, by its path or by its name. `chsr` refuses a file that is not part of the policy. It also refuses, with the reason, a file that it cannot load, like a file written by hand without its `version`: `chsr upgrade --check` lists them all.

```bash
chsr file list
chsr file monitoring.json r prometheus add
chsr f /etc/security/rootasrole.d/monitoring.json o l
```

`chsr list` shows every file of the policy, with its path. When `chsr` saves, it writes only the files that changed. The files that it creates are readable and writable by their owner only.

## `chsr editor`

`chsr editor` opens a policy file in a text editor, for the changes that are easier to write in JSON, like the selectors:

```bash
chsr editor                    # default.json, like the other commands
chsr editor monitoring.json    # another file of the policy
```

Without a path, it opens the same file as the other commands: `default.json` of a policy directory, or the only file. With a path or a name, it opens that file of the policy, like `chsr file`. To change where the policy is stored, give the path of the root file, `/etc/security/rootasrole.json`.

`chsr` copies the file into a private temporary folder in `/tmp` and starts the editor on the copy. When you quit the editor, `chsr` reads the result and validates it. If it is invalid, `chsr` tells why, and you continue editing or abort. If it is valid, `chsr` shows the resulting configuration and asks for a confirmation before saving it.

The editor is one of the editors chosen when RootAsRole was built (`/usr/bin/vim` by default). The `RAR_EDITOR` variable can select another one, but only among them. `vim` is started without your `vimrc` and without plugins, since they could run anything with the privileges of `chsr`.

Before starting the editor, `chsr` restricts itself with Landlock: the editor can only reach the policy files, its temporary folder, and the files that it needs to run. On a kernel without Landlock, `chsr` refuses to start the editor.

<blockquote class="caroot-stare">
Read the resulting configuration before you answer yes: what <code>chsr</code> saves is what it understood, not what you typed.
</blockquote>

## `chsr upgrade`

A new version of RootAsRole may change how the policy is written. After an upgrade, `chsr upgrade` rewrites the policy files in the format of the installed version. Packages run it for you during their updates.

```bash
chsr upgrade --check
```

`--check` only shows what would be upgraded, and fails if any file needs it: it is the right command for a script or a monitoring check.

## File Format Conversion

`chsr convert` converts the policy between JSON and CBOR. JSON is easy to read and to review. CBOR is a binary format, much faster to load: when your policy is ready, you can convert it.

```text
chsr convert [-r] [--from <type> <file>] <type> <file>
```

- `<type>` is `json` or `cbor`, and `<file>` is the file to write.
- `--from` reads another file than the current policy, with its format.
- `-r` (or `--reconfigure`) also updates `/etc/security/rootasrole.json`, so that `dosr` uses the new file.

Convert the current policy to CBOR, and use it:

```bash
chsr convert -r cbor /etc/security/rootasrole.bin
```

Come back to JSON:

```bash
chsr convert -r json /etc/security/rootasrole.json
```

Convert a file without changing what `dosr` uses:

```bash
chsr convert --from json /etc/security/rootasrole.json cbor /etc/security/rootasrole.bin
```

<blockquote class="caroot">
Keep the converted files in a protected system path, owned by root, and make them immutable. Also if you keep a copy on your working directory, do not make it readable by anyone else. Letting those files allows an attacker to discover your own policy.
</blockquote>

## Operational notes

- Keep the policy under version control, or at least keep a backup, before large changes.
- Check what a user can do with `dosr -i <command>`, on a task where `execinfo` is `show`, or read the policy with `chsr list`.
- After a conversion or an upgrade, run a command of each critical task once.
