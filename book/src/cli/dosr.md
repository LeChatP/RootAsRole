# `dosr`

<blockquote class="caroot-stare">
This section is AI-generated and reviewed by human.
</blockquote>

`dosr` (do switch role) runs a command with the privileges of one task of the policy, and nothing more. You do not become root: you get the user, the groups and the Linux capabilities that this task gives to this command.

This chapter explains what `dosr` does when you run it, how it chooses a task, and what you can control from the command line. It follows the WebOps team of the [Configuration](../configuration.md) chapter: alice, bob and charly now use `dosr` every day.

## Usage

<pre>
<u><b>Usage</b></u>: <b>dosr</b> [OPTIONS] [--] [COMMAND]...

<u><b>Options</b></u>:
  <b>-r, --role</b> &lt;ROLE&gt;             Role to use
  <b>-t, --task</b> &lt;TASK&gt;             Task to use in the selected role (--role required)
  <b>-u, --user</b> &lt;USER&gt;             User to execute the command as
  <b>-g, --group</b> &lt;GROUP&gt;(,&lt;GROUP&gt;...) Group(s) to execute the command as
  <b>-E, --preserve-env</b>            Keep your environment variables, if a matching task allows it
  <b>-D, --chdir</b> &lt;DIR&gt;             Working directory of the command
  <b>-p, --prompt</b> &lt;PROMPT&gt;         Prompt to display instead of "Password: "
  <b>-S, --stdin</b>                   Read the password from the standard input
  <b>-K, --remove-timestamp</b>        Remove your timestamp cookies before authentication
  <b>-i, --info</b>                    Print the execution context of a command, if a matching task allows it
  <b>-h, --help</b>                    Print help
  <b>-v, --version</b>                 Print version
</pre>

## What happens when you run `dosr`

Let's follow bob, who wants to read the last lines of the Caddy access log:

```bash
dosr tail -n 50 /var/log/caddy/access.log
```

1. **Options first.** `dosr` reads its own options until the first word that is not an option: this is the command. Everything after it belongs to the command, even when it starts with `-`. Here, `-n 50` is given to `tail`, not to `dosr`. Like with sudo, `--` also ends the options of `dosr`.
2. **Finding the tasks.** `dosr` reads the policy, keeps the roles where bob is an actor, and looks for the tasks whose commands match `tail -n 50 /var/log/caddy/access.log`. `tail` is resolved with the `path` option of the policy, never with the current directory.
3. **Authentication.** `dosr` asks for bob's password through PAM. It asks it even when no task matches: before bob is authenticated, `dosr` reveals nothing about the policy. Someone who stole bob's account cannot list what the policy allows without his password.
4. **The decision.** If no task matches, `dosr` answers "You are not allowed to execute this command, this incident will be reported." and logs the attempt.
5. **The execution context.** `dosr` prepares the user, the groups and the capabilities of the task, filters the environment, sets the working directory and the umask. If the task needs a capability that this session can never obtain, `dosr` stops here and tells which ones.
6. **The execution.** `dosr` logs the execution, runs the command and waits for it. When the command ends, `dosr` ends the same way.

<blockquote class="caroot">
dosr does not run a shell, like sudo does as well. When you are doing <code>dosr echo hello > /etc/file</code>, the redirection is done by your own shell, with your own privileges, before <code>dosr</code> even starts. So, you can use <code>dosr sh -c 'echo hello > /etc/file'</code> to run the redirection with the privileges of the task.
</blockquote>

## How `dosr` chooses a task

A user may hold several roles, and several tasks may match the same command. In that case, `dosr` selects the most precise and least privileged task.

The precision comes first. It is about how closely the policy matches you and your command: a command line written in full is more precise than a regular expression on the arguments, which is more precise than a task that accepts any arguments. Then, only when two tasks are equally precise, the one with fewer privileges wins: fewer capabilities, no change to root, and so on.

Despite this selection, confusion can still arise. When two tasks are entirely equivalent but configure the command differently (for example with different environment variables), `dosr` cannot decide for you. It answers "Permission denied", and logs a warning saying that the policy must be fixed.

When you know which task you want, say it:

```bash
dosr -r caddy-audit -t read-logs tail -n 50 /var/log/caddy/access.log
```

This is the best practice in automation (Ansible, scripts): the selection is then deterministic, and a change in the policy cannot make your script use another task without you noticing.

## Choosing the user and the groups: `-u` and `-g`

By default, the task decides who the command runs as. With `-u` and `-g`, you ask for a specific user or group, but only among those that the task allows (see the [selector forms](../configuration.md#selector-forms)). A task that does not allow your request is not selected:

```bash
# Only accepted by a task whose setgid selector allows www-data
dosr -g www-data /usr/local/bin/caddy-probe
```

`-u` and `-g` do not give you a user: they choose one within the policy.

When the task changes the user and gives no groups, the command gets the groups of that user, its primary group and its supplementary groups, as a login gives them. It never mixes the new user with your own groups, unless the task asks for it with `"from": "caller"` in its `setgid`. A task that keeps your user keeps your groups.

## The environment of the command

The command does not inherit your environment. Only the variables allowed by the `env` option of the task cross the privilege boundary, and the variables that PAM modules set (`pam_env`, `pam_systemd`) go through the same filter. This is what stopped the `APT_CONFIG` hook of the WebOps scenario.

`dosr` then sets a few variables itself:

- `USER`, `LOGNAME`, `HOME` and `SHELL`, of the user the command runs as;
- `PATH`, from the `path` option of the task;
- `RAR_USER`, `RAR_UID`, `RAR_GID` and `RAR_COMMAND`, who asked for what;
- `SUDO_USER`, `SUDO_UID`, `SUDO_GID` and `SUDO_COMMAND`, the same values, for the scripts written for sudo;
- `TERM`, set to `unknown` if you had none.

With `-E`, you ask to keep your own variables. It is only accepted by a task that allows it, and even then, the `delete` and `check` lists still apply. See [Preserving the environment with `dosr -E`](../configuration.md#preserving-the-environment-with-dosr--e).

## The working directory: `-D`

The command runs in your current directory, entered as the user of the command, or in the directory that the `workdir` option forces. With `-D`, you ask for another directory, among those that the `workdir` option allows.

## Authentication

`dosr` authenticates you through PAM, with the `dosr` service: `/etc/pam.d/dosr`. A task may skip it with the `authentication` option, but think twice: this is the only step that proves the person typing is really the owner of the account.

A wrong password is asked again, after "Sorry, try again.", up to 3 times by default, with a delay of 5 seconds after each failure. The delay makes guessing slow. Any other PAM error stops at once. The `password` option changes both values, at any level of the policy:

```bash
chsr options password set --tries 3 --delay 00:00:05
```

`-p` changes the prompt, and `-S` reads the password from the standard input, when there is no terminal. When two `dosr` of the same pipeline need a password, like in `dosr cat a | dosr tee b`, the second one waits until the first is authenticated, and then reuses its cookie when the timeout allows it. They do not fight for your keystrokes anymore.

### Timestamps

Typing your password for every command is tiring, so `dosr` remembers a successful authentication for a while, according to the `timeout` option:

- `type` is the scope of the cookie. `ppid` reuses it for the same parent process (your shell) in the same session, `tty` for the same terminal, and `uid` for any process of your user, which is the widest;
- `duration` is how long it stays valid;
- `max_usage` is how many commands it can serve.

For their `sys-admin` role, the WebOps team chose a cookie per terminal, valid for one minute and one command only: this role is root-equivalent, so its authentication must stay fresh.

`dosr -K` removes your cookies, so the next command asks for your password again. Without a command, it only removes them.

<blockquote class="caroot-stare">
If you are using cookies for uid, be warned about this feature. If anyone has access to your user account, they can then use your cookie, performing privileged operations without needing your password. This all matters of your own security policy.
</blockquote>

## While the command runs

When you run `dosr` from a terminal, the command gets its own pseudo-terminal: it cannot push characters into your terminal to make your shell run them. `dosr` forwards the signals it receives to the command.

- **Ctrl+Z** suspends the command like any shell job, and `fg` or `bg` resumes it. Your unsaved work in an editor is not lost.
- **When `dosr` has to stop the command itself**, it sends SIGHUP and SIGTERM first, then SIGKILL two seconds later. A package manager or a database has time to remove its lock or to finish a write.
- **The exit status** is the one of the command. If the command was killed by a signal, `dosr` ends with the same signal, so your shell sees the usual 128 + N: 130 for Ctrl+C, 143 for SIGTERM. The errors of `dosr` itself end with status 1.

## Logs

Every execution, every refusal and every authentication failure is written to syslog, with the `auth` facility. An execution looks like this:

```text
bob : TTY=/dev/pts/0 ; PWD=/home/bob ; ROLE=caddy-audit ; TASK=read-logs ; USER=bob ; GROUPS=adm,systemd-journal ; CAPS=none ; COMMAND=/usr/bin/tail -n 50 /var/log/caddy/access.log
```

With systemd, you can read them with:

```bash
journalctl -t dosr
```

## Checking your rights: `-i`

`-i` shows what `dosr` would do, without running the command:

```text
$ dosr -i tail -n 50 /var/log/caddy/access.log
Role: caddy-audit
Task: read-logs
Execute as user: Your current user and group(s): adm (4), systemd-journal (999)
With capabilities: None
Command: /usr/bin/tail ["-n", "50", "/var/log/caddy/access.log"]
```

It only works with tasks whose `execinfo` option is `show`. Listing what the policy allows is valuable information for an attacker, so the WebOps team hides it everywhere: for them, `dosr -i` always answers that it is not allowed. An administrator can still read the whole policy with `chsr`.

## Coming from sudo

We kept most of the sudo command line, so that your habits and your scripts keep working. However, a few options differ:

| sudo | dosr | Note |
|------|------|------|
| `-u`, `-g`, `-E`, `-D`, `-p`, `-S`, `-K` | same | Only within what the task allows. |
| `-r` (SELinux role) | `-r` | The RootAsRole role. |
| `-i` (login shell) | `-i` | Prints the execution context instead. |
| `-l` | `-i` | For one command, if `execinfo` is `show`. |
| `-k` | `-K` | Removes the cookies. |
| `-s`, `-b`, `-n`, `-A`, `sudoedit` | none | Not available. |

If you're accustomed to utilizing the sudo tool and find it difficult to break that habit, consider creating an alias:

```sh
alias sudo="dosr"
alias sr="dosr"
```

### Future Design Considerations

Today, the CLI of `dosr` follows the one of sudo, to keep old scripts working. We might follow a new design in the future, with retro-compatibility enabled. For example, we could detect when the command name is `sudo` and then use the sudo CLI design, otherwise fall back to the new design.

## When something goes wrong

`You are not allowed to execute this command, this incident will be reported.` --> No task of your roles matches this command, with these options.

`Permission denied` --> Two equivalent tasks match: the policy must be fixed. The log has the details.

`dosr: the task needs capabilities that this session cannot obtain anymore: …` --> The task needs capabilities that are out of the bounding set of your session, for example in a container.

`This incident is reported.` --> The authentication failed.

`You need at least dac_read_search or dac_override, setpcap and setuid capabilities to run dosr` --> `dosr` itself lacks its file capabilities: check the installation.

In every case, the log says more than the terminal, on purpose.
