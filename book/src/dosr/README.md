# `dosr`

`dosr` executes commands through RootAsRole policy checks.

## Usage

<pre>
Execute privileged commands with a role-based access control system

<u><b>Usage</b></u>: <b>dosr</b> [OPTIONS] [COMMAND]...

<u><b>Arguments</b></u>:
  [COMMAND]...  Command to execute

<u><b>Options</b></u>:
  <b>-r, --role</b> &lt;ROLE&gt;  Role to select
  <b>-t, --task</b> &lt;TASK&gt;  Task to select (--role required)
  <b>-u, --user</b> &lt;USER&gt;  User to execute the command as
  <b>-g, --group</b> &lt;GROUP<,GROUP...>&gt; Group(s) to execute the command as
  <b>-E, --preserve-env</b>          Keep environment variables from the current process
  <b>-D, --chdir</b> &lt;DIR&gt;  Change working directory before executing the command
  <b>-p, --prompt</b> &lt;PROMPT&gt; Prompt to display
  <b>-K</b>                 Remove timestamp file
  <b>-i, --info</b>         Print the execution context of a command if allowed by a matching task
  <b>-h, --help</b>         Print help (see more with '--help')
  <b>-V, --version</b>      Print version
</pre>

If you're accustomed to utilizing the sudo tool and find it difficult to break that habit, consider creating an alias : 
```sh
alias sudo="dosr"
alias sr="dosr"
```

## Examples

```bash
dosr reboot
dosr -r ops -t reboot reboot
```