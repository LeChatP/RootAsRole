# What is sr tool

`sr` is the abbrevation of "switch role" is a command line tool like sudo. It allows a permitted user to execute a command as another user and groups. More than sudo it allows to a permitted user to obtain some privileges. The sr command is used to switch to a role.

# Usage

<pre>
<u><b>Usage</b></u>: <b>sr</b> [OPTIONS] [COMMAND]...

<u><b>Arguments</b></u>:
  [COMMAND]...  Command to execute

<u><b>Options</b></u>:
  <b>-r, --role</b> &lt;ROLE&gt;  Role to select
  <b>-t, --task</b> &lt;TASK&gt;  Task to select (--role required)
  <b>-p, --prompt</b> &lt;PROMPT&gt; Prompt to display
  <b>-i, --info</b>         Display rights of executor
  <b>-h, --help</b>         Print help (see more with '--help')
  <b>-V, --version</b>      Print version
</pre>