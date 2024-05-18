# Capable tool usage

<pre style="white-space: pre-wrap;">
<b><u>Usage:</u></b> capable [OPTIONS] [COMMAND]...

<b><u>Arguments:</u></b>
  [COMMAND]...  Specify a command to execute with arguments

<b><u>Options:</u></b>
  <b>-s, --sleep</b> <SLEEP>  Specify a delay before killing the process
  <b>-d, --daemon</b>         collecting data on system and print result at the end
  <b>-j, --json</b>           Print output in JSON format, ignore stdin/out/err
  <b>-h, --help</b>           Print help (see more with '--help')
</pre>

## Examples

```bash
$ capable -j cat /etc/shadow
["CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH"]
```

#### How to Find Out the Privileges Needed for Your Command

To determine the privileges required for your command, you can use the capable program. This tool listens for capability requests and displays them to you. Here’s how to use it effectively:

1. **Run the capable program**: It will monitor and display all capability requests made by your command.

1. **Analyze the output**: Pay close attention to the capabilities requested. It's common to see capabilities like CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH because many programs attempt to access files the user doesn't have permission to read. However, these capabilities are often not essential.

1. **Filter unnecessary capabilities**: Determine if the requested capabilities are truly needed. If they are not, consider switching to an appropriate user with the necessary access rights.

1. **Handle missing privileges**: If your program fails to execute due to missing privileges, try granting the specific missing privileges one at a time. Test the program after each change until it works as expected.

By following these steps, you can identify and manage the necessary privileges for your command more effectively.