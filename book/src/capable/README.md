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