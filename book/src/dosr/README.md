# `dosr`

`dosr` executes commands through RootAsRole policy checks.

## Usage

```text
dosr [OPTIONS] [COMMAND]...
```

## Main options

- `-r, --role <ROLE>`: select role
- `-t, --task <TASK>`: select task (requires role)
- `-u, --user <USER>`: filter on target user
- `-g, --group <GROUP(,GROUP...)>`: filter on target group(s)
- `-E, --preserve-env`: request environment preservation
- `-p, --prompt <PROMPT>`: custom authentication prompt
- `-S, --stdin`: use stdin for password prompt
- `-K, --remove-timestamp`: remove timestamp cookie before authentication (when `timeout` feature is enabled)
- `-i, --info`: print effective execution context
- `-v, --version`: print version
- `-h, --help`: print help

`-K/--remove-timestamp` can also be used without command arguments to only clear the cookie state and exit.

## Examples

```bash
dosr reboot
dosr -i reboot
dosr -r ops -t reboot reboot
```