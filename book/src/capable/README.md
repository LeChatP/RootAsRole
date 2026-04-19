# `capable`

`capable` is a helper utility used during policy design and testing.

It observes capability requests made by a command and helps build a minimal capability allow-list.

## Usage

```text
capable [OPTIONS] [COMMAND]...
```

## Options

- `-s, --sleep <SLEEP>`: wait before stopping traced process
- `-d, --daemon`: collect system events and print at end
- `-j, --json`: output JSON
- `-h, --help`: help

## Example

```bash
capable -j cat /etc/shadow
```

## Operational guidance

- Treat output as candidate capabilities, not final policy.
- Remove capabilities that are not strictly required.
- Validate with real-world command execution after each reduction.
- Do not rely on `capable` output alone for production hardening.