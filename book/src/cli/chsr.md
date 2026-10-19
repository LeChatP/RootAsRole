# `chsr`

<blockquote class="caroot-stare">
This section needs rewriting.
</blockquote>

`chsr` is the policy administration tool for RaR.

Use it to manage roles, tasks, command rules, credentials, and options.

## Usage

```text
chsr [COMMAND] [ARGS...]
```

## Main command families

- `role`: create/delete roles, grant/revoke actors
- `role ... task`: create/delete tasks
- `role ... task ... cmd`: manage command allow/deny rules
- `role ... task ... cred`: manage `setuid`, `setgid`, and capabilities
- `options`: manage global/role/task execution options
- `convert`: convert policy storage between JSON and CBOR
- `editor`: open interactive editor mode (when enabled)

## `chsr editor`

`chsr editor` opens an interactive policy editing mode.

When the edit session is applied, RaR validates the policy before saving.
Invalid content is rejected with explicit errors.

Use `chsr editor` for multi-field edits when you want immediate validation.

For policy field reference, see [Configuration File Format](../configuration.md).
For storage migration, see [File Format Conversion](#file-format-conversion).

## File Format Conversion

<blockquote class="caroot-stare">
This section needs rewriting.
</blockquote>

`chsr convert` converts RootAsRole policy storage between JSON and CBOR.

### Supported formats

- `json`
- `cbor`

### Command forms

```text
chsr convert [--from <from_type> <from_file>] <to_type> <to_file>
chsr convert -r [--from <from_type> <from_file>] <to_type> <to_file>
```

- `--from`: explicitly select source format and source file.
- `-r` / `--reconfigure`: update `/etc/security/rootasrole.json` so storage points to the new file.

### Common convert examples

Convert current policy storage to CBOR and reconfigure runtime:

```bash
chsr convert -r cbor /etc/security/rootasrole.bin
```

Convert back to JSON and reconfigure runtime:

```bash
chsr convert -r json /etc/security/rootasrole.json
```

Explicit source/target conversion:

```bash
chsr convert --from json /etc/security/rootasrole.json cbor /etc/security/rootasrole.bin
```

## Operational notes

- Keep target files in protected system paths.
- If policy content changes during migration prep, prefer `chsr editor` to catch invalid policies before write.
- Validate policy execution after conversion with `dosr -i <command>`.
- Use version control and backups before large migrations.

For policy field details, see [Configuration File Format](../configuration.md).

## Common general examples

```bash
chsr role ops add
chsr role ops grant -g ops
chsr role ops task reboot add
chsr role ops task reboot cmd whitelist add reboot
chsr role ops task reboot cred caps whitelist add CAP_SYS_BOOT
```

For complete policy fields, see [Configuration File Format](../configuration.md).

