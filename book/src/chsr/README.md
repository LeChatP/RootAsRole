# `chsr`

`chsr` is the policy administration tool for RootAsRole.

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

When the edit session is applied, RootAsRole validates the policy before saving.
Invalid content is rejected with explicit errors.

Use `chsr editor` for multi-field edits when you want immediate validation.

For policy field reference, see [Configuration File Format](file-config.md).
For storage migration, see [File Format Conversion](convert.md).

## Common examples

```bash
chsr role ops add
chsr role ops grant -g ops
chsr role ops task reboot add
chsr role ops task reboot cmd whitelist add reboot
chsr role ops task reboot cred caps whitelist add CAP_SYS_BOOT
```

For complete policy fields, see [Configuration File Format](file-config.md).