# Configuration File Format

This page documents the RootAsRole policy file, usually `/etc/security/rootasrole.json`.

Use `chsr` for routine edits. Keep manual JSON editing for advanced workflows and reviewed changes.

## 1) Top-level structure

```json
{
  "version": "4.0.0",
  "storage": {
    "method": "json",
    "settings": {
      "path": "/etc/security/rootasrole.json",
      "immutable": true
    }
  },
  "options": {},
  "roles": []
}
```

- `version`: policy schema version written by tooling.
- `storage`: where policy data is stored (`json` or `cbor`, with reconfiguration).
- `options`: global execution options (inherited by roles/tasks unless overridden).
- `roles`: list of role definitions.

## 2) Minimal working role example

```json
{
  "version": "4.0.0",
  "roles": [
    {
      "name": "ops",
      "actors": [
        { "type": "group", "name": "ops" }
      ],
      "tasks": [
        {
          "name": "reboot",
          "purpose": "Allow reboot",
          "cred": {
            "capabilities": ["CAP_SYS_BOOT"]
          },
          "commands": ["/usr/sbin/reboot"]
        }
      ]
    }
  ]
}
```

## 3) Role and task model

- A `role` contains:
  - `name`
  - `actors` (users/groups allowed to use it)
  - `tasks`
  - optional `options`
- A `task` contains:
  - `name`
  - optional `purpose`
  - `cred` (execution credentials)
  - `commands` (allowed command patterns)
  - optional `options`

## 4) Command model

`commands` supports 3 compact forms:

1. String policy:

```json
"commands": "all"
```

2. Explicit allow-list:

```json
"commands": ["/usr/bin/systemctl restart sshd"]
```

3. Full object:

```json
"commands": {
  "default": "none",
  "add": ["/usr/bin/systemctl restart sshd"],
  "del": ["/usr/bin/systemctl reboot"]
}
```

Supported `default` values are `all` and `none`.

## 5) Credential model (`cred`)

Main fields:

- `setuid`
- `setgid`
- `capabilities`

### `capabilities` accepted forms

```json
"capabilities": "all"
```

```json
"capabilities": ["CAP_NET_BIND_SERVICE", "CAP_SYS_BOOT"]
```

```json
"capabilities": {
  "default": "none",
  "add": ["CAP_SYS_BOOT"],
  "del": ["CAP_SYS_ADMIN"]
}
```

### `setuid` selector form

```json
"setuid": {
  "default": "none",
  "fallback": "root",
  "add": ["root"],
  "del": ["nobody"]
}
```

### `setgid` selector form

```json
"setgid": {
  "default": "none",
  "fallback": ["root"],
  "add": [["wheel"]],
  "del": [["nogroup"]]
}
```

`setuid`/`setgid` can also be written in compact mandatory form (single user/group or group list).

## 6) Options and inheritance

`options` can be declared at:

1. global level
2. role level
3. task level

Resolution is hierarchical: task overrides role, role overrides global. `inherit` means “use parent level”.

Important option families:

- `path`: execution PATH filtering/override policy
- `env`: environment policy (`keep`/`delete`/`check`/`set` with inheritance)
- `root`: `user` or `privileged`
- `bounding`: `strict` or `ignore`
- `authentication`: `perform` or `skip`
- `execinfo`: `show` or `hide`
- `timeout`: `{ type, duration, max_usage }`
- `umask`: octal string (example: `"022"`)

## 7) Plugins and extra fields

RootAsRole supports extension fields (for example role hierarchy or separation-of-duty metadata) and command plugin objects (for example hash-check metadata).

These fields are preserved by the policy model and consumed by relevant tooling/plugins.

## 8) `dbus` and `file` credential fields

`dbus` and `file` entries are primarily used by `gensr`-driven workflows to materialize DBus/Polkit and file-permission enforcement artifacts.

They represent discovered execution requirements and are useful in IaC/security automation pipelines.

## 9) Recommended workflow

1. Initialize/modify policy with `chsr`.
2. For multi-field edits, prefer `chsr editor` so invalid policies are rejected before write.
3. Validate expected execution with `dosr -i ...`.
4. Convert storage format with `chsr convert` only when required.
5. Keep policy in version control and review changes like code.

See also:

- [chsr command overview](README.md)
- [File Format Conversion](convert.md)