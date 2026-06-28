# File Format Conversion

`chsr convert` converts RootAsRole policy storage between JSON and CBOR.

## Supported formats

- `json`
- `cbor`

## Command forms

```text
chsr convert [--from <from_type> <from_file>] <to_type> <to_file>
chsr convert -r [--from <from_type> <from_file>] <to_type> <to_file>
```

- `--from`: explicitly select source format and source file.
- `-r` / `--reconfigure`: update `/etc/security/rootasrole.json` so storage points to the new file.

## Common examples

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

For policy field details, see [Configuration File Format](file-config.md).