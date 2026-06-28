# FAQ

Common issues seen during installation, policy authoring, and runtime testing.

## Why not `cargo install rootasrole`?

`cargo install` targets user-local binaries. RootAsRole requires system-level deployment (PAM files, capabilities, policy file location/permissions). For that reason, use distro packages or the project installer flow.

## `capable` does not work on my host

`capable` depends on eBPF and kernel features that are not always available or enabled.

Check:

- kernel support for required eBPF features
- security profile restrictions in your environment
- memory/resource limits

If it still fails, open an issue with kernel version, distro, and reproducible steps.

## Why are `capable` results different from expected behavior?

Possible causes:

1. Access is granted by normal ACL/ownership, so no capability is needed.
2. Program exits before capability checks happen.
3. Program behavior changes based on UID/GID.

Treat output as a starting point for iterative testing, not final ground truth.

## Why does `chsr editor` refuse to save my changes?

`chsr editor` validates policy consistency before writing.

Typical causes are:

- invalid field type (for example string vs object)
- unsupported values in command/capability sets
- broken inheritance/option structure

Review the reported error, fix the corresponding field, and retry.
For schema examples, see [Configuration File Format](chsr/file-config.md).

## Why does `chsr convert` fail?

Common causes:

- source path is wrong or unreadable
- target path is not writable
- `--from` format does not match the actual source content

Retry with explicit `--from` and verify file permissions.
See [File Format Conversion](chsr/convert.md) for command forms.