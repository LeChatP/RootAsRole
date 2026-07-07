# Linux capabilities and RootAsRole

Linux capabilities split superuser privileges into explicit units. This is the technical basis that allows RootAsRole to enforce least privilege during command execution @@wazanRootAsRoleSecurityModule2022 @@billoirImplementingPrincipleLeast2023.

## Why this is central to the project

RootAsRole does not only decide *who* can run a command; it also controls *which privileges* are granted at execution time (`cred.capabilities`, `setuid`, `setgid`).

In practice, this enables:

- privilege minimization per task
- reduction of full-root execution paths
- auditable privilege intent in policy

## Operational guidance

1. Start from minimal capability sets.
2. Prefer command-scoped tasks over broad command wildcards.
3. Review tasks that grant `all` capabilities as high risk.
4. Periodically validate real needs with `capable` and execution tests.

This is the core operational idea behind RootAsRole: keep privileges narrow and visible in policy @@billoirImplementingPrincipleLeast2024.

For kernel-level capability semantics, see [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html).