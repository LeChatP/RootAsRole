# Role hierarchy in RootAsRole

Role hierarchy is a standard RBAC mechanism used to reduce policy duplication while preserving semantic clarity @@sandhuRoleBasedAccessControl1996 @@ferraioloProposedNISTStandard2001.

In RootAsRole, hierarchy is useful when several roles share a common base (for example diagnostic commands), while child roles add stricter or domain-specific tasks.

## Why this matters for RootAsRole

- reduces repeated command and credential blocks
- limits policy drift between similar roles
- improves auditability of inherited permissions

## Practical guidance

Use hierarchy for shared, low-risk baselines. Keep high-risk actions in dedicated child roles with explicit capabilities and constraints.

In policy files, hierarchy is expressed through the `parent` array in role definitions.