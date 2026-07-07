# RBAC for RootAsRole

RootAsRole uses a role-centric model because admin delegation is first an assignment problem: who can run which privileged action, under which credentials @@sandhuRoleBasedAccessControl1996 @@ferraioloProposedNISTStandard2001.

## Why RBAC is the right baseline here

In practice, RootAsRole policies are built around stable responsibilities (operators, backup admins, deployment roles). This is where RBAC is strong:

- explicit user/group to role assignment
- permission grouping by operational task
- easier review and audit than per-user privilege rules

This design choice is consistent with the RootAsRole research and implementation trajectory @@wazanRootAsRoleSecureAlternative2021 @@wazanRootAsRoleSecurityModule2022 @@billoirImplementingPrincipleLeast2023.

## Mapping RBAC concepts to RootAsRole objects

- `role`: administrative responsibility unit
- `actors`: users/groups allowed to activate the role
- `task`: execution context within the role
- `commands`: authorized command patterns
- `cred`: Linux privilege materialization (`setuid`, `setgid`, capabilities)
- `options`: execution constraints (environment, path handling, auth, timeout, bounding set policy)

This mapping keeps policy readable while preserving least-privilege execution control @@billoirImplementingPrincipleLeast2024.

## Practical SOTA direction for the project

For this project, the next step is to improve how RBAC policies are maintained:

1. reduce policy ambiguity (role/task overlap)
2. enforce stricter separation constraints (SSD/DSD-ready design)
3. improve role hierarchy usage to avoid policy duplication
4. keep capability assignment minimal and reviewable

This keeps policy governance aligned with RBAC foundations and Linux privilege engineering constraints @@sandhuRoleBasedAccessControl1996 @@ferraioloProposedNISTStandard2001 @@billoirImplementingPrincipleLeast2024.