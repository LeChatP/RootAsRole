# Separation of duties in RootAsRole

Separation of duties (SoD) is essential for administrative privilege governance in RBAC systems @@ferraioloProposedNISTStandard2001 @@kuhnMutualExclusionRoles1997.

## Static Separation of Duties (SSD)

SSD prevents users from holding conflicting roles at assignment time.

In RootAsRole, SSD is supported through role-level exclusions (`ssd` array). Use it for high-impact role pairs (for example operations vs audit).

## Dynamic Separation of Duties (DSD)

DSD prevents conflicting role activation in the same session or runtime context @@kuhnMutualExclusionRoles1997.

RootAsRole currently focuses on SSD. If your workflow needs DSD-like guarantees, design role/task boundaries so sensitive combinations are structurally impossible, and keep execution review strict.