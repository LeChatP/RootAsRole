# Static/Dynamic Separation of Duties notion

## Static Separation of Duties

Static Separation of Duties (SSD) within an RBAC ensures that no single user can hold conflicting administrative roles, enhancing security and operational integrity@@ferraioloProposedNISTStandard2001. For instance, SSD policies would prevent a user assigned as a "System Administrator" from also being a "Network Administrator" or "Backup Administrator," thereby mitigating the risk of entire control of a system and potential fraud.

With RootAsRole, you can implement SSD by creating roles that are mutually exclusive by adding `ssd` array in a role definition. For example, you can create a role for a "System Administrator" and another for a "Network Administrator." You can then assign these roles to different users, ensuring that no single user has both roles at the same time. If a user obtains a new role that conflicts with an existing role, RootAsRole will prevent the user to use any conflicting role.

## Dynamic Separation of Duties

Dynamic Separation of Duties (DSD) in RBAC ensures that no single user can perform conflicting roles within a system simultaneously, managed at runtime. It verifies users' or system sessions context before allowing them to activate roles, ensuring that they do not have conflicting permissions given the dynamic context of the system.

For example, In a very small business, it may have only one system administrator. In this case the small business can enforce a DSD feature that prevent the unique administrator to simultaneously activate roles that allow both system configuration and audit log management, and cannot perform system configuration if no audit is enforced, ensuring that the administrator cannot cover his tracks.

For now, RootAsRole does not support DSD.