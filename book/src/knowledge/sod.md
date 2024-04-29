# Static/Dynamic Separation of Duties notion

## Static Separation of Duties

Static separation of duties (SSD) in RBAC is a security feature that restricts users from having conflicting roles. This means that a user cannot have two roles that are in conflict. In RootAsRole, if a user is still assigned to two roles that are in conflict, the user will not be able to execute any command of these roles.

For example, let's say we have two roles: `admin` and `user`. The `admin` role has the ability to create new users, while the `user` role does not. If a user is assigned to both the `admin` and `user` roles, the user will not be able to execute any command of these roles.

## Dynamic Separation of Duties

Dynamic separation of duties (DSD) in RBAC is a security feature that restricts users from having conflicting roles at the same time. This means that a user cannot have two roles that are in conflict at the same time. For now, RootAsRole does not support this feature.