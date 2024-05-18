# RootAsRole Command matching

## Role Conflict resolution

As you may know with this RBAC model, it is possible for multiple roles to reference the same command for the same users. Since we do not ask by default the role to use, our tool applies an smart policy to choose a role using user, group, command entry and least privilege criteria. We apply a partial order comparison algorithm to decide which role should be chosen :

* Find all the roles that match the user id assignment or the group id, and the command input
* Within the matching roles, select the one that is the most precise and least privileged :
   1. exact command is more precise than command with regex argument
   1. command with regex argument is more precise than a wildcarded command path
   1. wildcarded command path is more precise than wildcarded command path and regex args
   1. wildcarded command path and regex args is more precise than complete wildcard
   1. A role granting no capability is less privileged than one granting at least one capability
   1. A role granting no insecure capability is less privileged than one at least one insecure capability
   1. A role granting insecure capability is less privileged than one granting all capabilities.
   1. A role without setuid is less privileged than one has setuid.
   1. if no root is disabled, a role without 'root' setuid is less privileged than a role with 'root' setuid
   1. A role without setgid is less privileged than one has setgid.
   1. A role with a single setgid is less privileged than one that set multiple gid.
   1. if no root is disabled, A role with multiple setgid is less privileged than one that set root gid
   1. if no root is disabled, A role with root setgid is less privileged than one that set multiple gid, particularly using root group
   1. A role that enables root privileges is less privileged than one which disables root privileges (see "no-root" feature)
   1. A role that disables the Bounding set feature in RootAsRole is less privileged than one that enables it
   1. user assignment is more precise than the combination of group assignment
   1. the combination of group assignment is more precise than single group assignment

After these step, if two roles are conflicting, these roles are considered equal (only the environment variables are different), so configurator is being warned that roles could be in conflict and these could not be reached without specifing precisely the role to choose (with `--role` option). In such cases, we highly recommend to review the design of the configured access control.