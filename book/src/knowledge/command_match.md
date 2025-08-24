# RootAsRole Command matching

A command in a RootAsRole policy is splitted in two parts : the command path and the command arguments. 

The command path is the absolute path of the executable to run. It can be exact (like `/usr/bin/ls`), or wildcarded (like `/usr/bin/*` or even `**` for every files, obviously dangerous).
The command arguments can be either :
* a regular expression that must start with `^` and end with `$` to match the whole arguments string (like `^-l( -a)?$` to match `-l` or `-l -a` but not `-a -l`),
* a simple space-separated list of arguments, that is matching exactly

Note that we differentiate between a command with `^.*$` and one with `^reg.*ex$` : the first one is a full regex command, while the second one is a regex command with fixed arguments. The first one is less precise than the second one. This enter to the conflict resolution algorithm explained in the next section.

## Role Conflict resolution

As you may know with this RBAC model, it is possible for multiple roles to reference the same command for the same users. Since we do not ask by default the role to use, our tool applies an smart policy to choose a role using user, group, command entry and least privilege criteria. We apply a partial order comparison algorithm @@abedinDetectionResolutionAnomalies2006 to decide which role should be chosen :

* Find all the roles that match the user id assignment or the group id, and the command input
* Within the matching roles, select the one that is the most precise and least privileged :
   1. exact command is more precise than command with regex argument
   1. command with regex argument is more precise than a wildcarded command path
   1. wildcarded command path is more precise than wildcarded command path and regex args
   1. wildcarded command path and regex args is more precise than complete wildcard
   1. A task granting no capability is less privileged than one granting at least one capability
   1. A task granting no insecure capability is less privileged than one at least one insecure capability
   1. A task granting insecure capability is less privileged than one granting all capabilities.
   1. A task without setuid is less privileged than one has setuid.
   1. if no root is disabled, a task without 'root' setuid is less privileged than a task with 'root' setuid
   1. A task without setgid is less privileged than one has setgid.
   1. A task with a single setgid is less privileged than one that set multiple gid.
   1. if no root is disabled, A task with multiple setgid is less privileged than one that set root gid
   1. if no root is disabled, A task with root setgid is less privileged than one that set multiple gid, particularly using root group
   1. A task that requires authentication is less privileged than one that doesn't
   1. A task that keeps safe PATH values is less privileged than one that doesn't
   1. A task that keeps unsafe PATH values is less privileged than one that keep it safe
   1. A task that keeps environment variables is less privileged than one that doesn't
   1. A task that enables root privileges is less privileged than one which disables root privileges (see "no-root" feature)
   1. A task that disables the Bounding set feature in RootAsRole is less privileged than one that enables it
   1. user assignment is more precise than the combination of group assignment
   1. the combination of group assignment is more precise than single group assignment

After these step, if two roles are conflicting, these roles are considered equal. In this case if execution settings are totally equal, no matter which role is chosen, it execute the asked command. If execution settings are different, there is a conflict, so configurator is being warned that roles could be in conflict and these could not be reached without specifing precisely the role to choose (with `--role` or/and `--task` option). In such cases, we highly recommend to review the design of the configured access control.