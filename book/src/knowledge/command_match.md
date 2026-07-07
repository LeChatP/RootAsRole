# RootAsRole Command matching

A command entry in RootAsRole has two parts: command path and command arguments.

The command path is the executable path. It can be exact (for example `/usr/bin/ls`) or wildcarded (for example `/usr/bin/*`). A complete wildcard (`**`) is possible but usually too permissive for production.

Arguments can be:

* a regular expression that starts with `^` and ends with `$` so the full argument string is matched (for example `^-l( -a)?$` matches `-l` or `-l -a`, but not `-a -l`),
* an exact space-separated argument list.

RootAsRole distinguishes `^.*$` from a constrained regex such as `^reg.*ex$`: the first means “any arguments”, the second is more specific. That specificity matters during conflict resolution.

## Role Conflict resolution

With RBAC, multiple roles can match the same command for the same actor. Because role selection is not always explicit, RootAsRole applies a deterministic least-privilege policy and a partial-order comparison @@abedinDetectionResolutionAnomalies2006 to select a candidate:

* Find all roles matching user/group assignment and command input.
* Within matching roles, select the most precise and least privileged candidate:
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

After these steps, if two candidates are still equal:

- if execution settings are identical, execution can proceed,
- if execution settings differ, RootAsRole reports a conflict and requires explicit selection (`--role` and/or `--task`).

When that happens, it is usually a policy design smell and worth refactoring.