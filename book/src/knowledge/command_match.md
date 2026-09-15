# Command matching

A command entry in RootAsRole has two parts: command path and command arguments.

The command path is the executable path. It can be exact (for example `/usr/bin/ls`) or wildcarded (for example `/usr/bin/*`). A complete wildcard (`**`) is possible but usually too permissive.

Arguments can be:

* a regular expression that starts with `^` and ends with `$` so the full argument string is matched (for example `^-l( -a)?$` matches `-l` or `-l -a`, but not `-a -l`),
* an exact space-separated argument list.

RaR distinguishes `^.*$` from a constrained regex such as `^reg.*ex$`: the first means "any arguments", the second is more specific. That specificity matters during conflict resolution.

## Role Conflict resolution

With RBAC, multiple roles can match the same command for the same actor. Because role selection is implicit by default, RaR applies a deterministic least-privilege policy and a partial-order comparison @@abedinDetectionResolutionAnomalies2006 to select a candidate.

If multiple tasks match a command, RaR automatically:
1. chooses the most specific match,
1. if still ambiguous, selects the least-privileged one,
1. and only requires the user for clarification (using options in cli) if ambiguity remains.

When ambiguity remains, it is usually a policy design smell and worth refactoring.