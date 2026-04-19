# Policy Model and Inheritance

RootAsRole policy is built on three levels:

1. Global options
2. Role options
3. Task options

A user executes a command through a matching task.

## Core objects

- **Role**: assignment boundary for users and groups.
- **Task**: command pattern + execution rights.
- **Credentials**: `setuid`, `setgid`, and Linux capabilities.
- **Options**: environment, PATH, authentication, timeout, and related controls.

## Matching behavior

`dosr` evaluates candidate tasks and selects the best match.

Selection is based on:

- Command/path and arguments match quality
- Actor match (user/group)
- Optional filters (`-r`, `-t`, `-u`, `-g`, `-E`)
- Least-privilege preference when candidates are equivalent

If two candidates remain ambiguous, execution is denied until policy is clarified. In operations, this is preferable to silently picking a risky path.

## Inheritance behavior

Options are resolved from global to role to task.

- If a level is `inherit`, parent level is used.
- If a level is explicit, it overrides parent level.

This lets you keep broad defaults while tightening sensitive tasks.

## Recommended modeling style

- Keep one operational intent per task.
- Keep capability allow-lists short.
- Avoid broad command wildcards in production.
- Use role boundaries to separate teams and duties.
- Use plugins (role hierarchy, separation of duties) only when needed.
