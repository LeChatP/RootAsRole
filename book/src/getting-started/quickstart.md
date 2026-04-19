# First Policy in 10 Minutes

This walkthrough builds a minimal real policy: users in group `ops` can reboot the host through `dosr`.

## 1) Create a role

```bash
chsr role ops add
chsr role ops grant -g ops
```

## 2) Create a task

```bash
chsr role ops task reboot add
```

## 3) Allow one command

```bash
chsr role ops task reboot cmd whitelist add reboot
```

## 4) Grant minimal capability

```bash
chsr role ops task reboot cred caps whitelist add CAP_SYS_BOOT
```

## 5) Test execution

```bash
dosr reboot
```

If multiple tasks can match, select explicitly:

```bash
dosr -r ops -t reboot reboot
```

## Some tips

- Keep tasks narrow: one operational action per task.
- Use explicit `-r` and `-t` in automation for deterministic behavior.
- Verify that the command cannot be executed as a non-privileged user.
- Avoid full `root` delegation when capabilities are sufficient.
- Avoid granting capabilities you cannot justify.
- Prefer explicit command allow-lists over broad patterns.
- Regexes are powerful but can be error-prone. Test them carefully.
- Glob patterns are supported, but use them carefully to avoid unintended matches.
