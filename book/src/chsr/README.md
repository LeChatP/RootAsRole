# Chsr tool documentation

Chsr is a command-line tool to configure roles, permissions and execution options.

## How does configuration work?

The configuration is stored in a JSON file. The default path is `/etc/security/rootasrole.json`. It is possible to change the path where the configuration is stored by changing the `path` setting in the configuration file manually.
Note: The configuration file must be immutable after edition.
```json
"storage": {
  "method": "json",
  "settings": {
    "path": "/etc/security/rootasrole.json",
    "immutable": true
  }
}
```

Next, the configuration is divided into roles, tasks, commands, credentials, and options. Each role can have multiple tasks, each task can have multiple commands and credentials. The options are global and can be set for the whole configuration or for a specific role or task.

## How options work with examples

### Path options example 1

Here is an example global configuration:

```json
{
  "options": {
    "path": {
      "default": "delete-all",
      "add": [
        "/usr/bin"
      ]
    }
  }
}
```

This configuration will delete all paths and add `/usr/bin` to the whitelist.

```json
{
  "options": {
    "path": {
      "default": "delete-all",
      "add": [
        "/usr/bin"
      ]
    }
  },
  "roles": {
    "admin": {
      "options": {
        "path": {
          "default": "inherit",
          "add": [
            "/usr/sbin"
          ]
        }
      }
    }
  }
}
```

This configuration will delete all paths and add `/usr/bin` to the whitelist for all roles. The `admin` role will inherit the global configuration and add `/usr/sbin` to the whitelist. So the final configuration for the `admin` role will be `/usr/bin:/usr/sbin`.

### Path options example 2

Here is an example global configuration:

```json
{
  "options": {
    "path": {
      "default": "keep-safe",
      "add": [
        "/usr/bin"
      ]
    }
  }
}
```

This configuration will keep all paths that are absolute and add `/usr/bin` to the path.

```json
{
  "options": {
    "path": {
      "default": "keep-safe",
      "add": [
        "/usr/bin"
      ]
    }
  },
  "roles": {
    "admin": {
      "options": {
        "path": {
          "default": "inherit",
          "add": [
            "/usr/sbin"
          ]
        }
      }
    }
  }
}
```

This configuration will keep all paths that are absolute and add `/usr/bin` to the whitelist for all roles. The `admin` role will inherit the global configuration and add `/usr/sbin` to the whitelist. So the final configuration for the `admin` role will be `/usr/bin:/usr/sbin:$PATH`, where `$PATH` is the current executor path value.

### Path options example 3

Here is an example global configuration:

```json
{
  "options": {
    "path": {
      "default": "keep-unsafe",
      "sub": [
        "/usr/bin"
      ]
    }
  }
}
```

This configuration will keep all paths, even them that are relative, and remove `/usr/bin` from the path.

```json
{
  "options": {
    "path": {
      "default": "keep-unsafe",
      "add": [
        "/usr/bin"
      ]
    }
  },
  "roles": {
    "admin": {
      "options": {
        "path": {
          "default": "inherit",
          "add": [
            "/usr/sbin"
          ]
        }
      }
    }
  }
}
```

This configuration will keep all paths, even them that are relative, and add `/usr/bin` to the whitelist for all roles. The `admin` role will inherit the global configuration and add `/usr/sbin` to the whitelist. So the final configuration for the `admin` role will be `/usr/bin:/usr/sbin:$PATH`, where `$PATH` is the current executor path value.

Note: path are always prepended to the current path value.

### Path options example 4

Here is an example global configuration:

```json
{
  "options": {
    "path": {
      "default": "inherit",
      "add": [
        "/usr/bin"
      ]
    }
  }
}
```

If the policy is inherit in global configuration, the policy will be `delete-all`.

```json
{
  "options": {
    "path": {
      "default": "delete-all",
      "add": [
        "/usr/bin"
      ]
    }
  },
  "roles": {
    "admin": {
      "options": {
        "path": {
          "default": "keep-safe",
          "sub": [
            "/usr/sbin"
          ]
        }
      },
      "tasks": {
        "task1": {
          "options": {
            "path": {
              "default": "inherit",
              "add": [
                "/usr/sbin"
              ]
            }
          }
        }
      }
    }
  }
}
```

This complex configuration will delete-all paths in the global configuration for all roles except for `admin` role. The `admin` role will keep all paths that are absolute and remove `/usr/sbin` from the path. The `task1` task will inherit the `admin` role configuration and tries to add `/usr/sbin` to the path but it will be ignored because the task inherits the `admin` role configuration, and it removes `/usr/sbin` from the path. So the final path is the current executor path value less `/usr/sbin`.

In conclusion, two logical properties can be deducted : 
1. The path removed from the path variable cannot be added, even by inheritance.
2. When a more precise configuration defines a policy (delete-all,keep-safe,keep-unsafe), it will override less precise configuration.
   * Global is less precise than Role, Role is less precise than Task

### Environment options example 1

Here is an example global configuration:

```json
{
  "options": {
    "env": {
      "default": "delete",
      "keep": [
        "VAR1"
      ]
    }
  }
}
```

Environment variables are managed in the same way as paths. The policy can be `delete`, `keep`, or `inherit`. The `delete` policy will remove all environment variables except the ones in the `keep` list. The `keep` list is a list of environment variables that will be kept in the environment.

```json
{
  "options": {
    "env": {
      "default": "delete",
      "keep": [
        "VAR1"
      ]
    }
  },
  "roles": {
    "admin": {
      "options": {
        "env": {
          "default": "inherit",
          "keep": [
            "VAR2"
          ]
        }
      }
    }
  }
}
```

This configuration will delete all environment variables except `VAR1` for all roles. The `admin` role will inherit the global configuration and keep `VAR2` in the environment. So only `VAR1` and `VAR2` values will be kept in the environment for the `admin` role.

### Environment options example 2

Here is an example global configuration:

```json
{
  "options": {
    "env": {
      "default": "keep",
      "delete": [
        "VAR1"
      ]
    }
  }
}
```

The `delete` list is a list of environment variables that will be removed from the environment.

```json
{
  "options": {
    "env": {
      "policy": "keep",
      "delete": [
        "VAR1"
      ]
    }
  },
  "roles": {
    "admin": {
      "options": {
        "env": {
          "policy": "inherit",
          "delete": [
            "VAR2"
          ]
        }
      }
    }
  }
}
```

This configuration will keep all environment variables except `VAR1` for all roles. The `admin` role will inherit the global configuration and remove `VAR2` from the environment. So only `VAR1` and `VAR2` values are removed from the environment for the `admin` role.

### Environment options example 3

Here is an example global configuration:

```json
{
  "options": {
    "env": {
      "default": "keep",
      "check": [
        "VAR1"
      ]
    }
  }
}
```

The `check` list is a list of environment variables that will be checked for unsafe characters. If an environment variable contains unsafe characters, it will be removed from the environment.

## Usage

<pre>
<b><u>Usage:</u> chsr</b> [command] [options]

<u><b>Commands:</b></u>
  <b>-h, --help</b>                    Show help for commands and options.
  <b>list, show, l</b>                 List available items; use with specific commands for detailed views.
  <b>role, r</b>                       Manage roles and related operations.


<u><b>Role Operations:</b></u>
chsr role [role_name] [operation] [options]
  <b>add, create</b>                   Add a new role.
  <b>del, delete, unset, d, rm</b>     Delete a specified role.
  <b>show, list, l</b>                 Show details of a specified role (actors, tasks, all).
  <b>purge</b>                         Remove all items from a role (actors, tasks, all).
  
  <b>grant</b>                         Grant permissions to a user or group.
  <b>revoke</b>                        Revoke permissions from a user or group.
    <b>-u, --user</b> [user_name]      Specify a user for grant or revoke operations.
    <b>-g, --group</b> [group_names]   Specify one or more groups combinaison for grant or revoke operations.


<u><b>Task Operations:</b></u>
chsr role [role_name] task [task_name] [operation]
  <b>show, list, l</b>                 Show task details (all, cmd, cred).
  <b>purge</b>                         Purge configurations or credentials of a task (all, cmd, cred).
  <b>add, create</b>                   Add a new task.
  <b>del, delete, unset, d, rm</b>     Remove a task.


<u><b>Command Operations:</b></u>
chsr role [role_name] task [task_name] command [cmd]
  <b>show</b>                          Show commands.
  <b>setpolicy</b> [policy]            Set policy for commands (allow-all, deny-all).
  <b>whitelist, wl</b> [listing]       Manage the whitelist for commands.
  <b>blacklist, bl</b> [listing]       Manage the blacklist for commands.


<u><b>Credentials Operations:</b></u>
chsr role [role_name] task [task_name] credentials [operation]
  <b>show</b>                          Show credentials.
  <b>set, unset</b>                    Set or unset credentials details.
  <b>caps</b>                          Manage capabilities for credentials.


<u><b>Capabilities Operations:</b></u>
chsr role [role_name] task [task_name] credentials caps [operation]
  <b>setpolicy</b> [policy]            Set policy for capabilities (allow-all, deny-all).
  <b>whitelist, wl</b> [listing]       Manage whitelist for credentials.
  <b>blacklist, bl</b> [listing]       Manage blacklist for credentials.


<u><b>Options:</b></u>
chsr options [option] [operation]
chsr role [role_name] options [option] [operation]
chsr role [role_name] task [task_name] options [option] [operation]
  <b>path</b>                          Manage path settings (set, whitelist, blacklist).
  <b>env</b>                           Manage environment variable settings (set, whitelist, blacklist, checklist).
  <b>root</b> [policy]                 Defines when the root user (uid == 0) gets his privileges by default. (privileged, user, inherit)
  <b>bounding</b> [policy]             Defines when dropped capabilities are permanently removed in the instantiated process. (strict, ignore, inherit)
  <b>wildcard-denied</b>               Manage chars that are denied in binary path.
  <b>timeout</b>                       Manage timeout settings (set, unset).


<u><b>Path options:</b></u>
chsr options path [operation]
  <b>setpolicy</b> [policy]            Specify the policy for path settings (delete-all, keep-safe, keep-unsafe, inherit).
  <b>set</b> [path]                    Set the policy as delete-all and the path to enforce.
  <b>whitelist, wl</b> [listing]       Manage the whitelist for path settings.
  <b>blacklist, bl</b> [listing]       Manage the blacklist for path settings.


<u><b>Environment options:</b></u>
chsr options env [operation]
  <b>setpolicy</b> [policy]            Specify the policy for environment settings (delete-all, keep-all, inherit).
  <b>set</b> [key=value,...]           Set the policy as delete-all and the key-value map to enforce.
  <b>whitelist, wl</b> [listing]       Manage the whitelist for environment settings.
  <b>blacklist, bl</b> [listing]       Manage the blacklist for environment settings.
  <b>checklist, cl</b> [listing]       Manage the checklist for environment settings. (Removed if contains unsafe chars)


<u><b>Timeout options:</b></u>
chsr options timeout [operation]
  <b>set, unset</b>                    Set or unset timeout settings.
    <b>--type</b> [tty, ppid, uid]     Specify the type of timeout.
    <b>--duration</b> [HH:MM:SS]       Specify the duration of the timeout.
    <b>--max-usage</b> [number]        Specify the maximum usage of the timeout.

<u><b>Listing:</b></u>
    add [items,...]                        Add items to the list.
    del [items,...]                        Remove items from the list.
    set [items,...]                        Set items in the list.
    purge                                  Remove all items from the list.
</pre>