# How does configuration work?

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

## How configuration work with examples

### A complete Config example

The following example shows a RootAsRole config without plugins when almost every field is modified with comments.

```json
{
  "version": "3.0.0-alpha.4", // Version of the configuration file
  "storage": { // Storage settings, Roles storage location
    "method": "json", // Storage method
    "settings": { // Storage settings
      "immutable": false, // Program return error if the file is not immutable, default is true
      "path": "target/rootasrole.json" // Path to the storage file
    }
  },
  "options": {
    "path": { // Path options
      "default": "delete", // Default policy for path, delete, keep-safe, keep-unsafe, inherit
      "add": [ // Paths to add to the whitelist
        "path1",
        "path2"
      ],
      "sub": [ // Paths to remove from the whitelist
        "path3",
        "path4"
      ]
    },
    "env": { // Environment options
      "default": "delete", // Default policy for environment, delete, keep, inherit
      "keep": [ // Environment variables to keep
        "env1",
        "env2"
      ],
      "check": [ // Environment variables to check for unsafe characters
        "env3",
        "env4"
      ],
      "delete": [ // Environment variables to delete
        "env5",
        "env6"
      ]
    },
    "root": "privileged", // Default policy for root: privileged, user, inherit
    "bounding": "ignore", // Default policy for bounding: strict, ignore, inherit
    "wildcard-denied": "*", // Characters denied in any binary path
    "timeout": {
      "type": "ppid", // Type of timeout: tty, ppid, uid
      "duration": "15:30:30", // Duration of the timeout in HH:MM:SS format
      "max_usage": 1 // Maximum usage before timeout expires
    }
  },
  "roles": [ // Role list
    {
      "name": "complete", // Role name
      "actors": [ // Actors granted to the role
        {
          "id": 0, // ID of the actor, could be a name
          "type": "user" // Type of actor: user, group
        },
        {
          "groups": 0, // ID of the group or a list of ID for AND condition
          "type": "group" 
        },
        {
          "type": "group",
          "groups": [ // List of groups, this is an AND condition between groups
            "groupA",
            "groupB"
          ]
        }
      ],
      "tasks": [ // List of role's tasks
        {
          "name": "t_complete", // Task name, must be unique in the role
          "purpose": "complete", // Task purpose, just a description
          "cred": {
            "setuid": "user1", // User to setuid before executing the command
            "setgid": [ // Groups to setgid before executing the command, The first one is the primary group
              "group1",
              "group2"
            ],
            "capabilities": { // Capabilities to grants
              "default": "all", // Default policy for capabilities, all, none
              "add": [ // Capabilities to add
                "CAP_LINUX_IMMUTABLE",
                "CAP_NET_BIND_SERVICE"
              ],
              "sub": [ // Capabilities to remove, overrides add
                "CAP_SYS_ADMIN",
                "CAP_SYS_BOOT"
              ]
            },
            // Dbus credentials are relied to Dbus and Polkit policies. They can be enforced using `gensr` tool
            "dbus": [
              "org.freedesktop.login1.Reboot", // DBus method to allow
            ],
            // File credentials are relied to file permissions. They can be enforced using `gensr` tool
            "file": {
              "/path/to/file": "R", // File path and permission, r for read, w for write, x for execute
            }
          },
          "commands": {
            "default": "all", // Default policy for commands, allow-all, deny-all
            "add": [ // Commands to add to the whitelist
              "ls",
              "echo"
            ],
            "sub": [ // Commands to add to the blacklist
              "cat",
              "grep"
            ]
          },
          "options": { // Task-level options
            "path": {
              "default": "delete", // When default is not inherit, all upper level options are ignored
              "add": [
                "path1",
                "path2"
              ],
              "sub": [
                "path3",
                "path4"
              ]
            },
            "env": {
              "default": "delete",
              "keep": [
                "env1",
                "env2"
              ],
              "check": [
                "env3",
                "env4"
              ],
              "delete": [
                "env5",
                "env6"
              ]
            },
            "root": "privileged",
            "bounding": "ignore",
            "wildcard-denied": "*",
            "timeout": {
              "type": "ppid",
              "duration": "15:30:30",
              "max_usage": 1
            }
          }
        }
      ],
      "options": { // Role-level options
        "path": {
          "default": "delete",
          "add": [
            "path1",
            "path2"
          ],
          "sub": [
            "path3",
            "path4"
          ]
        },
        "env": {
          "default": "delete",
          "keep": [
            "env1",
            "env2"
          ],
          "check": [
            "env3",
            "env4"
          ],
          "delete": [
            "env5",
            "env6"
          ]
        },
        "root": "privileged",
        "bounding": "ignore",
        "wildcard-denied": "*",
        "timeout": {
          "type": "ppid",
          "duration": "15:30:30",
          "max_usage": 1
        }
      }
    }
  ]
}
```

### Config example Role hierarchy plugin

The following example shows a RootAsRole config using role hierarchy plugin.

```json
{
  "version": "3.0.0-alpha.4",
  "roles": [
    {
      "parents": ["user"],
      "name": "admin",
      "actors": [
        {
          "id": 0,
          "type": "user"
        }
      ],
      "tasks": [
      ],
    },
    {
      "name": "user",
      "actors": [
        {
          "id": 1,
          "type": "user"
        }
      ],
      "tasks": [
        {
          "name": "t_user",
          "purpose": "user",
          "commands": {
            "default": "all",
            "sub": [
              "cat",
              "grep"
            ]
          }
        }
      ]
    }
  ]
}
```

In this example, the `admin` role inherits from the `user` role. The `user` role has a task `t_user` that denies `cat` and `grep` commands. The `admin` role will inherit the `t_user` task and deny `cat` and `grep` commands.

### Config example Static separation of duties plugin

The following example shows a RootAsRole config using separation of duties plugin.

```json
{
  "version": "3.0.0-alpha.4",
  "roles": [
    {
      "ssd": ["user"],
      "name": "admin",
      "actors": [
        {
          "id": 0,
          "type": "user"
        }
      ],
      "tasks": [
      ],
    },
    {
      "name": "user",
      "actors": [
        {
          "id": 0,
          "type": "user"
        }
      ],
      "tasks": [
        {
          "name": "t_user",
          "purpose": "user",
          "commands": {
            "default": "all",
            "sub": [
              "cat",
              "grep"
            ]
          }
        }
      ]
    }
  ]
}
```

In this example, the `admin` role is separated from the `user` role. The user 0 cannot be in the `user` role and the `admin` role at the same time. But currently this user is still on these two roles. In resulting, the user 0 will not be able to execute any `admin` or `user` role's tasks.

### Config example with hashchecker plugin

Hashchecker plugin verifies the integrity of the binary before executing it. The following example shows a RootAsRole config using hashchecker plugin.

```json
{
  "version": "3.0.0-alpha.4",
  "roles": [
    {
      "name": "admin",
      "actors": [
        {
          "id": 0,
          "type": "user"
        }
      ],
      "tasks": [
        {
          "name": "t_admin",
          "purpose": "admin",
          "commands": {
            "default": "none",
            "add": [
              {
                "command": "/usr/bin/cat superfile",
                "hash_type": "sha256",
                "hash": "3b77deacba25588129debfb3b9603d7e7187c29d7f6c14bdb667426b7be91761"
              }
            ]
          }
        }
      ]
    }
  ]
}
```

This example shows a `t_admin` task that allows the `cat superfile` command only if the hash of the binary is `3b77deacba25588129debfb3b9603d7e7187c29d7f6c14bdb667426b7be91761`. If the hash of the binary is different, the command isn't even considered in configuration setup. Supported hashes : SHA224, SHA256, SHA384, SHA512.

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

## What are dbus and file credentials fields?

the `dbus` and `file` fields are used for gensr tool from RootAsRole-utils repository. They are enforced to the DBus and file permissions. The `dbus` field is used to allow DBus methods. The `file` field is used to allow file permissions. The gensr tool will generate the DBus and file permissions in according to the `setuid` credentials. So gensr tool requires the `setuid` field to be set.