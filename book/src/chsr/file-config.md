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

### Role example



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
