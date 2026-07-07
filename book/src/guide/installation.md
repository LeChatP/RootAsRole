# Full Compilation & Installation Process

This is a complete process for compiling and installing `dosr` and `chsr` binaries.

## Prerequisites

- Linux system with PAM
- Rust toolchain
- Administrative rights (`sudo` or equivalent)

## Retrieve the source code

```bash
git clone https://github.com/LeChatP/RootAsRole
cd RootAsRole
```

## Configuring the fallback default behavior

Before installing the tool, you might want to set default behavior. You'll find in .cargo/config.toml :

```toml
[env]
RAR_CFG_TYPE = "json"
RAR_CFG_PATH = "/etc/security/rootasrole.json"
RAR_CFG_DATA_PATH = "/etc/security/rootasrole.d/"
RAR_PAM_SERVICE = "dosr"
RAR_BIN_PATH = "/usr/bin"
RAR_CFG_IMMUTABLE = "true"
RAR_CHSR_EDITOR_PATH = "/usr/bin/vim"
RAR_TIMEOUT_TYPE = "ppid"
RAR_TIMEOUT_DURATION = "00:05:00"
RAR_TIMEOUT_MAX_USAGE = ""
RAR_PATH_DEFAULT = "delete"
RAR_PATH_ADD_LIST = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
RAR_PATH_REMOVE_LIST = ""
RAR_ENV_DEFAULT = "delete"
RAR_ENV_KEEP_LIST = "HOME,USER,LOGNAME,COLORS,DISPLAY,HOSTNAME,KRB5CCNAME,LS_COLORS,PS1,PS2,XAUTHORY,XAUTHORIZATION,XDG_CURRENT_DESKTOP"
RAR_ENV_CHECK_LIST = "COLORTERM,LANG,LANGUAGE,LC_.*,LINGUAS,TERM,TZ"
RAR_ENV_DELETE_LIST = "PS4,SHELLOPTS,PERLLIB,PERL5LIB,PERL5OPT,PYTHONINSPECT"
RAR_ENV_SET_LIST = ""
RAR_ENV_OVERRIDE_BEHAVIOR = "false"
RAR_AUTHENTICATION = "perform"
RAR_EXEC_INFO_DISPLAY = "hide"
RAR_USER_CONSIDERED = "user"
RAR_BOUNDING = "strict"
RAR_UMASK = "0022"
RAR_MAX_LOCKFILE_RETRIES = "10"
RAR_LOCKFILE_RETRY_INTERVAL = "1"
RAR_TIMEOUT_STORAGE = "/var/run/rar/ts"
RAR_WORKDIR_BEHAVIOR = "all"
RAR_WORKDIR_ADD_LIST = ""
RAR_WORKDIR_REMOVE_LIST = ""
#RAR_WORKDIR_FALLBACK = ""
```

These variables allows a customized compilation of the binary. With these variables you'll be able to edit every behaviors, either hardcoded in the binary such as the root configuration file path, or the execution options when they aren't defined at all in the policy.

### Core Path & Configuration Storage Variables Reference

| Variable Name | Type / Format | Description |
| :--- | :--- | :--- |
| `RAR_BIN_PATH` | Folder Path | Used by the `xtask` command: defines the directory where the compiled binaries will be copied. |
| `RAR_CFG_TYPE` | String (`"json"` | `"cbor"`) | Defines the format used by the configuration backend storage. |
| `RAR_CFG_PATH` | File Path | Absolute filesystem path to the primary policy configuration file. |
| `RAR_CFG_DATA_PATH` | Directory/File Path | Path to configuration data directory. The directory must exist before compiling, or its name must end with `.d`. |
| `RAR_CFG_IMMUTABLE` | Boolean String (`"true"` | `"false"`) | When true, enforces strict write protection/immutability on `RAR_CFG_PATH`, `RAR_CFG_DATA_PATH`, and their top-level contents (non-recursive). |
| `RAR_CHSR_EDITOR_PATH` | Binary Path | Defines the binary path for the `chsr` policy editor utility (e.g., `/usr/bin/vim` or `/usr/bin/nano`). |
| `RAR_PAM_SERVICE` | String | The exact system PAM service configuration identifier called during user authentication. |

<blockquote class="caroot">
For security reasons, you'll have to set absolute paths.
</blockquote>

### Environment Variable Management

| Variable Name | Type / Format | Description |
| :--- | :--- | :--- |
| `RAR_ENV_DEFAULT` | String (`"none"` | `"check"` | `"all"`) | The default handling posture for environment variables inherited from the calling user. |
| `RAR_ENV_KEEP_LIST` | Comma-separated (`,`) | A list of explicit environment variables allowed to safely inherit and pass through unchanged. |
| `RAR_ENV_CHECK_LIST` | Comma-separated (`,`) | Environment variables routed to strict validation/compliance check logic. |
| `RAR_ENV_DELETE_LIST`| Comma-separated (`,`) | Environment variables aggressively wiped and stripped out of the execution context entirely. |
| `RAR_ENV_SET_LIST` | Newline-separated (`\n`), `K=V` | Static key-value pairs to inject directly into the target execution environment. |
| `RAR_ENV_OVERRIDE_BEHAVIOR` | Boolean String (`"true"` | `"false"`) | Rules whether environment mutation handling can be overridden at runtime via the `-E` flag. |

<blockquote class="caroot-stare">
Malformed values strings create compile-time errors.
</blockquote>

### Execution Context & Workspace Controls

| Variable Name | Type / Format | Description |
| :--- | :--- | :--- |
| `RAR_PATH_DEFAULT` | String (`"none"` \| `"keep_safe"` \| `"keep_unsafe"`) | Default processing stance for target system `PATH` variable management. Keep safe ignores relative paths, where keep_unsafe is allowing relative paths. |
| `RAR_PATH_ADD_LIST` | Colon-separated (`:`) | Explicit directory paths appended/inserted directly into the `PATH`. |
| `RAR_PATH_REMOVE_LIST`| Colon-separated (`:`) | Explicit directory paths to actively scrub out of the `PATH`. |
| `RAR_WORKDIR_BEHAVIOR`| String (`"allowlist"` \| `"blacklist"`) | Defines the basic behavioral model of the target directory ruleset. |
| `RAR_WORKDIR_ADD_LIST`| Comma-separated (`,`) | Allowed system directories where users are explicitly authorized to execute commands. |
| `RAR_WORKDIR_REMOVE_LIST`| Comma-separated (`,`) | Denylist of forbidden working directories where execution requests are rejected. |
| `RAR_WORKDIR_FALLBACK`| Optional File Path | Forces a static fallback working directory for the executed command if not defined. Warning! This will *always* set the working directory for *every* commands. |

<blockquote class="caroot">
Be very careful with PATH management, "keep-unsafe" is insecure. And I strongly not reccommend it. <br/> <br/> Working directory management is somewhat useful for some cases, such as allowing restricted commands only in a specific restricted directory. Of course that means that allowed commands shouldn't change internally the working directory. For example, if you set "/bin/ls" command, and setting fallback workdir to the "/tmp", then all "dosr ls" command will only show "/tmp" content, no matter where the user is located. Otherwise, if you set "/bin/ls .*" for the command, then the user still be able to retrieve folder contents everywhere on the system.
</blockquote>

### Security, Timeouts & Authentication

| Variable Name | Type / Format | Description |
| :--- | :--- | :--- |
| `RAR_AUTHENTICATION` | String (`"perform"` \| `"skip"`) | Controls whether explicit user authentication sequences must be requested. |
| `RAR_BOUNDING` | String (`"strict"` \| `"ignore"`) | Dictates whether to actively lock down or ignore the Linux capabilities "Bounding" set. |
| `RAR_USER_CONSIDERED` | String (`"root"` \| `"user"`) | Determines if UID 0 requests are treated like a regular user or preserve classic legacy root behavior. |
| `RAR_UMASK` | Octal / Decimal Integer | Default file creation mask applied directly to processes. |
| `RAR_TIMEOUT_TYPE` | String (`"ppid"` \| `"tty"` \| `"uid"`) | The operating system context key used to track and anchor elevation timeouts. |
| `RAR_TIMEOUT_DURATION`| Duration `"hh:mm:ss"` | The temporal lifespan window allowed for a token before authorization validation expires. |
| `RAR_TIMEOUT_MAX_USAGE`| Integer (`u64`) | Absolute limits on how many times a given token context can be reused. |
| `RAR_TIMEOUT_STORAGE` | Folder Path | Filesystem path used by the timeout engine to persist execution timestamp tokens. |
| `RAR_MAX_LOCKFILE_RETRIES` | Integer (`u64`) | Limit threshold of locking retries allowed on timestamp validation tokens. |
| `RAR_LOCKFILE_RETRY_INTERVAL` | Integer (`u64`) | Backoff sleep duration (seconds) executed between structural timestamp lock checks. |
| `RAR_EXEC_INFO_DISPLAY`| String (`"hide"` \| `"show"`) | Give the ability to users to know their allowed commands and configuration applied. |

<blockquote class="caroot-stare">
Showing to a user their policy can help attackers in their enumeration phase. A good policy knows what command a user is allowed to do in a such way that the user don't know that there is a strict policy applied.
</blockquote>

## Dependencies installation, compiling and installing

It might be trivial, but in order to install RootAsRole, you needs full administrative privileges. But only for specific cases when needed. Again, even here, we wants to apply PoLP. However, compiling a program will never need privileges. So managing unprivileged compilation and privileged installation is a bit tricky.

To manage that, we developed an installation helper tool

```bash
cargo xtask install -bip sudo
```

This command performs:

- dependency installation when required (privileged)
- project build
- deployment of `dosr` and `chsr` in `RAR_BIN_PATH` (privileged)
- capability/ownership setup for `dosr` (privileged)
- installation of PAM config for `dosr` with `RAR_PAM_SERVICE` name (privileged)
- installation of the configuration and policy with `RAR_CFG_PATH` and `RAR_CFG_DATA_PATH` paths (privileged)
- immutable flag setup on policy file when supported by the filesystem controlled with `RAR_CFG_IMMUTABLE` (privileged)

<blockquote class="caroot">
If you don't have sudo installed, you can use su, doas or please binaries. They should work as expected.
</blockquote>