# Build-time default configuration

<blockquote class="caroot">
All this configuration was thought to apply the Fail-safe default principle by Saltzer & Scroeder. This implies enforcing the most strict security options at the top-level of the configuration and overriding only at the lowest according to needs! So if you want to modify Build-time defaults, be very careful and understand the implications of your changes.
</blockquote>

Before installing the tool, you might want to set default behavior. You'll find in .cargo/config.toml :

```toml
[env]
RAR_CFG_TYPE = "json"
RAR_CFG_PATH = "/etc/security/rootasrole.json"
RAR_CFG_DATA_PATH = "/etc/security/rootasrole.d/"
RAR_PAM_SERVICE = "dosr"
RAR_BIN_PATH = "/usr/bin"
RAR_CFG_IMMUTABLE = "true"
RAR_CHSR_EDITOR_PATH = "/usr/bin/vim,/usr/bin/nano,/usr/bin/emacs,/usr/bin/joe,/usr/bin/micro"
RAR_LOG_COMMAND = "journalctl -t dosr -p info"
RAR_TIMEOUT_TYPE = "ppid"
RAR_TIMEOUT_DURATION = "00:05:00"
RAR_TIMEOUT_MAX_USAGE = ""
RAR_PASSWORD_TRIES = "3"
RAR_PASSWORD_DELAY = "00:00:05"
# Who owns the terminal of a command run as another user: caller, or target like sudo.
RAR_TTY_OWNER = "caller"
RAR_PATH_DEFAULT = "delete"
RAR_PATH_ADD_LIST = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
RAR_PATH_REMOVE_LIST = ""
RAR_ENV_DEFAULT = "delete"
RAR_ENV_KEEP_LIST = "HOME,USER,LOGNAME,COLORS,DISPLAY,HOSTNAME,KRB5CCNAME,LS_COLORS,PS1,PS2,XAUTHORITY,XAUTHORIZATION,XDG_CURRENT_DESKTOP"
RAR_ENV_CHECK_LIST = "COLORTERM,LANG,LANGUAGE,LC_*,LINGUAS,TERM,TZ"
RAR_ENV_DELETE_LIST = "IFS,CDPATH,LOCALDOMAIN,RES_OPTIONS,HOSTALIASES,NLSPATH,PATH_LOCALE,LD_*,_RLD*,TERMINFO,TERMINFO_DIRS,TERMPATH,TERMCAP,ENV,BASH_ENV,PS4,GLOBIGNORE,BASHOPTS,SHELLOPTS,JAVA_TOOL_OPTIONS,PERLIO_DEBUG,PERLLIB,PERL5LIB,PERL5OPT,PERL5DB,FPATH,NULLCMD,READNULLCMD,ZDOTDIR,TMPPREFIX,PYTHONHOME,PYTHONPATH,PYTHONINSPECT,PYTHONUSERBASE,RUBYLIB,RUBYOPT"
RAR_ENV_SET_LIST = ""
RAR_ENV_OVERRIDE_BEHAVIOR = "false"
RAR_AUTHENTICATION = "perform"
RAR_EXEC_INFO_DISPLAY = "hide"
RAR_USER_CONSIDERED = "user"
RAR_BOUNDING = "strict"
RAR_UMASK = "0022"
RAR_TIMEOUT_STORAGE = "/var/run/rar/ts"
RAR_WORKDIR_BEHAVIOR = "all"
RAR_WORKDIR_ADD_LIST = ""
RAR_WORKDIR_REMOVE_LIST = ""
#RAR_WORKDIR_FALLBACK = ""
```

These variables allows a customized compilation of the binary. With these variables you'll be able to edit every behaviors, either hardcoded in the binary such as the root configuration file path, or the execution options when they aren't defined at all in the policy.

## Core Path & Configuration Storage Variables Reference

| Variable Name | Type / Format | Description |
| :--- | :--- | :--- |
| `RAR_BIN_PATH` | Folder Path | Used by the `xtask` command: defines the directory where the compiled binaries will be copied. |
| `RAR_CFG_TYPE` | String (`"json"` \| `"cbor"`) | Defines the format used by the configuration backend storage. |
| `RAR_CFG_PATH` | File Path | Absolute filesystem path to the primary policy configuration file. |
| `RAR_CFG_DATA_PATH` | Directory/File Path | Path to configuration data directory. The directory must exist before compiling, or its name must end with `.d`. |
| `RAR_CFG_IMMUTABLE` | Boolean String (`"true"` \| `"false"`) | When true, enforces strict write protection/immutability on `RAR_CFG_PATH`, `RAR_CFG_DATA_PATH`, and their top-level contents (non-recursive). Only in a release build: a debug build never sets the flag. |
| `RAR_CHSR_EDITOR_PATH` | Comma-separated (`,`) binary paths | The editors that `chsr editor` may run. `chsr` takes the one that `/usr/bin/editor` points to when it is in the list, otherwise the first one installed, and `RAR_EDITOR` can only choose among them. vim, nano, emacs, joe and micro are tested under the sandbox of the editor: another editor may not start there. |
| `RAR_PAM_SERVICE` | String | The exact system PAM service configuration identifier called during user authentication. |
| `RAR_LOG_COMMAND` | String | The command that `dosr` names to the user after an error whose reason is only in the log, like a refused policy file. `-p info` leaves out the debug lines of the PAM modules. Empty, `dosr` only says to look in the system log. On a system without journald, set your own command, or leave it empty. |

<blockquote class="caroot">
For security reasons, you'll have to set absolute paths.
</blockquote>

## Environment Variable Management

| Variable Name | Type / Format | Description |
| :--- | :--- | :--- |
| `RAR_ENV_DEFAULT` | String (`"delete"` \| `"keep"`) | The default handling posture for environment variables inherited from the calling user: `delete` removes them except the keep and check lists, `keep` keeps them except the delete list. In both modes, a variable of the check list is removed when its value is unsafe. |
| `RAR_ENV_KEEP_LIST` | Comma-separated (`,`) | A list of explicit environment variables allowed to safely inherit and pass through unchanged. |
| `RAR_ENV_CHECK_LIST` | Comma-separated (`,`) | Environment variables routed to strict validation/compliance check logic. |
| `RAR_ENV_DELETE_LIST`| Comma-separated (`,`) | Environment variables removed from the user's environment in `keep` mode: the variables of the dynamic loader, of the shells and of the interpreters. |
| `RAR_ENV_SET_LIST` | Newline-separated (`\n`), `K=V` | Static key-value pairs to inject directly into the target execution environment. |
| `RAR_ENV_OVERRIDE_BEHAVIOR` | Boolean String (`"true"` \| `"false"`) | Rules whether environment mutation handling can be overridden at runtime via the `-E` flag. |

<blockquote class="caroot-stare">
Malformed values strings create compile-time errors.
</blockquote>

## Execution Context & Workspace Controls

| Variable Name | Type / Format | Description |
| :--- | :--- | :--- |
| `RAR_PATH_DEFAULT` | String (`"delete"` \| `"keep-safe"` \| `"keep-unsafe"`) | Default processing stance for target system `PATH` variable management. `delete` gives the command the add list only. `keep-safe` adds the `PATH` of the user after it, without its relative paths, where `keep-unsafe` is allowing relative paths. |
| `RAR_PATH_ADD_LIST` | Colon-separated (`:`) | Explicit directory paths appended/inserted directly into the `PATH`. |
| `RAR_PATH_REMOVE_LIST`| Colon-separated (`:`) | Explicit directory paths to actively scrub out of the `PATH`. |
| `RAR_WORKDIR_BEHAVIOR`| String (`"all"` \| `"none"`) | Defines the basic behavioral model of the target directory ruleset: `all` allows every working directory except the remove list, `none` only those of the add list. |
| `RAR_WORKDIR_ADD_LIST`| Comma-separated (`,`) | Allowed system directories where users are explicitly authorized to execute commands. |
| `RAR_WORKDIR_REMOVE_LIST`| Comma-separated (`,`) | Denylist of forbidden working directories where execution requests are rejected. |
| `RAR_WORKDIR_FALLBACK`| Optional File Path | Forces a static fallback working directory for the executed command if not defined. Warning! This will *always* set the working directory for *every* commands. |
| `RAR_TTY_OWNER` | String (`"caller"` \| `"target"`) | Determines whether the controlling terminal of the executed command is owned by the calling user or the target user. Note that sudo uses the "target" option by default, but a safer approach is to use "caller", so RaR uses "caller" by default. |

<blockquote class="caroot">
Be very careful with PATH management, "keep-unsafe" is insecure. And I strongly not reccommend it. <br/> <br/> Working directory management is somewhat useful for some cases, such as allowing restricted commands only in a specific restricted directory. Of course that means that allowed commands shouldn't change internally the working directory. For example, if you set "/bin/ls" command, and setting fallback workdir to the "/tmp", then all "dosr ls" command will only show "/tmp" content, no matter where the user is located. Otherwise, if you set "/bin/ls .*" for the command, then the user still be able to retrieve folder contents everywhere on the system.
</blockquote>

## Security, Timeouts & Authentication

| Variable Name | Type / Format | Description |
| :--- | :--- | :--- |
| `RAR_AUTHENTICATION` | String (`"perform"` \| `"skip"`) | Controls whether explicit user authentication sequences must be requested. |
| `RAR_BOUNDING` | String (`"strict"` \| `"ignore"`) | Dictates whether to actively lock down or ignore the Linux capabilities "Bounding" set. |
| `RAR_USER_CONSIDERED` | String (`"user"` \| `"privileged"`) | Determines if UID 0 requests are treated like a regular user (`user`) or preserve classic legacy root behavior (`privileged`). |
| `RAR_UMASK` | Octal, from 0 to 777 | Default file creation mask applied directly to processes, when the policy sets none. It is written in octal, like the `umask` option of the policy. |
| `RAR_TIMEOUT_TYPE` | String (`"ppid"` \| `"tty"` \| `"uid"`) | The operating system context key used to track and anchor elevation timeouts. |
| `RAR_TIMEOUT_DURATION`| Duration `"hh:mm:ss"` | The temporal lifespan window allowed for a token before authorization validation expires. |
| `RAR_TIMEOUT_MAX_USAGE`| Integer (`u64`), or empty | Absolute limits on how many times a given token context can be reused. Empty: no limit. |
| `RAR_TIMEOUT_STORAGE` | Folder Path | Filesystem path used by the timeout engine to persist execution timestamp tokens. |
| `RAR_EXEC_INFO_DISPLAY`| String (`"hide"` \| `"show"`) | Give the ability to users to know their allowed commands and configuration applied. |
| `RAR_PASSWORD_TRIES` | Integer, from 1 to 255 | Maximum number of password attempts allowed before aborting the authentication sequence. |
| `RAR_PASSWORD_DELAY` | Duration `"hh:mm:ss"` | The time to wait between password attempts. |

<blockquote class="caroot-stare">
Showing to a user their policy can help attackers in their enumeration phase. A good policy knows what command a user is allowed to do in a such way that the user don't know that there is a strict policy applied.
</blockquote>