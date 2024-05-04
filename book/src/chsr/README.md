# Chsr tool documentation

Chsr is a command-line tool to configure roles, permissions and execution options. If you want to know how the file configuration works, you can check the [file configuration](file-config.md) section.

## Usage

<pre style="white-space: pre-wrap;">
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
    <b>-g, --group</b> [nameA,...]     Specify one or more groups combinaison for grant or revoke operations.
Example : chsr role roleA grant -u userA -g groupA,groupB -g groupC
This command will grant roleA to "userA", "users that are in groupA AND groupB" and "groupC".



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
     <b>--setuid</b> [user]            Specify the user to set.
     <b>--setgid</b> [group,...]       Specify groups to set.
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
