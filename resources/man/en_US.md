% RootAsRole(8) RootAsRole 3.2.4 | System Manager's Manual
% Eddie Billoir <lechatp@outlook.fr>
% August 2025

# NAME
RootAsRole - An alternative to sudo/su commands that adheres to the principle of least privilege and provides more secure memory management.

# SYNOPSIS
- **dosr** [__OPTIONS__] [__COMMAND__]...
- **chsr** [__ARGUMENTS__]

    **chsr**'s arguments follow a grammar available at <https://github.com/LeChatP/RootAsRole/tree/main/src/chsr/cli/cli.pest>

# DESCRIPTION
**RootAsRole** is a tool for administrators that provides a structured role-based access control (RBAC) system to delegate administrative tasks and access rights. It specifically supports __Linux capabilities(7)__ to minimize user privileges.

The Role-Based Access Control (RBAC) model is based on sets of permissions assigned to users or groups. In RootAsRole, a role is a set of administrative tasks assigned to users. Tasks are commands with specific rights. Rights can include changing the user, changing the group, or/and using Linux capabilities.

The **dosr** command allows the execution of commands using a role. It requires a command to be executed as a mandatory parameter. It is also possible to specify a role and a task to select.

There are cases where several tasks correspond to a user's command input. In such cases, sr will select the most precise and least privileged task. The notion of precision is based on how closely the RootAsRole policy matches the user's command. The more the user's profile matches the policy, the higher the level of precision. The same applies to the precision of the user's command compared to its specification in the policy. Similarly, the task with fewer privileges will be prioritized over a task with higher privileges, but only if the tasks are equally precise. Despite this intelligent selection, confusion can still arise, and an error message will be returned.

Example of a confusion case: Two roles are assigned in the same way to a user, and among these roles, two tasks are entirely equivalent, but the configured environment variable are different for these two tasks. In this case, dosr will display the error message "Permission denied" and log a warning that configuration must be fixed. This case should not happen if administrators are using **chsr**, the configuration tool.

It is possible to change the user's prompt using the **-p** option. It is also possible to view the executor's rights using the **-i** option. The displayed information is very limited for the user. Otherwise, administrator can use **chsr** to obtain the complete policy.

The **chsr** command is used to configure RootAsRole and its access control policy. It allows configuring roles, tasks, and permissions. The configuration is stored in the **/etc/security/rootasrole.json** file. If the file system supports it, the file is made immutable, requiring the CAP_LINUX_IMMUTABLE privilege to use **chsr**. The default RootAsRole policy grants to the installer the possibility to use **chsr** with the necessary privileges.

The storage mode of the access control policy can be configured. By default, RootAsRole uses a JSON file. It is possible to change the storage mode by manually modifying the **/etc/security/rootasrole.json** file.

Regarding authentication, RootAsRole uses Pluggable Authentication Module (PAM). The **/etc/pam.d/dosr** file can be configured to change authentication behavior.

The core of RootAsRole implements RBAC-0, a simplified version of RBAC. By default, it adds features in the form of plugins to implement certain RBAC-1 functionalities. RBAC-0 simply implements roles, tasks, and permissions. Plugins add role hierarchy and separation of duties. Plugins can only be implemented directly in the project. Another plugin allows testing the checksum of executed files.

# OPTIONS

**\-r, --role** &lt;ROLE&gt;
  Choose a specific role.

**\-t, --task** &lt;TASK&gt;
  Choose a specific task within a role (requires --role)

**\-u USER, --user** &lt;USER&gt;
  Execute the command as a specific user (act as a filter to select a task)

**\-g GROUP(,GROUP...) , --group** &lt;GROUP(,GROUP...)&gt;
  Execute the command as specific group(s) (act as a filter to select a task)

**\-E, --preserve-env**  
  Preserve environment variables from the current process if allowed by a matching task.

**\-p, --prompt** &lt;PROMPT&gt; 
  Prompt to display when authenticating.

**\-K**  
  Remove timestamp file. (It requires you to authenticate again before executing a command)

**\-i, --info**  
  Print the execution context of a command if allowed by a matching task.

**\-h, --help**  
  Print help (see more with '--help')  

**\-v, --version**  
  Print version information

# EXAMPLES

**dosr reboot**  
  Execute the reboot command (if the policy allows it).

**dosr -r dac chmod 644 /etc/foo/bar**  
  Execute the command chmod 644 /etc/foo/bar with the role dac (if the policy has a dac role and a task that allows the chmod command).

# HISTORY

You can find the history of RootAsRole in the website <https://lechatp.github.io/HISTORY.html>.

# SECURITY RISKS

RootAsRole is a security tool that can give a user full control of the system. An administrator can write an access control policy that gives too many privileges to a user. A Perl-compatible regular expression (pcre2) library is very complex and may accept unexpected special characters.

It can be challenging to determine the necessary privileges for a command. For this, you can use the "capable" tool available at <https://github.com/LeChatP/RootAsRole-capable/> to determine the required capabilities for a command. However, this tool might give too many capabilities. It is recommended to verify if the capabilities are truly necessary, as in most cases, they are not. It is discouraged to use "capable" in production, as it is only for testing purposes.

# SUPPORT

For help, please visit <https://github.com/LeChatP/RootAsRole/discussions> or <https://github.com/LeChatP/RootAsRole/issues> if you find a bug.

# DISCLAIMER

This program is provided "as is" without any warranty, to the extent permitted by law. The authors disclaim any responsibility for the quality or suitability of the program for a particular purpose. You use this program at your own risk. In case of problems, you are responsible for any necessary repairs or corrections. For more details, please refer to the GNU LGPL version 3 or later <https://www.gnu.org/licenses/lgpl-3.0.html>

# LICENSE
LGPLv3+: GNU LGPL version 3 or later <https://www.gnu.org/licenses/lgpl-3.0.html>.

# SEE ALSO
Linux capabilities(7), sudo(8), su(1)
