# Introduction

**RootAsRole** is a project to allow Linux/Unix administrators to delegate their administrative tasks access rights to users. Its main features are :

* [A structured access control model based on Roles](https://dl.acm.org/doi/10.1145/501978.501980)
  * [Role hierarchy](https://dl.acm.org/doi/10.1145/501978.501980)
  * [Static/Dynamic Separation of Duties](https://dl.acm.org/doi/10.1145/501978.501980)
* [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) support, to minimize the privileges of the user executing the command.
  * Prevent the escalation of privileges via Bounding set manipulation.
* [Highly configurable](chsr/README.md) with a simple command line interface. This interface is designed to be as easy as `ip` command.
  * File relocation ability.
  * Multi-layered and inheritable execution environment configuration.
  * Interoperable and evolvable by using [JSON](https://www.json.org/) as the main configuration file format.
* Command matching based on commonly-used open-source libraries:
  * [glob](https://docs.rs/glob/latest/glob/) for binary path
  * [PCRE2](https://www.pcre.org/) for command arguments

## Usage

The main command line tool is `sr`. It allows you to execute a command by simply typing:
  
```bash
sr <command>
```

You can find more information about this command in the [sr](sr/README.md) section.

The `chsr` command allows you to configure the roles and capabilities of the system. You can find more information about this command in the [Configure RootAsRole](chsr/README.md) section.

## Comparison with sudo 

By using a role-based access control model, this project allows us to better manage administrative tasks. With this project, you could distribute privileges and prevent them from escalating directly. Unlike sudo does, we don't want to give entire privileges for any insignificant administrative task. You can configure our tool easily with `chsr` command. To find out which capability is needed for a administrative command, we provide the `capable` command. With these two tools, administrators could configure its system to respect the least privilege principle.


## Scenarios

### Scenario 1: Personal usage

You are using your personal computer and you want to install a new package. By default, RootAsRole add one role with 2 tasks : one task for using `chsr` command that grant only the `CAP_LINUX_IMMUTABLE` capability as `root` user (unprivileged), and one task for all commands but without `CAP_LINUX_IMMUTABLE` privilege.

```bash
sr apt install <package>
```

### Scenario 2: System administrator of a company

You are the system administrator of a company and you want to delegate the right to restart the server to a user. You can use `chsr` to create a role and grant the right to restart the server to users.

```bash
sr chsr role r_users add # Create a new role
sr chsr role r_users grant -g users # Grant the role to the group users
sr chsr role r_users task t_reboot add # Create a new task
sr chsr role r_users task t_reboot command whitelist add reboot # Add the reboot command to the task
sr chsr role r_users task t_reboot cred caps whitelist add CAP_SYS_BOOT # Add the CAP_SYS_BOOT capability to the task
```

Then users can restart the server with the following command:

```bash
sr reboot
```
