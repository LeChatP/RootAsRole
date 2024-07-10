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

## Our Research Articles

In 2021, we published our first research article about RootAsRole project @@wazanRootAsRoleSecureAlternative2021. This article present the pilot implementation of RootAsRole project and the main features of the project.

In 2022, we published a journal article about our finding with the `capable` tool thus to simplify RootAsRole configuration @@wazanRootAsRoleSecurityModule2022. This article was more focused on the eBPF feature, and tool outputs analysis.

In 2023, we published a third article about explaining linux kernel issues @@billoirImplementingPrincipleLeast2023. This article proposes enhancements to achieving a balance between usability and the principle of least privilege, emphasizing the need for precise capability definitions.

In May 2024, we published a more general article about the Administrative privilege on various OS @@billoirImplementingPrincipleLeast2024. This article explores the different approaches implemented by the main operating systems (namely Linux, Windows, FreeBSD, and Solaris) to control the privileges of system administrators in order to enforce the principle of least privilege. We define a set of requirements to manage these privileges properly, striving to balance adherence to the principle of least privilege and usability. We also present a deep analysis of each administrative privilege system based on these requirements and exhibit their benefits and limitations.

In July 2024, we studied how to integrate RootAsRole on today's production environment as the project becomes a mature project. This article presents a semi-automated process that improves Ansible-based deployments to have fine-grained control on administrative privileges granted to Ansible tasks. This article is not yet published.

## Comparison with sudo 

By using a role-based access control model, this project allows us to better manage administrative tasks. With this project, you could distribute privileges and prevent them from escalating directly. Unlike sudo does, we don't want to give entire privileges for any insignificant administrative task. You can configure our tool easily with `chsr` command. To find out which capability is needed for a administrative command, we provide the `capable` command. With these two tools, administrators could configure its system to respect the least privilege principle.


## Scenarios

### Scenario 1: Installing a new package

You are using your personal computer and you want to install a new package. By default, RootAsRole add one role with 2 tasks : one task for using `chsr` command that grant only the `CAP_LINUX_IMMUTABLE` capability as `root` user (unprivileged), and one task for all commands but without `CAP_LINUX_IMMUTABLE` privilege. As installing a package may require almost all capabilities, you can use the default role to install a package. Indeed, if you wish to install apache2, you'll need `CAP_NET_BIND_SERVICE`, if you install docker you'll need many privileges, virtualbox needs `CAP_SYS_MODULE`, etc. So, you can use the default role to install a package:

```bash
sr apt install <package>
```

### Scenario 2: Granting users the right to restart their system

You are the system administrator of a company and you want to delegate the right to restart the server to a user. You can use `chsr` to create a role and grant the right to restart the server to users.

```bash
sr chsr role r_users add # Create a new role
sr chsr role r_users grant -g users # Grant the role to the group users
sr chsr role r_users task t_reboot add # Create a new task
sr chsr role r_users task t_reboot cmd whitelist add reboot # Add the reboot command to the task
sr chsr role r_users task t_reboot cred caps whitelist add CAP_SYS_BOOT # Add the CAP_SYS_BOOT capability to the task
```

Then users can restart the server with the following command:

```bash
sr reboot
```

### Scenario 3 : Passing environment variables to a command

You are a developer and you want to pass environment variables to a command. For example with sudo you can use the `-E` option to pass environment variables to a command. With RootAsRole, you'll need to setup a role with a task that allows the command to use environment variables. However, as you keep the default configuration, you'll have two roles that matches ANY commands, and if the first one is more restrictive than the second one, you'll need to specify the role to use. Here is an example:
  
```bash
sr chsr role env add # Create a new role
sr chsr role env task env add # Create a new task
sr chsr role env task env cmd setpolicy allow-all # Add all command to the task
sr chsr role env task env cred caps setpolicy allow-all # Add all capabilities to the task
sr chsr role env task env o env setpolicy keep-all # Keep the environment variables
```

Then you can use the following command to pass environment variables to a command:

```bash
sr -r env [command]
```

This is because the default role do not keep the environment variables, so if you want to keep environment variables you need to specify the role to use.

### Scenario 4 : Automating reboot every day

You are an administrator that want to automatically reboot the system at 04:05 every day with cron for example. You can disable authentication by setting skip-auth in the options. Here is an example:

```bash
sr chsr role auto add # Create a new role
sr chsr role grant -u cron # Grant the role to the user cron
sr chsr role auto task cron_reboot add # Create a new task
sr chsr role auto task cron_reboot cmd whitelist add reboot # Add the reboot command to the task
sr chsr role auto task cron_reboot cred caps whitelist add CAP_SYS_BOOT # Add the CAP_SYS_BOOT capability to the task
sr chsr role auto task cron_reboot o authentication skip # Skip authentication
```

Then you can configure the cron to reboot the system with the following command:

```bash
sr crontab -u cron -e
```

and add the following line to reboot the system at 04:05 every day

```cron
5 4 * * * sr -r auto -t cron_reboot reboot
```

Note: You should consider to set the `-r auto -t cron_reboot` options to the `sr` command when you automate a task to avoid any security issue or future conflict.

For a more complete example, you can checkout the [Is a Linux system without root user possible ?](knowledge/no-root.md) section.