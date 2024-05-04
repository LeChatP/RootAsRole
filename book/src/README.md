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

