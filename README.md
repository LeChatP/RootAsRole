<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
<p align="center">
  <img src="./RootAsRolev2.svg" width=30%>
 </p>
 <p align="center">
  
<img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/LeChatP/RootAsRole/build.yml?label=Build"/>
<img alt="Test Status" src="https://img.shields.io/github/actions/workflow/status/LeChatP/RootAsRole/tests.yml?label=Unit%20Tests">
<a href="https://codecov.io/gh/LeChatP/RootAsRole" >
 <img src="https://codecov.io/gh/LeChatP/RootAsRole/branch/main/graph/badge.svg?token=6J7CRGEIG8"/>
 </a>
 <img alt="GitHub" src="https://img.shields.io/github/license/LeChatP/RootAsRole">

</p>
<!-- The project version is managed on json file in resources/rootasrole.json -->
<!-- markdownlint-restore -->

# RootAsRole (V3.0.5) : A memory-safe and security-oriented alternative to sudo/su commands

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

If you need help to configure a RootAsRole policy, you can use our **[capable tool](https://github.com/LeChatP/RootAsRole-capable)**. This tool identifies the rights required by specific commands, making it easier to define a precise policy.

For administrators who already use **Ansible playbooks** for their tasks and wish to implement **RootAsRole**, our tool [gensr](https://github.com/LeChatP/RootAsRole-utils) can generate an initial draft of a **RootAsRole policy**. The `gensr` tool works by running your Ansible playbook alongside the [capable tool](https://github.com/LeChatP/RootAsRole-capable), creating a draft policy based on the observed required rights. This process helps administrators to harden their Ansible tasks. It helps to verify eventual third-party supply-chain attacks.

**Note:** The `gensr` tool is still in development and may not work with all playbooks. If you wish to contribute to this project, feel free to make issues and pull requests.

## <img src="https://lechatp.github.io/RootAsRole/favicon.svg" width="20px"/>  You can find every interesting resources using [the RootAsRole User/Knowledge/Reference Guide Book](https://lechatp.github.io/RootAsRole/).</h2>

## Installation

### Prerequisites (for compilation)

* [Rust](https://www.rust-lang.org/tools/install) >= 1.76.0
  * You can install Rust by running the following command:
    ```sh
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
    (Do not forget to add the cargo bin directory to your PATH with `. "$HOME/.cargo/env"` command)
* [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
  * You can install git by running the following commands depending on your distribution:
    Ubuntu : `sudo apt-get install git`, RedHat : `sudo yum install git`, ArchLinux : `sudo pacman -S git`
* [clang](https://clang.llvm.org/get_started.html) (or gcc, but clang is highly recommended)
  * You can install clang by running the following commands depending on your distribution:
    Ubuntu : `sudo apt-get install clang`, RedHat : `sudo yum install clang`, ArchLinux : `sudo pacman -S clang`

Then the xtask installation will install the rest of the dependencies for you.

### Install from source

  1. `git clone https://github.com/LeChatP/RootAsRole`
  1. `cd RootAsRole`
  1. `cargo xtask install -bip sudo`


### Install from precompiled binaries

You can download the precompiled binaries from the [release page](https://github.com/LeChatP/RootAsRole/releases).

Then you can install the package with the following commands:

```sh
sudo apt install rootasrole_3.0.0_amd64.deb
```

```sh
sudo rpm -i rootasrole-3.0.0-1.x86_64.rpm
```


### Additional Installation Options

To know more about options, you can run `cargo xtask install --help`.

**[What does the installation do?](https://lechatp.github.io/RootAsRole/guide/installation.html#what-does-the-installation-script-do)**

> [!WARNING]
> **This installation process gives by default the entire privileges set for the user which execute sudo. This means that the user which install this program will be privileged.**


### Usage

<pre>
Execute privileged commands with a role-based access control system

<u><b>Usage</b></u>: <b>sr</b> [OPTIONS] [COMMAND]...

<u><b>Arguments</b></u>:
  [COMMAND]...  Command to execute

<u><b>Options</b></u>:
  <b>-r, --role</b> &lt;ROLE&gt;  Role to select
  <b>-t, --task</b> &lt;TASK&gt;  Task to select (--role required)
  <b>-p, --prompt</b> &lt;PROMPT&gt; Prompt to display
  <b>-i, --info</b>         Display rights of executor
  <b>-h, --help</b>         Print help (see more with '--help')
  <b>-V, --version</b>      Print version
</pre>

If you're accustomed to utilizing the sudo tool and find it difficult to break that habit, consider creating an alias : 
```sh
alias sudo="sr"
```

However you won't find out exact same options as sudo, you can use the `--role` option to specify the role you want to use instead.


## Why do you need this tool ?

| Feature                                  | setcap??          | doas       | sudo                           | sudo-rs                       | sr                                           |
|------------------------------------------|-------------------|------------|--------------------------------|--------------------------------|----------------------------------------------|
| **Change user/groups**                   | N/A               | ✅ mandatory  | ✅ mandatory                     | ✅ mandatory                     | ✅✅ mandatory and optional                       |
| **Manage environment variables**         | N/A               | ✅ partially  | ✅ complete                      | ✅ partially                     | ✅ complete                                    |
| **Specific command matching**            | N/A               | ✅ Strict-only | ✅ Strict & wildcards            | ✅ Strict & wildcards            | ✅ Strict & glob and PCRE                       |
| **Centralized policy**                   | ❌                | ❌         | ✅ LDAP-based                    | ❌                            | ❌                                           |
| **Secure signal forwarding**             | N/A               | ❌         | ✅                            | ✅                            | ❌                                           |
| **Authentication management**            | ❌                | ✅ PAM        | ✅✅ PAM, Kerberos, etc.           | ✅ PAM                           | ✅ PAM                                          |
| **Logging features**                     | ❌                | ✅ syslog     | ✅✅ syslog, logsrvd, etc.         | ✅ syslog                        | ✅ syslog                                       |
| **Plugin API**                           | N/A               | ❌         | complete                      | ❌                            | ⚠️ incomplete                                   |
| **Set capabilities**                     | ⚠️ on files only     | ❌         | ❌                             | ❌                            | ✅ Ambient-based                                |
| **Prevent direct privilege escalation**  | ❌                | ❌         | ❌                             | ❌                            | ✅✅ “Bounding set” based                         |
| **Untrust authorized users**             | ❌                | ❌         | ❌                             | ❌                            | ✅✅ using Immutable file flag                   |
| **Evolvable configuration/policy**       | ❌                | ⚠️ custom     | ⚠️ custom                         | ⚠️ custom                        | ✅ JSON-based                                   |
| **Scalable access control model**        | N/A               | ❌ ACL        | ❌ ACL                            | ❌ ACL                           | ✅ RBAC                                         |
| **Just-in-time features**                | N/A               | ❌         | ❌                             | ❌                            | ❌                                           |
| **Multi-person control**                 | N/A               | ❌         | ❌                             | ❌                            | ❌                                           |
| **SELinux policy management**            | N/A               | ❌         | ✅                            | ❌                            | ❌                                           |


Traditional Linux system administration relies on a single powerful user, the superuser (root), who holds all system privileges. This model does not adhere to the principle of least privilege, as any program executed with superuser rights gains far more privileges than necessary. For example, `tcpdump`, a tool for sniffing network packets, only needs network capabilities. However, when run as the superuser, tcpdump gains all system privileges, including the ability to reboot the system. This excessive privilege can be exploited by attackers to compromise the entire system if tcpdump has vulnerabilities or their developers performs a supply chain attack.

The RootAsRole project offers a role-based approach for managing Linux capabilities. It includes the sr (switch role) tool, which allows users to control the specific privileges assigned to programs.

`Sudo` and `su` are the most common tools for managing privileges in Linux. However, they have several limitations. For example, when an user wants to change owner of a file, they must have the `CAP_CHOWN` capability in order to execute `chown` command. However, the `sudo` tool change the user ID to another one, and this user is root by default, which gives the user all the capabilities of the root user. Additionnally to not allow the user to have only the `CAP_CHOWN` capability, the sudo tool change the user ID to root, which is not necessary for the `chown` command. The RootAsRole project allows the user to have only the `CAP_CHOWN` capability without changing user, which is more secure.

While tools like `setcap` and the `pam_cap` module also manage privileges, they only handle this specific function, which is for limited administrative usages. For example, when you need to use `apt` to install a package, you may not only need cap_dac_override (to read/write files arbitrary) but also to change effective user ID to root. Indeed, without the setuid, every installed file configuration will be owned by the user who executed the command, making file configuration owners inconsistent. This is why the RootAsRole project is essential for managing the entire user credential structure.

Additionnally, `setcap` is applied to the binary file, which means that the capabilities are fixed for every program use-case. This is not ideal for a multi-user system, where different users may need different capabilities for the same program.

Furthermore, the `pam_cap` module is applied to the PAM user session, which means that the capabilities are fixed for every user's session. This is not ideal as administrator do not need these capabilities for every commands and every sessions.

The RootAsRole project is compatible with LSM (Linux Security Modules) such as SELinux and AppArmor, as well as pam_cap.so. Administrators can continue using pam_cap.so alongside our project. Additionally, the project includes the capable tool, which helps users identify the privileges required by an application.

### How to configure RootAsRole

You can configure RootAsRole with the `chsr` command. This command permits you to create roles, tasks, and assign them to users or groups. You can find more information about this command in the [Configure RootAsRole](https://lechatp.github.io/RootAsRole/chsr/index.html) section.

#### How to Find Out the Privileges Needed for Your Command

To determine the privileges required for your command, you can use the capable program. This tool listens for capability requests and displays them to you. Here’s how to use it effectively:

1. **Run the capable program**: It will monitor and display all capability requests made by your command.

1. **Analyze the output**: Pay close attention to the capabilities requested. It's common to see capabilities like CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH because many programs attempt to access files the user doesn't have permission to read. However, these capabilities are often not essential. Additionally, be aware that the Linux kernel may return the cap_sys_admin capability, even if it is not necessary.

1. **Filter unnecessary capabilities**: Determine if the requested capabilities are truly needed. If they are not, consider switching to an appropriate user with the necessary access rights.

1. **Handle missing privileges**: If your program fails to execute due to missing privileges, try granting the specific missing privileges one at a time. Test the program after each change until it works as expected.

By following these steps, you can identify and manage the necessary privileges for your command more effectively.

## Compatibility

Our project has been manually tested on (tests in may 2023):

* Ubuntu>=16.04
* Debian>=10
* ArchLinux

In june 2024, we performed automated `capable` tests with Vagrant on the following distributions:

* ❌ Debian 10 → Dev dependencies unavailable, it should work once compiled
* ✅ Debian 11
* ✅ Fedora 37
* ✅ RedHat 9
* ✅ Ubuntu 22.04
* ✅ ArchLinux
* ✅ Almalinux 8
* ✅ RockyLinux 8

This doesn't mean that earlier versions of these distributions are incompatible; it simply indicates they haven't been tested yet. However, if you encounter issues during the compilation process, they are likely due to dependency problems. In theory, the RootAsRole project should work on any Linux distribution with a kernel version of 4.1 or higher. However, since BTF (BPF Type Format) is becoming a mandatory requirement, [the kernel must be compiled with many features enabled](https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration).

## Contributors

Eddie Billoir : <eddie.billoir@gmail.com>

Ahmad Samer Wazan : <ahmad.wazan@zu.ac.ae>

Rémi Venant: <remi.venant@gmail.com>

Guillaume Daumas : <guillaume.daumas@univ-tlse3.fr>

Romain Laborde : <laborde@irit.fr>

## About Logo

This logo were generated using DALL-E 2 AI, for any license issue or plagiarism, please note that is not intentionnal and don't hesitate to contact us.

## Licence notice

This project includes [sudo-rs](https://github.com/memorysafety/sudo-rs) code licensed under the Apache-2 and MIT licenses: 
We have included cutils.rs, securemem.rs to make work the rpassword.rs file. Indeed, We thought that the password was well managed in this file and we have reused it. As sudo-rs does, rpassword.rs is from the rpassword project (License: Apache-2.0). We use it as a replacement of the rpassword project usage.

This project was initiated by **IRIT** and sponsored by both **IRIT** and **Airbus PROTECT** through an industrial PhD during 2022 and 2025.


## [Link to References](https://lechatp.github.io/RootAsRole/bibliography.html)
