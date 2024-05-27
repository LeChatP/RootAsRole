<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
<p align="center">
  <img src="./RootAsRolev2.svg" width=75%>
 </p>
 <p align="center">
  
<img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/LeChatP/RootAsRole/build.yml?label=Build"/>
<img alt="Test Status" src="https://img.shields.io/github/actions/workflow/status/LeChatP/RootAsRole/tests.yml?label=Unit%20Tests">
<a href="https://codecov.io/gh/LeChatP/RootAsRole" >
 <img src="https://codecov.io/gh/LeChatP/RootAsRole/branch/main/graph/badge.svg?token=6J7CRGEIG8"/>
 </a>
 <img alt="GitHub" src="https://img.shields.io/github/license/LeChatP/RootAsRole">

</p>
<!-- markdownlint-restore -->

# RootAsRole (V3.0.0-alpha.5) : A memory-safe and security-oriented alternative to sudo/su commands

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

## <img src="https://lechatp.github.io/RootAsRole/favicon.svg" width="20px"/>  You can find every interesting resources using [the RootAsRole User/Knowledge/Reference Guide Book](https://lechatp.github.io/RootAsRole/).</h2>

## Installation

### How to Build

Requirement: rustc >= 1.70.0

  1. `git clone <https://github.com/LeChatP/RootAsRole>`
  1. `cd RootAsRole`
  1. `. ./dependencies.sh`
  1. `sudo ./configure.sh`
  1. `make install`

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

Traditional Linux system administration relies on a single powerful user, the superuser (root), who holds all system privileges. This model does not adhere to the principle of least privilege, as any program executed with superuser rights gains far more privileges than necessary. For example, `tcpdump`, a tool for sniffing network packets, only needs network capabilities. However, when run as the superuser, tcpdump gains all system privileges, including the ability to reboot the system. This excessive privilege can be exploited by attackers to compromise the entire system if tcpdump has vulnerabilities or their developers performs a supply chain attack.

The RootAsRole project offers a role-based approach for managing Linux capabilities. It includes the sr (switch role) tool, which allows users to control the specific privileges assigned to programs.

`Sudo` and `su` are the most common tools for managing privileges in Linux. However, they have several limitations. For example, when an user wants to change owner of a file, they must have the `CAP_CHOWN` capability in order to execute `chown` command. However, the `sudo` tool change the user ID to another one, and this user is root by default, which gives the user all the capabilities of the root user. Additionnally to not allow the user to have only the `CAP_CHOWN` capability, the sudo tool change the user ID to root, which is not necessary for the `chown` command. The RootAsRole project allows the user to have only the `CAP_CHOWN` capability without changing user, which is more secure.

While tools like `setcap` and the `pam_cap` module also manage privileges, they only handle this specific function, which is for limited administrative usages. For example, when you need to use `apt` to install a package, you may not only need cap_dac_override (to read/write files arbitrary) but also to change effective user ID to root. Indeed, without the setuid, every installed file configuration will be owned by the user who executed the command, making file configuration owners inconsistent. This is why the RootAsRole project is essential for managing the entire user credential structure.

Additionnally, `setcap` is applied to the binary file, which means that the capabilities are fixed for every program use-case. This is not ideal for a multi-user system, where different users may need different capabilities for the same program.

Furthermore, the `pam_cap` module is applied to the PAM user session, which means that the capabilities are fixed for every user's session. This is not ideal as administrator do not need these capabilities for every commands and every sessions.

The RootAsRole project is compatible with LSM (Linux Security Modules) such as SELinux and AppArmor, as well as pam_cap.so. Administrators can continue using pam_cap.so alongside our module. Additionally, the module includes the capable tool, which helps users identify the privileges required by an application.

### How to configure RootAsRole

You can configure RootAsRole with the `chsr` command. This command permits you to create roles, tasks, and assign them to users or groups. You can find more information about this command in the [Configure RootAsRole](https://lechatp.github.io/RootAsRole/chsr/index.html) section.

#### How to Find Out the Privileges Needed for Your Command

To determine the privileges required for your command, you can use the capable program. This tool listens for capability requests and displays them to you. Here’s how to use it effectively:

1. **Run the capable program**: It will monitor and display all capability requests made by your command.

1. **Analyze the output**: Pay close attention to the capabilities requested. It's common to see capabilities like CAP_DAC_OVERRIDE and CAP_DAC_READ_SEARCH because many programs attempt to access files the user doesn't have permission to read. However, these capabilities are often not essential. Additionally, be aware that the Linux kernel may return the cap_sys_admin capability, even if it is not necessary.

1. **Filter unnecessary capabilities**: Determine if the requested capabilities are truly needed. If they are not, consider switching to an appropriate user with the necessary access rights.

1. **Handle missing privileges**: If your program fails to execute due to missing privileges, try granting the specific missing privileges one at a time. Test the program after each change until it works as expected.

By following these steps, you can identify and manage the necessary privileges for your command more effectively.

## Tested Platforms

Our module has been tested on:

* Ubuntu>=16.04
* Debian>=10
* ArchLinux

## Contributors

Ahmad Samer Wazan : <ahmad-samer.wazan@irit.fr>

Rémi Venant: <remi.venant@gmail.com>

Guillaume Daumas : <guillaume.daumas@univ-tlse3.fr>

Eddie Billoir : <eddie.billoir@gmail.com>

Anderson Hemlee : <anderson.hemlee@protonmail.com>

Romain Laborde : <laborde@irit.fr>

## About Logo

This logo were generated using DALL-E 2 AI, for any license issue or plagiarism, please note that is not intentionnal and don't hesitate to contact us.

## Licence notice

This project includes [sudo-rs](https://github.com/memorysafety/sudo-rs) code licensed under the Apache-2 and MIT licenses: 
We have included cutils.rs, securemem.rs to make work the rpassword.rs file. Indeed, We thought that the password was well managed in this file and we have reused it. As sudo-rs does, rpassword.rs is from the rpassword project (License: Apache-2.0). We use it as a replacement of the rpassword project usage.


## References

[1] PAM repository : <https://github.com/linux-pam/linux-pam>

[2] libcap repository : <https://github.com/mhiramat/libcap>

Very helpful site, where you can find some informations about PAM, libcap and the capabilities:

[3] Original paper about capabilities : <https://pdfs.semanticscholar.org/6b63/134abca10b49661fe6a9a590a894f7c5ee7b.pdf>

[4] Article about the capabilities : <https://lwn.net/Articles/632520/>

[5] Article about Ambient : <https://lwn.net/Articles/636533/>

[6] Simple article with test code for Ambient : <https://s3hh.wordpress.com/2015/07/25/ambient-capabilities/>

[7] Article about how PAM is working : <https://artisan.karma-lab.net/petite-introduction-a-pam>

[8] A very helpful code about how to create a PAM module : <https://github.com/beatgammit/simple-pam>

Source of the scenarios code:

[9] Where I have found the simple Python code for HTTP server : <https://docs.python.org/2/library/simplehttpserver.html>

[10] Where I have found the simple PRELOAD code : <https://fishi.devtail.io/weblog/2015/01/25/intercepting-hooking-function-calls-shared-c-libraries/>

[11] Serge E.Hallyn, Andrew G.Morgan, “Linux capabilities: making them work”, The Linux Symposium, Ottawa, ON, Canada (2008), <https://www.kernel.org/doc/ols/2008/ols2008v1.pages-163.172.pdf>
