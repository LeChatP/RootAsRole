<!-- markdownlint-capture -->
<!-- markdownlint-disable -->
<p align="center">
  <img src="./RootAsRolev2.svg" width=30%>
 </p>
 <p align="center">
  
<img alt="crates.io" src="https://img.shields.io/crates/v/rootasrole.svg?style=for-the-badge&label=Version&color=e37602&logo=rust" height="25"/>
<img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/LeChatP/RootAsRole/build.yml?style=for-the-badge&logo=githubactions&label=Build&logoColor=white" height="25"/>
<img alt="Tests Status" src="https://img.shields.io/github/actions/workflow/status/LeChatP/RootAsRole/tests.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Tests" height="25"/>
<img alt="Codecov" src="https://img.shields.io/codecov/c/github/lechatp/rootasrole?style=for-the-badge&logo=codecov&color=green&link=https%3A%2F%2Fapp.codecov.io%2Fgh%2FLeChatP%2FRootAsRole" height="25">
<img alt="GitHub" src="https://img.shields.io/github/license/LeChatP/RootAsRole?style=for-the-badge&logo=github&logoColor=white" height="25"/>


</p>
<!-- The project version is managed on json file in resources/rootasrole.json -->
<!-- markdownlint-restore -->

# RootAsRole — A better alternative to `sudo(-rs)`/`su` • ⚡ Blazing fast • 🛡️ Memory-safe • 🔐 Security-oriented

RootAsRole is a Linux/Unix privilege delegation tool based on **Role-Based Access Control (RBAC)**. It empowers administrators to assign precise privileges — not full root — to users and commands.

**[📚 Full Documentation for more details](https://lechatp.github.io/RootAsRole/)**


## 🚀 Why you need RootAsRole?

Most Linux systems break the [Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege). Tools like `sudo` give **full root**, even if you just need one capability like `CAP_NET_RAW`.

RootAsRole solves this:
- Grants **only the required capabilities**
- Uses **roles and tasks** to delegate rights securely
- Better than `sudo`, `doas`, `setcap`, or `pam_cap`, see Comparison table below

## ⚙️ Features

* [A structured access control model based on Roles](https://dl.acm.org/doi/10.1145/501978.501980)
  * [Role hierarchy](https://dl.acm.org/doi/10.1145/501978.501980)
  * [Static/Dynamic Separation of Duties](https://dl.acm.org/doi/10.1145/501978.501980)
* [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) support
* [Highly configurable](https://lechatp.github.io/RootAsRole/chsr/file-config.html)
* Command matching with [glob](https://docs.rs/glob/latest/glob/) for binary path and [PCRE2](https://www.pcre.org/) for command arguments
* 🛠️ Configuration Helpers:
   * [capable](https://github.com/LeChatP/RootAsRole-capable): Analyze command rights
   * [gensr](https://github.com/LeChatP/RootAsRole-gensr): Generate policy from Ansible playbooks

## 📊 Why It’s Better Than Others

| Feature                                  | setcap??          | doas       | sudo                           | sudo-rs                       | dosr (RootAsRole)                                          |
|------------------------------------------|-------------------|------------|--------------------------------|--------------------------------|----------------------------------------------|
| **Change user/groups**                   | N/A               | ✅  | ✅ | ✅ | ✅✅ mandatory or optional                       |
| **Environment variables**                | N/A               | partial  | ✅ | partial                     | ✅                                    |
| **Specific command matching**            | N/A               | strict | strict & regex            | strict & wildcard            | strict & regex                       |
| **Centralized policy**                   | ❌                | ❌         | ✅                    | ❌                            | Planned                                          |
| **Secure signal forwarding**             | N/A               | ❌         | ✅                            | ✅                            | Planned                                      |
| **Set capabilities**                     | ⚠️ files     | ❌         | ❌                             | ❌                            | ✅                                 |
| **Prevent direct privilege escalation**  | ❌                | ❌         | ❌                             | ❌                            | ✅                         |
| **Untrust authorized users**             | ❌                | ❌         | ❌                             | ❌                            | ✅                   |
| **Standardized policy format**       | ❌                | ❌     | ❌                         | ❌                        | ✅                                   |
| **Scalable access control model**        | N/A               | ❌ ACL        | ❌ ACL                            | ❌ ACL                           | ✅ RBAC                                         |


## 📥 Installation

### 🔧 From Source

### Prerequisites

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


### Install Steps


> [!WARNING]
> **This installation process configures RaR with all privileges for the user who install the program. See [what it does](https://lechatp.github.io/RootAsRole/guide/installation.html#what-does-the-installation-script-do).**
>  1. `git clone https://github.com/LeChatP/RootAsRole`
>  1. `cd RootAsRole`
>  1. `cargo xtask install -bip sudo`

### Install from Linux distributions

**We really need your help to bring the project to Linux distributions repositories! Please contribute 🙏!**


## 🧰 Usage

<pre>
Execute privileged commands with a role-based access control system

<u><b>Usage</b></u>: <b>dosr</b> [OPTIONS] [COMMAND]...

<u><b>Arguments</b></u>:
  [COMMAND]...  Command to execute

<u><b>Options</b></u>:
  <b>-r, --role</b> &lt;ROLE&gt;  Role to select
  <b>-t, --task</b> &lt;TASK&gt;  Task to select (--role required)
  <b>-u, --user</b> &lt;USER&gt;  User to execute the command as
  <b>-g, --group</b> &lt;GROUP<,GROUP...>&gt; Group(s) to execute the command as
  <b>-E, --preserve-env</b>          Keep environment variables from the current process
  <b>-p, --prompt</b> &lt;PROMPT&gt; Prompt to display
  <b>-K</b>                 Remove timestamp file
  <b>-i, --info</b>         Print the execution context of a command if allowed by a matching task
  <b>-h, --help</b>         Print help (see more with '--help')
  <b>-V, --version</b>      Print version
</pre>

If you're accustomed to utilizing the sudo tool and find it difficult to break that habit, consider creating an alias : 
```sh
alias sudo="dosr"
alias sr="dosr"
```

## 🏎️ Performance

RootAsRole **3.1.0** introduced **CBOR** support, significantly boosting performance:

- ⚡ **77% faster** than `sudo` when using a single rule
- 📈 **Scales 40% better** than `sudo` as more rules are added

[![Performance comparison](https://github.com/LeChatP/RaR-perf/raw/main/result_25-07-04_15.44.png)](https://github.com/LeChatP/RaR-perf)

> 📝 sudo-rs matches sudo performance but crashes with >100 rules ([won’t fix for now](https://github.com/trifectatechfoundation/sudo-rs/issues/1192))

### Why Performance Matters

When using **Ansible** (or any automation tool), every task that uses `become: true` will invoke `dosr` on the target host.
With **RootAsRole (RaR)**, each role and task introduces additional access control logic --- this doesn’t slow you down.

💡 **Here’s the reality**: You can reach the performance of **1 `sudo` rule** with **~4000 RaR rules**.

That means:
- You can define thousands of fine-grained rules
- You **enforce better security** (POLP) without degrading performance
- The system stays **fast, even at scale**

## 🧱 Configuration

Use the `chsr` command to:
* Define roles and tasks
* Assign them to users or groups

More information in the [documentation](https://lechatp.github.io/RootAsRole/chsr/file-config.html)

Use the [capable](https://github.com/LeChatP/RootAsRole-capable) command to:
* Analyze specific command rights
* Generate "credentials" task structure

Use [gensr](https://github.com/LeChatP/RootAsRole-gensr) for Ansible to:
* Auto-generate security policies for your playbooks
* Detect supply chain attacks by reviewing the generated policy

## ✅ Compatibility

* Linux kernel >= 4.3

## 👥 Contributors

* Eddie Billoir : <eddie.billoir@gmail.com>
* Ahmad Samer Wazan : <ahmad.wazan@zu.ac.ae>
* Romain Laborde : <laborde@irit.fr>
* Rémi Venant: <remi.venant@gmail.com>
* Guillaume Daumas : <guillaume.daumas@univ-tlse3.fr>

## 🖼️ Logo

This logo were generated using DALL-E 2 AI, for any license issue or plagiarism, please note that is not intentionnal and don't hesitate to contact us.

## 📜 Licence notice

This project includes [sudo-rs](https://github.com/memorysafety/sudo-rs) code licensed under the Apache-2 and MIT licenses: 
We have included cutils.rs, securemem.rs to make work the rpassword.rs file. Indeed, We thought that the password was well managed in this file and we have reused it. As sudo-rs does, rpassword.rs is from the rpassword project (License: Apache-2.0). We use it as a replacement of the rpassword project usage.

## 🧪 Sponsored research

This project was initiated by **IRIT** and sponsored by both **IRIT** and **Airbus PROTECT** through an industrial PhD during 2022 and 2025.


## [Link to References](https://lechatp.github.io/RootAsRole/bibliography.html)
