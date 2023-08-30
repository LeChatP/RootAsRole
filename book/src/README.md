# Introduction

**RootAsRole** is a prject to allow Linux/Unix administrators to delegate their administrative tasks access rights to users. This tool allows you to configure your privilege access management more securely on a single operating system.

Unlike sudo, this project sets the principle least privilege on its core features. Like sudo, this project wants to be usable. More than sudo, we care about configurators, and we try to warn configurators about dangerous manipulations.

By using a role-based access control model, this project allows us to better manage administrative tasks. With this project, you could distribute privileges and prevent them from escalating directly. Unlike sudo does, we don't want to give entire privileges for any insignificant administrative task, so you could configure it easily with `chsr` command. To find out which capability is needed for a administrative command, we provide the `capable` command. With these two tools, administrators could respect the least privilege principle on their system.

What we offer that sudo don't : 
* [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) managed and simplified
* [A structured access control model based on Roles](https://dl.acm.org/doi/10.1145/501978.501980)
* Command matching based on commonly-used open-source libraries 
  * [glob](https://docs.rs/glob/latest/glob/) for binary path
  * [PCRE2](https://www.pcre.org/) for command arguments
* Separation of duties.
* Configuration file formatted in XML and with DTD Schema Validation.

