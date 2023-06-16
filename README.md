<p align="center">
  <img src="./RootAsRolev2.svg" width=75%>
</p>

# RootAsRole (V3.0-alpha.1) : a secure alternative to sudo/su on Linux systems

A role-based access control tool for administrative tasks on Linux. This tool tries to convince the least privilege and ease of use. We design this tool to being least privilege and least vulnerability prone by default.

## Installation

### How to Build

  1. git clone https://github.com/SamerW/RootAsRole
  2. cd RootAsRole
  3. sudo sh ./configure.sh
  4. make
  5. sudo make install

### How to Configure

Our role manager is currently under development. But you can manually execute these commands :

```
sr chattr -i /etc/security/rootasrole.xml
sr nano /etc/security/rootasrole.xml
```

With the new role management features, you will be able to restrict the responsibilities of configurators, but this remains dangerous and there is still a contract of trust with them.

However, today, you can start to configure this tool with the rootasrole.xml file configuration. Some examples are commented on the preinstalled configuration file.

### Usage

```
Usage: sr [options] [command [args]]
Options:
  -r, --role <role>      Role to use
  -i, --info             Display rights of executor
  -v, --version          Display version
  -h, --help             Display this help
```

## Feedback

You may give us your feedbacks  about RootAsRole here:

<https://docs.google.com/forms/d/e/1FAIpQLSfwXISzDaIzlUe42pas2rGZi7SV5QvUXXcDM9_GknPa8AdpFg/viewform>

## Video presentation of the version 1.0 (in French)

https://www.youtube.com/watch?v=2Y8hTI912zQ

## Why do you need this tool ?

Traditionally, administering Linux systems is based on the existence of one powerful user (called superuser) who detains alone the complete list of the system's privileges. However, this administrative model is not respecting the least privilege principle because all programs executed in the context of the superuser obtain much more privileges than they need. For example, tcpdump, a tool for sniffing network packets, requires network capabilities to run. However, by executing it in the context of superuser, tcpdump obtains the complete list of systems' privileges, event reboot functionnality. Thus, the traditional approach of Linux administration breaks the principle of the least privilege that ensures that a process must have the least privileges necessary to perform its job (i.e., sniff packet networks). As a result, an attacker may exploit the vulnerabilities of tcpdump to compromise the whole system when the process of tcpdump possesses the complete list of root privileges.

RootAsRole module implements a role-based approach for distributing Linux capabilities to users. Our module contains the sr (switch role) tool that allows users to control the list of privileges they give to programs. Thus, with our module, users can stop using sudo and su commands that don't allow controlling the list of privileges granted to programs. Some tools already permit control of the list of privileges to give to programs, such as setcap and pam_cap module. However, these tools necessitate the use of extended attributes to store privileges. Storing privileges in extended attributes causes many different problems (see below motivation scenarios). Our module allows assigning Linux capabilities without the need to store the Linux capabilities in the extended attributes of executable files. Our work leverages a new capability set added to the Linux kernel, Ambient Set.

Our module is compatible with LSM modules (SELinux, AppArmor, etc.) and pam_cap.so. So administrators can continue using pam_cap.so along with our module. Finally, the RootAsRole module includes the capable tool, which helps Linux users know the privileges an application asks for.


## How do we solve Role conflicts ?

As you may know with this RBAC model, it is possible for multiple roles to reference the same command for the same users. Since we do not ask by default the role to use, our tool applies an smart policy to choose a role using user, group, command entry and least privilege criteria. We apply a partial order comparison algorithm to decide which role should be chosen :

* Find all the roles that match the user id assignment or the group id, and the command input
* Within the matching roles, select the one that is the most precise and least privileged : 
   1. user assignment is more precise than the combination of group assignment
   1. the combination of group assignment is more precise than single group assignment
   1. exact command is more precise than command with regex argument
   1. command with regex argument is more precise than a wildcarded command path
   1.  wildcarded command path is more precise than wildcarded command path and regex args
   1. wildcarded command path and regex args is more precise than complete wildcard
   1. A role granting no capability is less privileged than one granting at least one capability
   1. A role granting no "ADMIN" capability is less privileged than one granting "ADMIN" capability
   1. A role granting the "ADMIN" capability is less privileged than one granting all capabilities.
   1. A role without setuid is less privileged than one has setuid.
   1. if no root is disabled, a role without 'root' setuid is less privileged than a role with 'root' setuid
   1. A role without setgid is less privileged than one has setgid.
   1. A role with a single setgid is less privileged than one that set multiple gid.
   1. if no root is disabled, A role with multiple setgid is less privileged than one that set root gid
   1. if no root is disabled, A role with root setgid is less privileged than one that set multiple gid, particularly using root group
   1. A role that enables root privileges is less privileged than one which disables root privileges (see "no-root" feature)
   1. A role that disables the Bounding set feature in RootAsRole is less privileged than one that enables it


After these step, if two roles are conflicting, these roles are considered equal (only the environment variables are different), so configurator is being warned that roles could be in conflict and these could not be reached without specifing precisely the role to choose (with `--role` option). In such cases, we highly recommend to review the design of the configured access control.

Regarding the (vii),(viii), and (ix) points, the choice of least privilege is somewhat arbitrary. We are currently working on a explaination on a paper.

## Tested Platforms

Our module has been tested on:
 * Ubuntu>=16.04
 * Debian>=10
 * ArchLinux

After the installation you will find a file called rootasrole.xml in the /etc/security directory. You should configure this file in order to define the set of roles and assign them to users or group of users on your system. Once configuration is done, a user can assume a role using the ‘sr’ tool  that is installed with our package.

## Capable Tool

Since V2.0 of RootAsRole, we created a new tool that permits to retrieve capabilities asked by a program or a service. This can be very important when a user wants to configure the sr tool in order to inject the capabilities requested by a program.  Please note that you should pay attention to the output of the tool, especially with regards the cap_sys_admin capability. In most cases, programs don't need this capability but we show it because this what Linux kernel returns to the capable tool.

For more details please see [Here](https://github.com/SamerW/RootAsRole/tree/master/ebpf)

## [Motivations and Some Working Scenarios](https://github.com/SamerW/RootAsRole/wiki/Motivations-and-Some-Working-Scenarios)

## [How sr and sr_aux work?](https://github.com/SamerW/RootAsRole/wiki/How-sr-and-sr_aux-work)

## Contributors

Ahmad Samer Wazan : ahmad-samer.wazan@irit.fr

Rémi Venant: remi.venant@gmail.com

Guillaume Daumas : guillaume.daumas@univ-tlse3.fr

Eddie Billoir : eddie.billoir@gmail.com

Anderson Hemlee : anderson.hemlee@protonmail.com

Romain Laborde : laborde@irit.fr

## About Logo

This logo were generated using DALL-E 2 AI, for any license issue or plagiarism, please note that is not intentionnal and don't hesitate to contact us.

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
