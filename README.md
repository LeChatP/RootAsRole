<p align="center">
  <img src="./RootAsRolev2.svg">
</p>

# RootAsRole (V3.0) : a secure alternative to sudo/su on Linux systems

A role-based access control tool for administrative tasks on Linux. This tool tries to convince the least privilege and ease of use. We created a configuration that is the least vulnerability prone by default.

## Installation

### How to Build

  1. git clone https://github.com/SamerW/RootAsRole
  2. cd RootAsRole
  3. sudo sh ./configure.sh
  4. make
  5. sudo make install

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

## Intro

Traditionally, administering Linux systems is based on the existence of one powerful user (called superuser) who detains alone the complete list of the system's privileges. However, this administrative model is not respecting the least privilege principle because all programs executed in the context of the superuser obtain much more privileges than they need. For example, tcpdump, a tool for sniffing network packets, requires only the privilege cap_net_raw to run. However, by executing it in the context of superuser, tcpdump obtains the complete list of systems' privileges. Thus, the traditional approach of Linux administration breaks the principle of the least privilege that ensures that a process must have the least privileges necessary to perform its job (i.e., sniff packet networks). As a result, an attacker may exploit the vulnerabilities of tcpdump to compromise the whole system when the process of tcpdump possesses the complete list of root privileges.

RootAsRole module implements a role-based approach for distributing Linux capabilities to users. Our module contains the sr (switch role) tool that allows users to control the list of privileges they give to programs. Thus, with our module, users can stop using sudo and su commands that don't allow controlling the list of privileges granted to programs. Some tools already permit control of the list of privileges to give to programs, such as setcap and pam_cap module. However, these tools necessitate the use of extended attributes to store privileges. Storing privileges in extended attributes causes many different problems (see below motivation scenarios). Our module allows assigning Linux capabilities without the need to store the Linux capabilities in the extended attributes of executable files. Our work leverages a new capability set added to the Linux kernel, Ambient Set.

Our module is compatible with LSM modules (SELinux, AppArmor, etc.) and pam_cap.so. So administrators can continue using pam_cap.so along with our module.
Finally, the RootAsRole module includes the capable tool, which helps Linux users know the privileges an application asks for.


## How do we solve Role conflicts ?

With this RBAC model, it is possible for multiple roles to reference the same command for the same users. Since we do not ask by default the role to use, our tool applies an smart policy to choose a role using user, group, command entry and least privilege criteria. We apply a partial order comparison algorithm to decide which role should be chosen.

For lisibility we express user assignment to role configuration as "UA", group assignment as "GA", and command assignment as "CA". So they are checked in order :

1. UA=user1 $>$ GA=group1&group2 $>$ GA=group3

2. CA=foo $>$ CA=fooba* $>$ CA=foo*

3. no capabilities $>$ some capabilities $>$ contains "ADMIN" capability $>$ all capabilities

4. no setuid $>$ setuid=user1 $>$ setuid=root¹

5. no setgid $>$ setgid=group1 $>$ setgid=group2,group3 $>$ 
setgid=root¹ $>$ setgid=root¹,group4

6. allow root disabled $>$ allow root enabled

7. allow bounding disabled $>$ allow bounding enabled

Where : 

¹  Only if "no root" parameter is disabled

\* wildcard that match every characters except filtered ones (see wildcard-denied in configuration).

After these step, other parameters are considered equal, so configurator is being warned that roles could be in conflict and these could not be reached without specifing precisely the role to choose (with `--role` option). In such cases, we highly recommend to review the design of the configured access control.

As you can see, the order of the capabilities is not precise with respect to the least privilege. We worked hard on the analysis of the linux kernel to try to find a precise and automated order for the capabilities. We recommend you to read our research paper on this subject.

## Tested Platforms

Our module has been tested only on Ubuntu>=16.04 (Kernel 4.3) and Debian platforms.



After the installation you will find a file called rootasrole.xml in the /etc/security directory. You should configure this file in order to define the set of roles and assign them to users or group of users on your system. Once configuration is done, a user can assume a role using the ‘sr’ tool  that is installed with our package.

To edit the configuration file you must first assume the root role using the sr tool. The role root is defined by default with the list of all privileges. To assume the role Root, type in your shell the following command :
`sr -r root`

After that a new shell is opened. This shell contains the capabilities of the role that has been taken by the user. You can then edit capabilityRole.xml file to define your own roles (/etc/security/capabilityRole.xml).

![Screenshot](doc/assumerootrole.png)

For more details, please see **[How to use](https://github.com/SamerW/RootAsRole/wiki/How-to-use)**

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
