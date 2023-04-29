<p align="center">
  <img src="./RootAsRole_stroke.svg">
</p>

# RootAsRole (V3.0) : a secure alternative to sudo/su on Linux systems



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


## How do we solve conflicts ? More specific to less privileged

In this tool, we tried to present a formal way to define least privilege. Thus to provide a set of rules to resolve conflicts between two potential roles and potential commands block

We consider multiple sets :

Command = { Wildcarded + Not Wildcarded | Wildcarded ∉ Not Wilcarded }

Wildcarded(CMD) = { CMD ∈ /^.*\*.*$/ }
Not Wildcarded(CMD) = { CMD ∈ /^[^*]+$/ }

CMD(c) = 

Wildcard(c) = { c ∈ /^[^;&|]$/ }

Capabilities = { x ∈ /^CAP_.*$/ | 0 <  }

Commands = 


## Tested Platforms

Our module has been tested only on Ubuntu>=16.04 (Kernel 4.3) and Debian platforms.

## Installation

### How to Build

  1. git clone https://github.com/SamerW/RootAsRole
  2. cd RootAsRole
  3. sudo sh ./configure.sh
  4. make
  5. sudo make install

### Usage

Usage : sr [-r role | -c command] [-n] [-u user] [-v] [-h]

    -r, --role=role        the capabilities role to assume

    -c, --command=command  launch the command instead of a bash shell

    -n, --no-root          execute the bash or the command without the possibility to increase privilege (e.g.: sudo) and with no special treatment to root user (uid 0)

    -u, --user=user        substitue the user (reserved to administrators and used probably for service managment)

    -i, --info             print the commands the user is able to process within the role and quit

    -v, --version          print the version of RAR

    -h, --help             print this help and quit.

After the installation you will find a file called capabilityRole.xml in the /etc/security directory. You should configure this file in order to define the set of roles and assign them to users or group of users on your system. Once configuration is done, a user can assume a role using the ‘sr’ tool  that is installed with our package.

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
