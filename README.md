# RootAsRole : Avoiding su and sudo

## Contributors

Ahmad Samer Wazan : ahmad-samer.wazan@irit.fr

Rémi Venant: remi.venant@gmail.com

Guillaume Daumas : guillaume.daumas@univ-tlse3.fr

Eddie Billoir : eddie.billoir@gmail.com

Romain Laborde : laborde@irit.fr

## Intro

Traditionally, administering Linux systems is based on the existence of one powerful user (called super user) who detains alone the full list of system’s privileges.  This vision has been criticized because all programs executed in the context of the super user obtain much more privileges than they need. For example, tcpdump, a tool for sniffing network packets, needs only the privilege cap_net_raw to run. However, by executing it in the context of super user, tcpdump obtains the full list of systems’ privileges. Thus, the traditional approach of Linux administration breaks the principle of the least privilege that ensures that a process must have the least privileges necessary to perform its job (i.e. sniff packet networks). An attacker may exploit vulnerabilities of tcpdump to compromise the whole system, when the process of tcpdump possesses the full list of root privileges.

As consequence, a POSIX draft (POSIX draft 1003.1e) has been proposed in order to distribute the privileges of super user into processes by giving them only the privileges they need [11]. The proposal defines for each process three sets of bitmaps called Inheritable (i), Permitted (p) and Effective (e).  This model has not been adopted officially, but it has been integrated into the kernel of Linux since 1998.

However, for different reasons this model has not been used widely. Firstly, Linux capability model suffers from different technical problems because of the use of extended attributes to store privileges in the executables (problem 1). Secondly, System administrators don’t have a tool that allows them to distribute the privileges into Linux users in fine-grained manner (problem 2). Fine-grained privilege distribution should give the administrators the ability to decide which privileges to give to users, which programs (e.g. tcpdump) users can use these privileges and on which resources these privileges can be applied (e.g. network interface eth0).  Thirdly, Linux doesn’t provide a tool that permits to Linux users to know the privilege that an application asks for (problem 3). Fourthly, Linux comes with some basic commands that are not compatible with privileges, such as passwd command (problem 4). As a consequence, the majority of Linux users still use su and sudo commands to run privileged applications because the super user model has the advantage of being easy to use. 

Recently, a new privilege set called Ambient has been integrated into the kernel of Linux in order to cope with the technical problems related to the sorting of privileges in the extended attributes of executables. However, Linux doesn’t provide solutions to handle the problem 2,3 and 4.

Root As Role (RAR) module implements a role based approach for distributing Linux capabilities into Linux users. It provides a soluton to problem 2. Our module contains a tool called sr (switch role) that allows users to control the list of privileges they give to programs. Thus, with our module Linux users can stop using sudo and su commands that don't allow controlling the list of privileges to give to programs. There are already some tools that permit to control the list of privileges to give to programs such as setcap and pam_cap module. However, these tools necessitate the use of extended attributes to store privileges. Storing privileges in extended attributes causes many different problems (see below motivaiton scenarios). Our module allows assigning Linux capabilities without the need to store the Linux capabilities in the extended attributes of executable files. Our module leverages a new capability set added to Linux kernel, called Ambient Set. Using this module, administrators can group a set of Linux capabilities in roles and give them to their users. For security reasons, users don’t get the attributed roles by default, they should activate them using the command sr (switch role). Our module is compatible with pam_cap.so. So administrators can continue using pam_cap.so along with our module. Concretely, our module allows respecting the least privilege principle by giving the users the possibility to control the list of privileges they give to their programs.  

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

Since V2.0 of RootAsRole, we created a new tool that permits to retrieve capabilities asked by a running program. This tool is just showing capabilities asked, but not mandatory capabilities. So be warned about his output. This tool is useful when developpers doesn't gave the list of capabilities in his documentation or website. We recommand you to check capabilities in the [manual of linux](http://man7.org/linux/man-pages/man7/capabilities.7.html)
You can also use this tool to check if the tested program ask unwanted capabilities, then we recommand you to check integrity of programs.

## [Why choosing our module?](https://github.com/SamerW/RootAsRole/wiki/Why-choosing-our-module)

## [How sr and sr_aux work?](https://github.com/SamerW/RootAsRole/wiki/How-sr-and-sr_aux-work)

## Limitations

1. we handle the arguments of commands in a very basic way. In fact, when an administrator limits the use of a role to a command with a list of arguments, the user must provide exactly the same commands with the list of arguments in the same order as they are defined in the capabilityRole.xml file. Handling the arguments of commands in more flexible way is a very complex task. Commands have different formats for arguments; the same argument may have different names;some arguments may take values, others not; values of arguments have different formats, etc. 

## To Do List

1. Enhance the -i option to print out the roles and the associated commands for a user. When a user calls sr  with only -i option he can get this information.

2. Add the possibility to restrict the assuming of roles with time. An administrator can indicate the period of time where a user can assume roles.

3. Find an approach that allows controlling the use of privileges on a resource. For example, when cap_net_bind_service is given to a user , we want to indicate the port number that the user can use with this privilege. A possible solution is to use krpobe or to develop  LSM hooks.

4. Give the possibility to all users and all groups to run programs with some privileges. For example, an administrator wants to authorise all users to use ping program. In this case, he can edit the capabilityRole.xml to define a role that has cap_net_raw. In the user and group nodes, the administrator can use the character * for repersenting the list of all users and groups. Users can then use sr to assume the role and run the ping program, but they don't need to authenticate themselves to assume the role.

5. Today only root user can assume the role of other users. This is should be extended to give the possibility to any user who has the privileges cap_setuid, cap_setgid, cap_setfcap and cap_dac_override  to assume the roles of any user. This feature can be used for service management. Right now, even a user with root role can not assume the roles of other users because sr tool has two privileges in its extended attributes. According to capabilities calculation rules sr is considered as privileged file and it will not acquire as consequence the values of the shell's ambient. As consequence, it is important to build a new wrapper like sr_admin that doesn't have any privileges in its extended attributes. In this case, sr_admin will get a copy of its shell's ambient. So sr_admin will be able to have cap_setuid, cap_setgid, cap_setfcap and cap_dac_override when it is run by a shell that has these values in its ambient.  After that sr_admin should create a temporary file of sr tool, and then add the cap_setuid, cap_setgid and cap_dac_override in the extended attributes (permitted set) of the sr temporary file (sr has already cap_setfcap and setpcap) and makes an exec call to sr by passing at least the roles and user arguments. Optionally, sr_admin can pass also noroot and command arguments. Technically, sr_admin needs only cap_setfcap to be able to write the privileges in the sr temporary file but it should verify that user who runs it has cap_setuid, cap_setgid, cap_setfcap and cap_dac_override as sr tool will use these privileges when running the commands on behalf of other users. If the user's shell has these privileges in its effective set, sr_admin accept the request of the user to assume the roles of other users and it will write cap_setuid, cap_setgid and cap_dac_override in the extended attributes of sr temporary file, in addition to cap_setfcap and cap_setpcap that already exist in the extended attributes of sr temporary file.  A modification to sr code is also required to consider this feature that is reserved today to root user.

6. Test our module on other distributions of Linux and make our installation et configuration scripts applicable to them.

7. Use YAML or JSON instead of XML

8. Use Query language (XPath or other in JSON if To-Do #8) instead of sequential search of role

9. Managing blacklist, whitelist and translating list for environnement variables. [inspirated by sudo environnement variables handling system](https://www.sudo.ws/repos/sudo/file/tip/plugins/sudoers/env.c)

## References

[1] PAM repository : https://github.com/linux-pam/linux-pam

[2] libcap repository : https://github.com/mhiramat/libcap

Very helpful site, where you can find some informations about PAM, libcap and the capabilities:

[3] Original paper about capabilities : https://pdfs.semanticscholar.org/6b63/134abca10b49661fe6a9a590a894f7c5ee7b.pdf

[4] Article about the capabilities : https://lwn.net/Articles/632520/

[5] Article about Ambient : https://lwn.net/Articles/636533/

[6] Simple article with test code for Ambient : https://s3hh.wordpress.com/2015/07/25/ambient-capabilities/

[7] Article about how PAM is working : https://artisan.karma-lab.net/petite-introduction-a-pam

[8] A very helpful code about how to create a PAM module : https://github.com/beatgammit/simple-pam

Source of the scenarios code:

[9] Where I have found the simple Python code for HTTP server : https://docs.python.org/2/library/simplehttpserver.html

[10] Where I have found the simple PRELOAD code : https://fishi.devtail.io/weblog/2015/01/25/intercepting-hooking-function-calls-shared-c-libraries/

[11] Serge E.Hallyn, Andrew G.Morgan, “Linux capabilities: making them work”, The Linux Symposium, Ottawa, ON, Canada (2008), https://www.kernel.org/doc/ols/2008/ols2008v1.pages-163.172.pdf
