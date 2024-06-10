# FAQ

This page contains known issues and solutions for RootAsRole project.

## capable does not work on my OS, what can I do ?

capable is a tool based on eBPF features, so it requires a Linux kernel version 4.1 or later. Additionnally you need many kernel features enabled, [described here](https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration). It is also, possible that the program cannot allocate memory, in this case you may consider to add CAP_SYS_RESOURCE capability to the program, but this may not solve completely the issue.

Finally, if you want that capable works on your OS, you can 1) open an issue on the [GitHub repository](http://github.com/LeChatP/RootAsRole), 2) create a Vagrantfile in [test/capable/](https://github.com/LeChatP/RootAsRole/tree/develop/tests/capable) directory and a script to reproduce the issue/and or fix the problem. Note: Community Vagrant images may create more issues than they solve. For example, I never managed to make capable work on ArchLinux images, but my development machine is an ArchLinux.