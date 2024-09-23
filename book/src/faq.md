# FAQ

This page contains known issues and solutions for RootAsRole project.

## Why I cannot do `cargo install rootasrole` command ?

The `cargo install` command is primarily designed to install Rust binaries into a user’s local environment, specifically into the `.cargo/bin` directory in the user’s home directory. The philosophy behind this is to keep the installation process simple and unprivileged, avoiding system-wide changes that would require root or admin permissions.

In this context, RootAsRole is a privilege escalation tool, so it requires privileges to work. As the `cargo install` command is not designed to install system-wide binaries, so RootAsRole won't work as expected this way.

## capable does not work on my OS, what can I do ?

capable is a tool based on eBPF features, so it requires a Linux kernel version 4.1 or later. Additionnally you need many kernel features enabled, [described here](https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration). It is also, possible that the program cannot allocate memory, in this case you may consider to add CAP_SYS_RESOURCE capability to the program, but this may not solve completely the issue.

Finally, if you want that capable works on your OS, you can 1) open an issue on the [GitHub repository](http://github.com/LeChatP/RootAsRole), 2) create a Vagrantfile in [test/capable/](https://github.com/LeChatP/RootAsRole/tree/develop/tests/capable) directory and a script to reproduce the issue/and or fix the problem. Note: Community Vagrant images may create more issues than they solve. For example, I never managed to make capable work on ArchLinux images, but my development machine is an ArchLinux.

## Why capable do not show expected capabilities ?

Many reasons can explain that capable does not show expected capabilities. Here are some of them:

1. You access to files that matches with ACLs, so you do not need any capabilities to access to restricted files. This case is better than granting CAP_DAC_OVERRIDE to the program.
1. The program exit before the capabilities are requested. In this case, you may consider granting the blocking capability to the program.
1. The program checks uid == 0. In this case, you may consider to change to root user. capable may misbehave when working as the root user. I am still investigating this issue.