# What is eBPF?

An eBPF program is a kernel-based virtual machine that allows the execution of user-defined bytecode in a secure and high-performance manner. Kprobe is a kernel debugging mechanism that enables the attachment of our eBPF program to the `cap_capable` kernel function entry point, which provides a dynamic way to trace and monitor Linux capabilities requests. @@sharafExtendedBerkeleyPacket2022 @@billo2025

In RaR, eBPF is used by `capable` to observe capability checks during command execution. Therefore, it can determine the effective requested capabilities of a command. However, that does not mean that the command needs these capabilities to run. Or even mean that the command is requesting all possible capabilities of its use-case.

Even if we used to analyse the source code of a command to try finding the capabilities it needs, it is not a reliable method. This is for two main reasons:
1. The privileges are requested given the context of the execution. For example, `ls` command does not need any capabilities to run but if you want to show the content of a folder that is not accessible by the user, then it needs `CAP_DAC_READ_SEARCH` to bypass the access control.
1. The capabilities requests are only made inside the kernel. So reading the source code does not give any direct information about the capabilities that might request a program. Again, if you read the source code of `ls`, you will not find any explicit request for `CAP_DAC_READ_SEARCH` capaibility.

There are other purely practical reasons such as the fact that some progams are closed-source, but that is not a real issue, while annoying.