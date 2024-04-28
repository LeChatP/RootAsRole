# What is eBPF ?

eBPF (extended Berkeley Packet Filter) is a technology that allows the execution of custom programs in the Linux kernel without changing the kernel source code or loading kernel modules. In RootAsRole, we use eBPF to implement the `capable` command. This command allows you to check if a process requests any capability.