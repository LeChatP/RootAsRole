# What is eBPF?

eBPF (extended Berkeley Packet Filter) @@sharafExtendedBerkeleyPacket2022 lets the kernel run restricted programs without patching kernel code or loading custom kernel modules.

In RootAsRole, eBPF is used by `capable` to observe capability checks during command execution.