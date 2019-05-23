# RootAsRole C eBPF Capable Tool

## Introduction

Capabilities aren't user-friendly at all, even for a administrator. Mainly because administrator cannot determine exactly what capability a program needs to run correctly. So to fix that difficulty there's filter system integrated in Linux kernel to listen and filter kernel calls named eBPF. This filter uses JIT compilation and is injected to the kernel and will let access to user-space logs and maps. More details [https://github.com/pratyushanand/learn-bpf](here)
This tool inspect the capable() call, and filter them to be the most convenient result for administrators.

## Tested Plateforms

This program has been tested with kernel version 5.0.0-13-generic with x86_64 arch but compiled with 4.10.0-generic code.

## Installation

### How to Build

1. sr -r root -c 'make'

### Usage

By default capable without any argument will run as daemon and will print every capabilities when programs ends.

```Text
Usage : capable [-c command] [-s seconds] [-r | -d] [-h] [-v]
Get every capabilities used by running programs.
If you run this command for daemon you can use -s to kill automatically process
Options:
 -c, --command=command  launch the command to be more precise.
 -s, --sleep=number     specify number of seconds before kill program
 -d, --daemon           collecting data until killing program printing result at end
 -r, --raw              show raw results of injection without any filtering
 -v, --version          show the actual version of RootAsRole
 -h, --help             print this help and quit.
Note: this tool is mainly useful for administrators, and is almost not user-friendly
```

When a command is specified, the program will run the command and wait for ending. The result will be filtered by his pid and his child.
If your program is a daemon you can specify -s X then capable will wait only X seconds before kill him and print result.
When daemon option is specified, the program will wait for SIGINT (Ctrl+C) to print result.

## Example

To retrieve every capabilities for tcpdump, I will run ```capable -c "tcpdump -i eth0"```

## TO-DO

* Get and read stack trace in kernelside to filter capable() calls by fork() which are non-pertinent for user. This enhancement will ignore CAP_SYS_ADMIN and CAP_SYS_RESOURCES capable() calls for each process. But program must still write entry to map, useful to retrieve the process tree. Note : it seems impossible, see https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html#q-can-bpf-programs-access-stack-pointer but needs confirm. I've read in a commit (I dont resolve him) that bpf_get_stack permits to read stack.

## References

[1] <http://www.tcpdump.org/papers/bpf-usenix93.pdf>

[2] <https://lwn.net/Articles/437884/>

[3] <https://www.kernel.org/doc/Documentation/networking/filter.txt>

[4] <http://events.linuxfoundation.org/sites/events/files/slides/Performance%20Monitoring%20and%20Analysis%20Using%20perf%20and%20BPF_1.pdf>