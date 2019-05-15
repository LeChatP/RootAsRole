# RootAsRole C eBPF Capable Tool


## Introduction

Capabilities aren't user-friendly at all, even for a administrator. Mainly because administrator cannot determine exactly what capability a program needs to run correctly. So to fix that difficulty there's filter system integrated in Linux kernel to listen and filter kernel calls named eBPF. This filter uses JIT compilation and is injected to the kernel and will let access to user-space logs and maps. More details [https://github.com/pratyushanand/learn-bpf](here)

## Tested Plateforms

This program has been tested with kernel version 5.0.0-13-generic with x86_64 arch but compiled with 4.10.0-generic code.

## Installation

### How to Build

1. sr -r root -c 'make'

### Usage

By default capable without any argument will run as daemon and will print every capabilities (raw) when they are called in the kernel.

When a command is specified, the program will run the command and wait for ending. The result will be filtered by his pid and his child.
If your program is a daemon you can specify -s X then capable will wait only X seconds before kill him and print result.


## References

[1] <http://www.tcpdump.org/papers/bpf-usenix93.pdf>

[2] <https://lwn.net/Articles/437884/>

[3] <https://www.kernel.org/doc/Documentation/networking/filter.txt>

[4] <http://events.linuxfoundation.org/sites/events/files/slides/Performance%20Monitoring%20and%20Analysis%20Using%20perf%20and%20BPF_1.pdf>