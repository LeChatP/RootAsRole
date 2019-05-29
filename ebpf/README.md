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

By default capable without any argument will run as daemon and will print every capabilities when program ends.

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
If your program is a daemon you can specify -s X or -d to let the time to daemon to start.
When -d option is specified, the program will wait for SIGINT (Ctrl+C) to kill program specified (or not) and print result.

## Example

To retrieve every capabilities for tcpdump, I will run ```

```Txt
$ capable -c "tcpdump"
Here's all capabilities intercepted :
| UID   | GID   | PID   | PPID  | NAME                  | CAPABILITIES  |
| 1000  | 1000  | 17029 | 17028 | /proc/17029/cmdline   | cap_sys_admin |
| 1000  | 1000  | 17030 | 17029 | /proc/17030/cmdline   | cap_dac_override, cap_dac_read_search, cap_net_admin, cap_net_raw, cap_sys_admin      |
WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.
WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant
```

So here's the result in fancy Markdown :

| UID   | GID   | PID   | PPID  | NAME                  | CAPABILITIES  |
| ----- | ----- | ----- | ----- | --------------------- | ------------- |
| 1000  | 1000  | 17029 | 17028 | /proc/17029/cmdline   | cap_sys_admin |
| 1000  | 1000  | 17030 | 17029 | /proc/17030/cmdline   | cap_dac_override, cap_dac_read_search, cap_net_admin, cap_net_raw, cap_sys_admin      |

As You can see the process names is unknown, that is normal because retrieving names is done after command tested ends. There's different capabilities shown, but they aren't required! Particularly for CAP_SYS_ADMIN, this capability is call in every fork(). In common cases, capabilities retrieved by program is from last PID. If you look at ppid and pid you see that 17030 is last pid, and also the process that asked for many capabilities. In our case we just wants to get raw traffic, which corresponds to CAP_NET_RAW. So if you create role with CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_NET_ADMIN, CAP_NET_RAW and tcpdump command :

```XML
    <role name="net">
      <capabilities>
        <capability>CAP_NET_RAW</capability>
        <capability>CAP_DAC_OVERRIDE</capability>
        <capability>CAP_DAC_READ_SEARCH</capability>
        <capability>CAP_NET_ADMIN</capability>
      </capabilities>
      <users>
        <user name="lechatp">
          <commands>
            <command>tcpdump</command>
          </commands>
        </user>
      </users>
    </role>
```

So we will try :

```Txt
$ sr -c 'tcpdump'
Authentication of lechatp...
Password: 
Privileged bash launched with the following capabilities : cap_dac_override, cap_dac_read_search, cap_net_admin, cap_net_raw.
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on wlp108s0, link-type EN10MB (Ethernet), capture size 262144 bytes
15:40:03.315266 IP  ############
15:40:03.317476 IP  ############
15:40:03.419401 IP  ############
15:40:03.421165 IP  ############
15:40:03.423753 IP  ############
15:40:03.575237 IP  ############
^C
6 packets captured
6 packets received by filter
0 packets dropped by kernel
End of role net session.
```

Tcpdump works, but with lot of cpabilities, these capabilities are might not a requirement to tcpdump. Then if we read [documentation of tcpdump](http://marionpatrick.free.fr/man_html/html/tcpdump_8.html) : "unless your distribution has a kernel that supports capability bits such as CAP_NET_RAW and code to allow those capability bits to be given to particular accounts and to cause those bits to be set on a user's initial processes when they log in, in which case you must have CAP_NET_RAW in order to capture and CAP_NET_ADMIN to enumerate network devices with, for example, the -D flag". So We just need CAP_NET_RAW.

```XML
    <role name="net">
      <capabilities>
        <capability>CAP_NET_RAW</capability>
      </capabilities>
      <users>
        <user name="lechatp">
          <commands>
            <command>tcpdump</command>
          </commands>
        </user>
      </users>
    </role>
```

So we will try :

```Txt
$ sr -c tcpdump
Authentication of lechatp...
Password: 
Privileged bash launched with the following capabilities : cap_net_raw.
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on enp0s20f0u2, link-type EN10MB (Ethernet), capture size 262144 bytes
16:22:20.403293 IP  ############
16:22:20.403381 IP  ############
16:22:20.403423 IP  ############
16:22:20.403472 IP  ############
16:22:20.403490 IP  ############
16:22:20.405497 IP  ############
16:22:20.405964 IP  ############
^C
7 packets captured
13 packets received by filter
6 packets dropped by kernel
End of role net session.
```

Now tcpdump has the most convinient capability to our use case, and we also know that tcpdump may need other capabilities if this use case isn't convienentfor user.

## Example 2

Now we wants to get capabilities used to get addresses in kallsyms file :

```Txt
$ capable -c 'cat /proc/kallsyms'
...
0000000000000000 T acpi_video_get_backlight_type	[video]
0000000000000000 T acpi_video_set_dmi_backlight_type	[video]
0000000000000000 t acpi_video_detect_exit	[video]
0000000000000000 T acpi_video_register	[video]
0000000000000000 T nfnetlink_init	[nfnetlink]
Here's all capabilities intercepted :
| UID	| GID	| PID	| PPID	| NAME			| CAPABILITIES	|
| 1000	| 1000	| 20128	| 20127	| /proc/20128/cmdline	| cap_sys_admin, cap_syslog	|
| 1000	| 1000	| 20127	| 20126	| /proc/20127/cmdline	| cap_sys_admin	|
WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.
WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant
```

| UID	| GID	| PID	| PPID	| NAME		        	| CAPABILITIES	|
| ----- | ----- | ----- | ----- | --------------------- | ------------- |
| 1000	| 1000	| 20128	| 20127	| /proc/20128/cmdline	| cap_sys_admin, cap_syslog	|
| 1000	| 1000	| 20127	| 20126	| /proc/20127/cmdline	| cap_sys_admin	|

Same for this example : fork() is asking for CAP_SYS_ADMIN so, by default we don't gives cap_sys_admin to a new role. And for security reasons, it is important to set absolute path in configuration :

```Xml
    <role name="stacktrace">
      <capabilities>
        <capability>CAP_SYSLOG</capability>
      </capabilities>
      <users>
        <user name="lechatp">
          <commands>
            <command>cat /proc/kallsyms</command>
          </commands>
        </user>
      </users>
    </role>
```

Let's try for this new role :

```Txt
$ cat /proc/kallsyms
Authentication of lechatp...
Password: 
Privileged bash launched with the role stacktrace and the following capabilities : cap_syslog.
...
ffffffff******** T acpi_video_unregister	[video]
ffffffff******** T acpi_video_get_backlight_type	[video]
ffffffff******** T acpi_video_set_dmi_backlight_type	[video]
ffffffff******** t acpi_video_detect_exit	[video]
ffffffff******** T acpi_video_register	[video]
ffffffff******** T nfnetlink_init	[nfnetlink]
End of role stacktrace session.
```

Perfect! We can see real adresses.

## Example 3

In this example we will try to find capabilities used by sshd :

```Txt
$ capable -c /usr/sbin/sshd
Here's all capabilities intercepted :
| UID	| GID	| PID	| PPID	| NAME			| CAPABILITIES	|
| 1000	| 1000	| 3961	| 3960	| /proc/3961/cmdline	| cap_dac_read_search, cap_setgid, cap_sys_admin	|
| 1000	| 1000	| 3960	| 3959	| /proc/3960/cmdline	| cap_sys_admin	|
WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.
WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant
```

But this output appears to be wrong, because sshd is listening to a port. So we will trying to run as daemon capable and test ssh in parallel :

```Txt
$ capable
Collecting capabilities asked to system...
Use Ctrl+C to print result
^CHere's all capabilities intercepted :
| UID	| GID	| PID	| PPID	| NAME			| CAPABILITIES	|
| 1000	| 1000	| 3772	| 3770	| /proc/3772/cmdline	| cap_sys_admin	|
| 1000	| 1000	| 3760	| 3693	| /proc/3760/cmdline	| cap_dac_read_search, cap_setgid, cap_sys_admin	|
| 1000	| 1000	| 3784	| 3782	| /proc/3784/cmdline	| cap_sys_admin	|
| 1000	| 1000	| 3757	| 3755	| /proc/3757/cmdline	| cap_sys_admin	|
| 1000	| 1000	| 3761	| 1975	| /proc/3761/cmdline	| cap_dac_override, cap_net_bind_service, cap_sys_resource	|
| 1000	| 1000	| 3752	| 3736	| /proc/3752/cmdline	| cap_sys_admin	|
| 0	| 0	| 1569	| 1392	| /usr/lib/xorg/Xorg	| cap_sys_admin	|
| 1000	| 1000	| 3693	| 2917	| bash	| cap_sys_admin	|
| 1000	| 1000	| 3745	| 3743	| /proc/3745/cmdline	| cap_sys_admin	|
| 1000	| 1000	| 3736	| 3732	| /proc/3736/cmdline	| cap_sys_admin	|
| 1000	| 1000	| 3739	| 3737	| /proc/3739/cmdline	| cap_sys_admin	|
| 1000	| 1000	| 3781	| 3779	| /proc/3781/cmdline	| cap_sys_admin	|
| 0	| 0	| 394	| 1	| /lib/systemd/systemd-journald	| cap_kill, cap_setgid, cap_setuid, cap_sys_ptrace, cap_sys_admin	|
WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.
WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant
```

## TO-DO

* Get and read stack trace in kernelside to filter capable() calls by fork() which are non-pertinent for user. This enhancement will ignore CAP_SYS_ADMIN and CAP_SYS_RESOURCES capable() calls for each process. But program must still write entry to map, useful to retrieve the process tree. Note : it seems impossible, see https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html#q-can-bpf-programs-access-stack-pointer but needs confirm. I've read in a commit (I dont resolve him) that bpf_get_stack permits to read stack.

## References

[1] <https://github.com/pratyushanand/learn-bpf>

[2] <http://www.tcpdump.org/papers/bpf-usenix93.pdf>

[3] <https://lwn.net/Articles/437884/>

[4] <https://www.kernel.org/doc/Documentation/networking/filter.txt>

[5] <http://events.linuxfoundation.org/sites/events/files/slides/Performance%20Monitoring%20and%20Analysis%20Using%20perf%20and%20BPF_1.pdf>

[6] <https://www.kernel.org/doc/html/latest/trace/ftrace.html>

[7] <https://elixir.bootlin.com/linux/latest/source/samples/bpf/syscall_tp_kern.c>

[8] <https://lwn.net/Articles/740157/>

[9] <https://github.com/iovisor/ubpf/>

[10] <https://www.bouncybouncy.net/blog/bpf_map_get_next_key-pitfalls/>

[11] <https://www.kernel.org/doc/Documentation/trace/events.txt>

[12] <https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html>