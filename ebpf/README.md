# RootAsRole C eBPF Capable Tool

## Introduction

In many cases, it is very difficult for a user or administrator to know what kind of capabilities are requested by a program. So we build the capable tool in order to help Linux users know discover the capabilities requested by a program. Our tool uses eBPF in order to intercept the cap_capable() calls in the kernel. This filter uses JIT compilation and is injected to the kernel and will give back information to user-space. More details [https://github.com/pratyushanand/learn-bpf](here)
However, the kernel retruns the list of capabilities to all programs that are running on the OS. We have added a filtering mecanism in order to let the user see only the capabilites requested by his program. 

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

When a command is specified, the program will run the command and wait for the end of its execution. The result will be filtered by his pid and his child processes.
If your program is a daemon you can specify -s X or -d to give some time to daemon to start.
When -d option is specified, the program will wait for SIGINT (Ctrl+C) to kill the specified program  (or not) and print result.

## Example

To retrieve capabilities requested by tcpdump, I will run ```

```Txt
$ capable -c "tcpdump"
tcpdump: wlp108s0: You don't have permission to capture on that device
(socket: Operation not permitted)

Here's all capabilities intercepted for this program :
cap_net_raw, cap_sys_admin
WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.
WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant
```

In this example we can see that we haven't the permission to execute the tcpdump command but capable tool retruns CAP_NET_RAW and CAP_SYS_ADMIN capabilities. Please pay attention to CAP_SYS_ADMIN, this capability is not probably important for programs but the kernel shows it because it is needed for every fork() call. In this case, tcpdump just wants to get raw traffic, which corresponds to CAP_NET_RAW. So if you create a role with CAP_NET_RAW and tcpdump command :

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

Now tcpdump is run with only cap_net_raw capability.

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
cap_sys_admin, cap_syslog
WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.
WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant
```

We can see that the command output successfuly without permission denied. But adresses are all in 0, it isn't the use case that we want. Also we can see for this example that fork() is asking for CAP_SYS_ADMIN so, by default we don't gives cap_sys_admin to a new role. So let's try a new role with cap_syslog :

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

Let's try this new role :

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

Perfect! We can see real adresses. This example shows that capabilities can change the behavior of program without making errors. They can be handled by developer.

## Example 3

This example will show how our tool is powerful. In this example we will try to find capabilities used by a daemon, let's try with sshd :

```Txt
$ capable -c /usr/sbin/sshd
Here's all capabilities intercepted :
cap_net_bind_service, cap_sys_admin
WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.
WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant
```

We can see that sshd needs CAP_NET_BIND_SERVICE, so let's try to create configuration with sshd :

```Xml
    <role name="sshd">
      <capabilities>
        <capability>CAP_NET_BIND_SERVICE</capability>
      </capabilities>
      <users>
        <user name="lechatp">
          <commands>
            <command>/usr/sbin/sshd</command>
          </commands>
        </user>
      </users>
    </role>
```

```Txt
$ sr -c '/usr/sbin/sshd'
Authentication of lechatp...
Password:
Privileged bash launched with the role sshd and the following capabilities : cap_net_bind_service.
End of role sshd session.
$ ps -aux | grep sshd
$
```

As you can see, the daemon wasn't launched. This is maybe due that the daemon stop when he knows tht he doesn't have the right capability. So to try to solve that, we will give cap_net_bind_service to file with setcap and then retry :

```Txt
$ sr -r root -c "setcap cap_net_bind_service+ep /usr/sbin/sshd"
$ capable -c /usr/sbin/sshd
Could not load host key: /etc/ssh/ssh_host_rsa_key
Could not load host key: /etc/ssh/ssh_host_ecdsa_key
Could not load host key: /etc/ssh/ssh_host_ed25519_key

Here's all capabilities intercepted for this program :
cap_dac_override, cap_sys_admin
WARNING: These capabilities aren't mandatory, but can change the behavior of tested program.
WARNING: CAP_SYS_ADMIN is rarely needed and can be very dangerous to grant
```

Now we see that sshd needs cap_dac_override, it is mainly because the files that the program want to access are owned by root. So we got two choices : chown all the files needed for sshd, or grant cap_dac_override to sshd. We can just add CAP_DAC_OVERRIDE to our config.

```Xml
    <role name="sshd">
      <capabilities>
        <capability>CAP_NET_BIND_SERVICE</capability>
        <capability>CAP_DAC_OVERRIDE</capability>
      </capabilities>
      <users>
        <user name="lechatp">
          <commands>
            <command>/usr/sbin/sshd</command>
          </commands>
        </user>
      </users>
    </role>
```

```Txt
$ sr -c '/usr/sbin/sshd'
Authentication of lechatp...
Password:
Privileged bash launched with the role sshd and the following capabilities : cap_dac_override, cap_net_bind_service.
End of role sshd session.
$ ps -aux | grep sshd
lechatp  10003  0.0  0.0  11868  2856 ?        Ss   07:51   0:00 /usr/sbin/sshd
```

As you can see, the daemon has been launched with lechatp user. All of these steps was necessary to respect the principle of least privilege.

## TO-DO

* Get and read stack trace in kernelside to filter capable() calls by fork() which are non-pertinent for user. This enhancement will ignore CAP_SYS_ADMIN and CAP_SYS_RESOURCES capable() calls for each process. But program must still write entry to map, useful to retrieve the process tree. Note : it seems impossible, see https://www.kernel.org/doc/html/latest/bpf/bpf_design_QA.html#q-can-bpf-programs-access-stack-pointer but needs confirm. I've read in a commit (I dont resolve him) that bpf_get_stack permits to read stack.

* Make this tool testable. Tests are created but not functionning.

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
