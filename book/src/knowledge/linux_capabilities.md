# Why you need to use Linux Capabilities

Linux capabilities are a way to give specific privileges to a process without giving it full root access. This is useful when you want to give a process the ability to do something that requires root privileges, but you don't want to change user. For example, you might want to give a process the ability to bind to a privileged port (ports below 1024), but you don't want become root user or get other privileges.

## How Linux Capabilities work

Linux capabilities are a way to split the privileges of the root user into a set of distinct capabilities. Each capability is a specific privilege that can be granted to a process. For example, the `CAP_NET_BIND_SERVICE` capability allows a process to bind to a privileged port.

You can find more information about Linux capabilities in the [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)