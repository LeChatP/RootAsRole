use std::{cmp::Ordering, ops::{BitOrAssign, BitAnd}};

#[derive(Clone, PartialEq, PartialOrd,Debug)]
pub enum Caps {
    V2(u64),
    V1(u32),
}

impl Caps {
    const MAX : Self = Self::V2(u64::MAX >> (64 - POSITIONS.len()));
    const MIN : Self = Self::V2(0);
}

impl From<u64> for Caps {
    fn from(v: u64) -> Self {
        Caps::V2(v)
    }
}

impl From<u32> for Caps {
    fn from(v: u32) -> Self {
        Caps::V1(v)
    }
}

impl From<usize> for Caps {
    fn from(v: usize) -> Self {
        if usize::BITS == 64 {
            Caps::V2(v as u64)
        } else {
            Caps::V1(v as u32)
        }
    }
}

impl Into<usize> for Caps {
    fn into(self) -> usize {
        match self {
            Caps::V2(v) => v as usize,
            Caps::V1(v) => v as usize,
        }
    }
}

impl Into<u64> for Caps {
    fn into(self) -> u64 {
        match self {
            Caps::V2(v) => v,
            Caps::V1(v) => v as u64,
        }
    }
}

impl Into<Vec<String>> for Caps {
    fn into(self) -> Vec<String> {
        POSITIONS.iter().enumerate()
        .filter_map(| (index, (name , _)) | 
            if self.clone() & (1 << index) > Caps::MIN { 
                Some(format!("CAP_{}",*name))
            } else {
                None
            }).collect()
        
    }
}

impl Into<u32> for Caps {
    fn into(self) -> u32 {
        match self {
            Caps::V2(v) => v as u32,
            Caps::V1(v) => v,
        }
    }
}

impl From<i32> for Caps {
    fn from(v: i32) -> Self {
        Caps::V1(v as u32)
    }
}

impl BitOrAssign<usize> for Caps {
    fn bitor_assign(&mut self, rhs: usize) {
        match self {
            Caps::V2(v) => *v |= rhs as u64,
            Caps::V1(v) => *v |= rhs as u32,
        }
    }
}

impl BitAnd<usize> for Caps {
    type Output = Self;

    fn bitand(self, rhs: usize) -> Self::Output {
        match self {
            Caps::V2(v) => Caps::V2(v & rhs as u64),
            Caps::V1(v) => Caps::V1(v & rhs as u32),
        }
    }
}

impl From<&str> for Caps {
    fn from(v: &str) -> Self {
        let mut caps: Caps = Caps::MIN;
        let names : Vec<String> = POSITIONS.iter().map(| (name , _) | format!("CAP_{}",*name)).collect();
        for cap in v.split(',') {
        
            if cap.to_uppercase().cmp(&"ALL".to_string())==Ordering::Equal {
                return Caps::MAX;
            }
            if let Some(index) = names.iter().position(|x| x.cmp(&String::from(cap))==Ordering::Equal) {
                caps |= 1 << index;
            }
        }
        caps
    }
}

impl From<String> for Caps {
    fn from(v: String) -> Self {
        let mut caps: Caps = Caps::MIN;
        let names : Vec<String> = POSITIONS.iter().map(| (name , _) | format!("CAP_{}",*name)).collect();
        for cap in v.split(',') {
        
            if cap.to_uppercase().cmp(&"ALL".to_string())==Ordering::Equal {
                return Caps::MAX;
            }
            if let Some(index) = names.iter().position(|x| x.cmp(&String::from(cap))==Ordering::Equal) {
                caps |= 1 << index;
            }
        }
        caps
    }
}

impl From<Vec<String>> for Caps {
    fn from(value: Vec<String>) -> Self {
        let mut caps: Caps = Caps::MIN;
        let names : Vec<String> = POSITIONS.iter().map(| (name , _) | format!("CAP_{}",*name)).collect();
        for cap in value {
            if cap.to_uppercase().cmp(&"ALL".to_string())==Ordering::Equal {
                return Caps::MAX;
            }
            if let Some(index) = names.iter().position(|x| x.cmp(&cap)==Ordering::Equal) {
                caps |= 1 << index;
            }
        }
        caps
    }
}

impl ToString for Caps {
    fn to_string(&self) -> String {
        let mut caps = String::new();
        if *self == Caps::MAX {
            return "ALL".to_string();
        }
        for (i, (name, _)) in POSITIONS.iter().enumerate() {
            if self.clone() & (1 << i) != Caps::MIN {
                if caps.len() > 0 {
                    caps.push_str(",");
                }
                caps.push_str(&format!("CAP_{}",name));
            }
        }
        caps
    }
}

pub const POSITIONS : [(&str, &str); 41]  = [
("CHOWN","Overrides the restriction of changing file ownership and group ownership.
/!\\Be careful about this capability/!\\"),
("DAC_OVERRIDE","Override all DAC access, excluding immuables files."),
("DAC_READ_SEARCH","Allow to read and search on files and directories, excluding immuables files."),
("FOWNER","Condering process is owner of any file, but apply DAC restriction of owner."),
("FSETID","Overrides actions on SETUID or SETGID bit on files."),
("KILL","Overrides restrictions on sending a signal on process."),
("SETGID","Allows setgid setgroups manipulation, and forged gids on socket credentials passing."),
("SETUID","Allows setuid manipulation (including fsuid) and forged pids on socket credentials passing."),
("SETPCAP","Add any capabilities on current bounding to inheritable sets, drop any capability from bounding set."),
("LINUX_IMMUTABLE","Allow modification of S_IMMUTABLE and S_APPEND file attributes."),
("NET_BIND_SERVICE","Allows binding to TCP/UDP sockets below 1024, Allows binding to ATM VCIs below 32."),
("NET_BROADCAST","Allow broadcasting, listen to multicast."),
("NET_ADMIN","Allow manipulate and configure almost everything about networking in the entire system."),
("NET_RAW","Allow use of RAW sockets, use of PACKET sockets, Allow binding to any address for transparent proxying."),
("IPC_LOCK","Allow locking of shared memory segments, use mlock and mlockall."),
("IPC_OWNER","Override IPC ownership checks."),
("SYS_MODULE","Insert and remove kernel modules - modify kernel without limit."),
("SYS_RAWIO","Allow ioperm/iopl access and sending USB messages to any device via /dev/bus/usb."),
("SYS_CHROOT","Allow use of chroot(), even escape from namespaces."),
("SYS_PTRACE","Allow ptrace() of any process."),
("SYS_PACCT","Allow configuration of process accounting."),
("SYS_ADMIN","is the new ROOT, allow to do almost everything including some others capabilities."),
("SYS_BOOT","Allow use of reboot()."),
("SYS_NICE","Change the scheduling algorithm, priority, cpu affinity, realtime ioprio class on any process."),
("SYS_RESOURCE","Override resource, keymaps, quota limits. Override some filesystems limits and memory behaviour."),
("SYS_TIME","Allow manipulation of system clock. Allow irix_stime on mips. Allow setting the real-time clock."),
("SYS_TTY_CONFIG","Allow configuration of tty devices. Allow vhangup() of tty."),
("MKNOD","Allow the privileged aspects of mknod()."),
("LEASE","Allow taking of leases on files."),
("AUDIT_WRITE","Allow writing the audit log via unicast netlink socket."),
("AUDIT_CONTROL","Allow configuration of audit via unicast netlink socket."),
("SETFCAP","Set or remove capabilities on files. Map uid=0 into a child user namespace."),
("MAC_OVERRIDE","Override MAC access. Some MAC can ignore this capability."),
("MAC_ADMIN","Allow MAC configuration or state changes. Some MAC configurations can ignore this capability."),
("SYSLOG","Allow configuring the kernel's syslog (printk behaviour)."),
("WAKE_ALARM","Allow triggering something that will wake the system."),
("BLOCK_SUSPEND","Allow preventing system suspends."),
("AUDIT_READ","Allow reading the audit log via multicast netlink socket."),
("PERFMON","Allow system performance and observability privileged operation."),
("BPF","CAP_BPF allows many BPF operations."),
("CHECKPOINT_RESTORE","Allow checkpoint/restore related operations."),
];