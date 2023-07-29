use std::{
    cmp::Ordering,
    ops::{BitAnd, BitOrAssign},
};

#[derive(Clone, Eq, PartialEq, PartialOrd, Debug)]
pub enum Caps {
    V2(u64), // this will evolve
}

impl Caps {
    const MAX: Self = Self::V2(u64::MAX >> (64 - POSITIONS.len()));
    const MIN: Self = Self::V2(0);

    /**
     * Returns true if the capability is set
     */
    pub fn capable(&self, cap: usize) -> bool {
        if cap >= POSITIONS.len() {
            return false;
        }

        match self {
            Caps::V2(v) => v & (1 << cap) > 0,
        }
    }
    #[allow(dead_code)]
    pub fn set(&mut self, cap: usize) {
        if cap >= POSITIONS.len() {
            return;
        }

        match self {
            Caps::V2(v) => *v |= 1 << cap,
        }
    }
    pub fn is_not_empty(&self) -> bool {
        match self {
            Caps::V2(v) => *v > 0,
        }
    }
}

impl From<u64> for Caps {
    fn from(v: u64) -> Self {
        Caps::V2(v)
    }
}

impl From<usize> for Caps {
    fn from(v: usize) -> Self {
        Caps::V2(v as u64)
    }
}

impl From<Caps> for usize {
    fn from(val: Caps) -> Self {
        match val {
            Caps::V2(v) => v as usize,
        }
    }
}

impl From<Caps> for u64 {
    fn from(val: Caps) -> Self {
        match val {
            Caps::V2(v) => v,
        }
    }
}

impl From<&Caps> for Vec<String> {
    fn from(value: &Caps) -> Self {
        POSITIONS
            .iter()
            .enumerate()
            .filter_map(|(index, (name, _))| {
                if value.capable(index) {
                    Some(format!("cap_{}", *name))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl BitOrAssign<usize> for Caps {
    fn bitor_assign(&mut self, rhs: usize) {
        match self {
            Caps::V2(v) => *v |= rhs as u64,
        }
    }
}

impl<'a> BitAnd<usize> for Caps {
    type Output = Self;

    fn bitand(self, rhs: usize) -> Self::Output {
        match self {
            Caps::V2(v) => Caps::V2(v & rhs as u64),
        }
    }
}

impl From<&str> for Caps {
    fn from(v: &str) -> Self {
        let mut caps = Caps::MIN;
        let names: Vec<String> = POSITIONS
            .iter()
            .map(|(name, _)| format!("cap_{}", *name))
            .collect();
        for cap in v.split(',') {
            if cap.to_lowercase() == "all" {
                return Caps::MAX;
            }
            if let Some(index) = names.iter().position(|x| cap == x) {
                caps |= 1 << index;
            }
        }
        caps
    }
}

impl From<String> for Caps {
    fn from(v: String) -> Self {
        let mut caps: Caps = Caps::MIN;
        let names: Vec<String> = POSITIONS
            .iter()
            .map(|(name, _)| format!("cap_{}", *name))
            .collect();
        for cap in v.split(',') {
            if cap.to_lowercase() == "all".to_lowercase() {
                return Caps::MAX;
            } else if let Some(index) = names.iter().position(|x| x == cap) {
                caps |= 1 << index;
            }
        }
        caps
    }
}

impl From<Vec<String>> for Caps {
    fn from(value: Vec<String>) -> Self {
        let mut caps: Caps = Caps::MIN;
        let names: Vec<String> = POSITIONS
            .iter()
            .map(|(name, _)| format!("cap_{}", *name))
            .collect();
        for cap in value {
            if cap.to_lowercase() == "all" {
                return Caps::MAX;
            }
            if let Some(index) = names.iter().position(|x| cap.to_lowercase().eq(x)) {
                caps |= 1 << index;
            }
        }
        caps
    }
}

impl ToString for Caps {
    fn to_string(&self) -> String {
        let mut caps = String::new();
        if self.eq(&Caps::MAX) {
            return "ALL".to_string();
        }
        for (i, (name, _)) in POSITIONS.iter().enumerate() {
            if self.clone().bitand(1 << i).ne(&Caps::MIN) {
                if !caps.is_empty() {
                    caps.push(',');
                }
                caps.push_str(&format!("cap_{}", name));
            }
        }
        caps.to_lowercase()
    }
}

pub const POSITIONS : [(&str, &str); 41]  = [
("chown","Overrides the restriction of changing file ownership and group ownership.
/!\\Be careful about this capability/!\\"),
("dac_override","Override all DAC access, excluding immuables files."),
("dac_read_search","Allow to read and search on files and directories, excluding immuables files."),
("fowner","Condering process is owner of any file, but apply DAC restriction of owner."),
("fsetid","Overrides actions on SETUID or SETGID bit on files."),
("kill","Overrides restrictions on sending a signal on process."),
("setgid","Allows setgid setgroups manipulation, and forged gids on socket credentials passing."),
("setuid","Allows setuid manipulation (including fsuid) and forged pids on socket credentials passing."),
("setpcap","Add any capabilities on current bounding to inheritable sets, drop any capability from bounding set."),
("linux_immutable","Allow modification of S_IMMUTABLE and S_APPEND file attributes."),
("net_bind_service","Allows binding to TCP/UDP sockets below 1024, Allows binding to ATM VCIs below 32."),
("net_broadcast","Allow broadcasting, listen to multicast."),
("net_admin","Allow manipulate and configure almost everything about networking in the entire system."),
("net_raw","Allow use of RAW sockets, use of PACKET sockets, Allow binding to any address for transparent proxying."),
("ipc_lock","Allow locking of shared memory segments, use mlock and mlockall."),
("ipc_owner","Override IPC ownership checks."),
("sys_module","Insert and remove kernel modules - modify kernel without limit."),
("sys_rawio","Allow ioperm/iopl access and sending USB messages to any device via /dev/bus/usb."),
("sys_chroot","Allow use of chroot(), even escape from namespaces."),
("sys_ptrace","Allow ptrace() of any process."),
("sys_pacct","Allow configuration of process accounting."),
("sys_admin","is the new ROOT, allow to do almost everything including some others capabilities."),
("sys_boot","Allow use of reboot()."),
("sys_nice","Change the scheduling algorithm, priority, cpu affinity, realtime ioprio class on any process."),
("sys_resource","Override resource, keymaps, quota limits. Override some filesystems limits and memory behaviour."),
("sys_time","Allow manipulation of system clock. Allow irix_stime on mips. Allow setting the real-time clock."),
("sys_tty_config","Allow configuration of tty devices. Allow vhangup() of tty."),
("mknod","Allow the privileged aspects of mknod()."),
("lease","Allow taking of leases on files."),
("audit_write","Allow writing the audit log via unicast netlink socket."),
("audit_control","Allow configuration of audit via unicast netlink socket."),
("setfcap","Set or remove capabilities on files. Map uid=0 into a child user namespace."),
("mac_override","Override MAC access. Some MAC can ignore this capability."),
("mac_admin","Allow MAC configuration or state changes. Some MAC configurations can ignore this capability."),
("syslog","Allow configuring the kernel's syslog (printk behaviour)."),
("wake_alarm","Allow triggering something that will wake the system."),
("block_suspend","Allow preventing system suspends."),
("audit_read","Allow reading the audit log via multicast netlink socket."),
("perfmon","Allow system performance and observability privileged operation."),
("bpf","CAP_BPF allows many BPF operations."),
("checkpoint_restore","Allow checkpoint/restore related operations."),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_v2_to_usize() {
        let caps = Caps::V2(10);
        let value: usize = caps.into();
        assert_eq!(value, 10);
    }

    #[test]
    fn caps_v2_into_u64() {
        let caps = Caps::V2(10);
        let value: u64 = caps.into();
        assert_eq!(value, 10u64);
    }

    #[test]
    fn caps_v2_into_vec() {
        let caps = Caps::V2(10);
        let expected = vec!["cap_dac_override".to_string(), "cap_fowner".to_string()];
        let value: Vec<String> = (&caps).into();
        assert_eq!(value, expected);
    }

    #[test]
    fn caps_v2_into_string() {
        let caps = Caps::V2(10);
        let value: String = caps.to_string();
        assert_eq!(value, "cap_dac_override,cap_fowner");
    }
}
