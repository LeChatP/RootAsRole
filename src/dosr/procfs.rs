//! Process information read from `/proc/<pid>/stat`, ported from sudo-rs
//! (`read_proc_stat` in sudo-rs/src/system/mod.rs).

use std::{io, str::FromStr};

use nix::libc::dev_t;

/// Read the n-th field (0-based) of `/proc/<pid>/stat`.
/// The first two fields (pid and comm) are not accessible.
fn read_proc_stat<T: FromStr>(pid: &str, field_idx: usize) -> io::Result<T> {
    let stat = std::fs::read(format!("/proc/{pid}/stat"))?;
    parse_stat_field(&stat, field_idx)
}

fn parse_stat_field<T: FromStr>(stat: &[u8], field_idx: usize) -> io::Result<T> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "Invalid process stat");
    if field_idx < 2 {
        return Err(invalid());
    }
    // comm may contain spaces and parentheses, so start after the last ')'
    let comm_end = stat.iter().rposition(|b| *b == b')').ok_or_else(invalid)?;
    let field = stat[comm_end + 1..]
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .nth(field_idx - 2)
        .ok_or_else(invalid)?;
    std::str::from_utf8(field)
        .ok()
        .and_then(|field| field.parse().ok())
        .ok_or_else(invalid)
}

/// Controlling terminal of the current process, as known by the kernel.
/// Unlike the standard streams, it cannot be chosen by a redirection.
pub fn controlling_tty() -> Option<dev_t> {
    // tty_nr is displayed as a signed integer, but holds the bits of the encoded device number
    let tty_nr = read_proc_stat::<i32>("self", 6).ok()?.cast_unsigned();
    if tty_nr == 0 {
        return None;
    }
    let major = (tty_nr >> 8) & 0xfff;
    let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
    Some(nix::libc::makedev(major, minor))
}

/// Start time of a process, in clock ticks since boot.
#[cfg(feature = "timeout")]
pub fn start_time(pid: nix::unistd::Pid) -> io::Result<u64> {
    read_proc_stat(&pid.to_string(), 21)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stat_field() {
        let stat = b"42 (a) (b c) S 1 42 42 34816 42 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1234 0 0\n";
        assert_eq!(parse_stat_field::<char>(stat, 2).unwrap(), 'S');
        assert_eq!(parse_stat_field::<i32>(stat, 3).unwrap(), 1);
        assert_eq!(parse_stat_field::<i32>(stat, 5).unwrap(), 42);
        assert_eq!(parse_stat_field::<i32>(stat, 6).unwrap(), 34816);
        assert_eq!(parse_stat_field::<u64>(stat, 21).unwrap(), 1234);
        assert!(parse_stat_field::<u64>(stat, 1).is_err());
        assert!(parse_stat_field::<u64>(stat, 40).is_err());
        assert!(parse_stat_field::<u64>(b"42 no comm end 1 2 3", 2).is_err());
    }

    #[cfg(feature = "timeout")]
    #[test]
    fn test_start_time() {
        use nix::unistd::Pid;

        let this = start_time(Pid::this()).unwrap();
        let parent = start_time(Pid::parent()).unwrap();
        assert!(parent <= this);
        assert!(start_time(Pid::from_raw(-1)).is_err());
    }

    #[test]
    fn test_controlling_tty() {
        // the result depends on how tests are run, it must just not fail
        let _ = controlling_tty();
    }
}
