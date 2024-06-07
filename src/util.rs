use std::{error::Error, fs::File, mem, os::fd::AsRawFd, path::PathBuf};

use capctl::{Cap, CapSet, ParseCapError};
use libc::{FS_IOC_GETFLAGS, FS_IOC_SETFLAGS};
use pest::{error::LineColLocation, RuleType};
use tracing::{debug, warn};

use crate::common::{
    dac_override_effective, fowner_effective, immutable_effective, open_with_privileges,
    read_effective,
};

pub const RST: &str = "\x1B[0m";
pub const BOLD: &str = "\x1B[1m";
pub const UNDERLINE: &str = "\x1B[4m";
pub const RED: &str = "\x1B[31m";

#[macro_export]
macro_rules! upweak {
    ($e:expr) => {
        $e.upgrade().unwrap()
    };
}

#[macro_export]
macro_rules! as_borrow {
    ($e:expr) => {
        $e.as_ref().borrow()
    };
}

#[macro_export]
macro_rules! as_borrow_mut {
    ($e:expr) => {
        $e.as_ref().borrow_mut()
    };
}

#[macro_export]
macro_rules! rc_refcell {
    ($e:expr) => {
        std::rc::Rc::new(std::cell::RefCell::new($e))
    };
}

const FS_IMMUTABLE_FL: u32 = 0x00000010;

pub fn toggle_lock_config(file: &PathBuf, lock: bool) -> Result<(), String> {
    let file = match open_with_privileges(file) {
        Err(e) => return Err(e.to_string()),
        Ok(f) => f,
    };
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { nix::libc::ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if lock {
        val &= !(FS_IMMUTABLE_FL);
    } else {
        val |= FS_IMMUTABLE_FL;
    }
    debug!("Setting immutable privilege");
    immutable_effective(true).map_err(|e| e.to_string())?;
    debug!("Setting dac override privilege");
    read_effective(true)
        .or(dac_override_effective(true))
        .map_err(|e| e.to_string())?;
    fowner_effective(true).map_err(|e| e.to_string())?;
    debug!("Setting immutable flag");
    if unsafe { nix::libc::ioctl(fd, FS_IOC_SETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    debug!("Resetting immutable privilege");
    immutable_effective(false).map_err(|e| e.to_string())?;
    read_effective(false)
        .and(dac_override_effective(false))
        .map_err(|e| e.to_string())?;
    fowner_effective(false).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn warn_if_mutable(file: &File, return_err: bool) -> Result<(), Box<dyn Error>> {
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { nix::libc::ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if val & FS_IMMUTABLE_FL == 0 {
        if return_err {
            return Err(
                "Config file is not immutable, ask your administrator to solve this issue".into(),
            );
        }
        warn!("Config file is not immutable, think about setting the immutable flag.");
    }
    Ok(())
}

//parse string iterator to capset
pub fn parse_capset_iter<'a, I>(iter: I) -> Result<CapSet, ParseCapError>
where
    I: Iterator<Item = &'a str>,
{
    let mut res = CapSet::empty();

    for part in iter {
        match part.parse() {
            Ok(cap) => res.add(cap),
            Err(error) => {
                return Err(error);
            }
        }
    }
    Ok(res)
}

/// Reference every capabilities that lead to almost a direct privilege escalation
pub fn capabilities_are_exploitable(caps: &CapSet) -> bool {
    caps.has(Cap::SYS_ADMIN)
        || caps.has(Cap::SYS_PTRACE)
        || caps.has(Cap::SYS_MODULE)
        || caps.has(Cap::DAC_READ_SEARCH)
        || caps.has(Cap::DAC_OVERRIDE)
        || caps.has(Cap::FOWNER)
        || caps.has(Cap::CHOWN)
        || caps.has(Cap::SETUID)
        || caps.has(Cap::SETGID)
        || caps.has(Cap::SETFCAP)
        || caps.has(Cap::SYS_RAWIO)
        || caps.has(Cap::LINUX_IMMUTABLE)
        || caps.has(Cap::SYS_CHROOT)
        || caps.has(Cap::SYS_BOOT)
        || caps.has(Cap::MKNOD)
}

pub fn escape_parser_string_vec<S, I>(s: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    s.into_iter()
        .map(|s| escape_parser_string(s))
        .collect::<Vec<String>>()
        .join(" ")
}

pub fn escape_parser_string<S>(s: S) -> String
where
    S: AsRef<str>,
{
    remove_outer_quotes(s.as_ref())
}

fn remove_outer_quotes(input: &str) -> String {
    if input.len() >= 2
        && (input.starts_with('"') && input.ends_with('"')
            || input.starts_with('\'') && input.ends_with('\''))
    {
        remove_outer_quotes(&input[1..input.len() - 1])
    } else {
        input.to_string()
    }
}

#[cfg(test)]
pub(super) mod test {
    pub fn test_resources_folder() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("resources")
    }
    pub fn test_resources_file(filename: &str) -> String {
        test_resources_folder().join(filename).display().to_string()
    }
}

fn start<R>(error: &pest::error::Error<R>) -> (usize, usize)
where
    R: RuleType,
{
    match error.line_col {
        LineColLocation::Pos(line_col) => line_col,
        LineColLocation::Span(start_line_col, _) => start_line_col,
    }
}

pub fn underline<R>(error: &pest::error::Error<R>) -> String
where
    R: RuleType,
{
    let mut underline = String::new();

    let mut start = start(error).1;
    let end = match error.line_col {
        LineColLocation::Span(_, (_, mut end)) => {
            let inverted_cols = start > end;
            if inverted_cols {
                mem::swap(&mut start, &mut end);
                start -= 1;
                end += 1;
            }

            Some(end)
        }
        _ => None,
    };
    let offset = start - 1;
    let line_chars = error.line().chars();

    for c in line_chars.take(offset) {
        match c {
            '\t' => underline.push('\t'),
            _ => underline.push(' '),
        }
    }

    if let Some(end) = end {
        underline.push('^');
        if end - start > 1 {
            for _ in 2..(end - start) {
                underline.push('-');
            }
            underline.push('^');
        }
    } else {
        underline.push_str("^---")
    }

    underline
}
