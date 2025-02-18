use std::{
    env,
    error::Error,
    fs::File,
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};

use capctl::{prctl, CapState};
use capctl::{Cap, CapSet, ParseCapError};
use libc::{FS_IOC_GETFLAGS, FS_IOC_SETFLAGS};
use log::{debug, warn};
use serde::Serialize;
use strum::EnumIs;

#[cfg(feature = "finder")]
use crate::api::PluginManager;
use crate::database::structs::SCommand;

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

#[derive(Debug, EnumIs)]
pub enum ImmutableLock {
    Set,
    Unset,
}

fn immutable_required_privileges(file: &File, effective: bool) -> Result<(), capctl::Error> {
    //get file owner
    let metadata = file.metadata().unwrap();
    let uid = metadata.uid();
    let gid = metadata.gid();
    immutable_effective(effective)?;
    // check if the current user is the owner
    if nix::unistd::Uid::effective() != nix::unistd::Uid::from_raw(uid)
        && nix::unistd::Gid::effective() != nix::unistd::Gid::from_raw(gid)
    {
        read_or_dac_override(effective)?;
        fowner_effective(effective)?;
    }
    Ok(())
}

fn read_or_dac_override(effective: bool) -> Result<(), capctl::Error> {
    match effective {
        false => {
            read_effective(false).and(dac_override_effective(false))?;
        }
        true => {
            read_effective(true).or(dac_override_effective(true))?;
        }
    }
    Ok(())
}

/// Set or unset the immutable flag on a file
/// # Arguments
/// * `file` - The file to set the immutable flag on
/// * `lock` - Whether to set or unset the immutable flag
pub fn toggle_lock_config<P: AsRef<Path>>(file: &P, lock: ImmutableLock) -> io::Result<()> {
    let file = open_with_privileges(file)?;
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { nix::libc::ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if lock.is_unset() {
        val &= !(FS_IMMUTABLE_FL);
    } else {
        val |= FS_IMMUTABLE_FL;
    }
    debug!("Setting immutable privilege");

    immutable_required_privileges(&file, true)?;
    if unsafe { nix::libc::ioctl(fd, FS_IOC_SETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    debug!("Resetting immutable privilege");
    immutable_required_privileges(&file, false)?;
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

pub fn parse_conf_command(command: &SCommand) -> Result<Vec<String>, Box<dyn Error>> {
    match command {
        SCommand::Simple(command) => parse_simple_command(command),
        SCommand::Complex(command) => parse_complex_command(command),
    }
}

fn parse_simple_command(command: &str) -> Result<Vec<String>, Box<dyn Error>> {
    shell_words::split(command).map_err(Into::into)
}

fn parse_complex_command(command: &serde_json::Value) -> Result<Vec<String>, Box<dyn Error>> {
    if let Some(array) = command.as_array() {
        let result: Result<Vec<String>, _> = array
            .iter()
            .map(|item| {
                item.as_str()
                    .map(|s| s.to_string())
                    .ok_or_else(|| "Invalid command".into())
            })
            .collect();
        result
    } else {
        parse_complex_command_with_finder(command)
    }
}

#[cfg(feature = "finder")]
fn parse_complex_command_with_finder(
    command: &serde_json::Value,
) -> Result<Vec<String>, Box<dyn Error>> {
    let res = PluginManager::notify_complex_command_parser(command);
    debug!("Parsed command {:?}", res);
    res
}

#[cfg(not(feature = "finder"))]
fn parse_complex_command_with_finder(
    _command: &serde_json::Value,
) -> Result<Vec<String>, Box<dyn Error>> {
    Err("Invalid command".into())
}

pub fn find_from_envpath<P: AsRef<Path>>(exe_name: P) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .filter_map(|dir| {
                let full_path = dir.join(&exe_name);
                if full_path.is_file() {
                    Some(full_path)
                } else {
                    None
                }
            })
            .next()
    })
}

pub fn final_path(path: &str) -> PathBuf {
    if let Some(env_path) = find_from_envpath(path) {
        env_path
    } else if let Ok(canon_path) = std::fs::canonicalize(path) {
        canon_path
    } else {
        PathBuf::from(path)
    }
}

#[cfg(debug_assertions)]
pub fn subsribe(_: &str) -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .format_module_path(true)
        .init();
    Ok(())
}

#[cfg(not(debug_assertions))]
pub fn subsribe(tool: &str) -> Result<(), Box<dyn Error>> {
    use env_logger::Env;
    use log::LevelFilter;
    use syslog::{BasicLogger, Facility, Formatter3164};
    syslog::init(Facility::LOG_AUTH, LevelFilter::Info, Some(tool))?;
    Ok(())
}

pub fn drop_effective() -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.clear();
    current.set_current()
}

pub fn cap_effective(cap: Cap, enable: bool) -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.set_state(cap, enable);
    current.set_current()
}

pub fn setpcap_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETPCAP, enable)
}

pub fn setuid_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETUID, enable)
}

pub fn setgid_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETGID, enable)
}

pub fn fowner_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::FOWNER, enable)
}

pub fn read_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::DAC_READ_SEARCH, enable)
}

pub fn dac_override_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::DAC_OVERRIDE, enable)
}

pub fn immutable_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::LINUX_IMMUTABLE, enable)
}

pub fn activates_no_new_privs() -> Result<(), capctl::Error> {
    prctl::set_no_new_privs()
}

pub fn write_json_config<T: Serialize, S>(settings: &T, path: S) -> Result<(), Box<dyn Error>>
where
    S: std::convert::AsRef<Path> + Clone,
{
    let file = create_with_privileges(path)?;
    serde_json::to_writer_pretty(file, &settings)?;
    Ok(())
}

pub fn create_with_privileges<P: AsRef<Path>>(p: P) -> Result<File, std::io::Error> {
    std::fs::File::create(&p).or_else(|e| {
        debug!(
            "Error creating file without privilege, trying with privileges: {}",
            e
        );
        dac_override_effective(true)?;
        let res = std::fs::File::create(p).inspect_err(|e| {
            debug!(
                "Error creating file without privilege, trying with privileges: {}",
                e
            );
        });
        dac_override_effective(false)?;
        res
    })
}

pub fn open_with_privileges<P: AsRef<Path>>(p: P) -> Result<File, std::io::Error> {
    std::fs::File::open(&p).or_else(|e| {
        debug!(
            "Error creating file without privilege, trying with privileges: {}",
            e
        );
        read_effective(true).or(dac_override_effective(true))?;
        let res = std::fs::File::open(p);
        read_effective(false)?;
        dac_override_effective(false)?;
        res
    })
}

pub fn remove_with_privileges<P: AsRef<Path>>(p: P) -> Result<(), std::io::Error> {
    std::fs::remove_file(&p).or_else(|e| {
        debug!(
            "Error creating file without privilege, trying with privileges: {}",
            e
        );
        dac_override_effective(true)?;
        let res = std::fs::remove_file(p);
        dac_override_effective(false)?;
        res
    })
}

pub fn create_dir_all_with_privileges<P: AsRef<Path>>(p: P) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(&p).or_else(|e| {
        debug!(
            "Error creating file without privilege, trying with privileges: {}",
            e
        );
        dac_override_effective(true)?;
        let res = std::fs::create_dir_all(p);
        read_effective(false)?;
        dac_override_effective(false)?;
        res
    })
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::*;

    #[test]
    fn test_remove_outer_quotes() {
        assert_eq!(remove_outer_quotes("'test'"), "test");
        assert_eq!(remove_outer_quotes("\"test\""), "test");
        assert_eq!(remove_outer_quotes("test"), "test");
        assert_eq!(remove_outer_quotes("t'est"), "t'est");
        assert_eq!(remove_outer_quotes("t\"est"), "t\"est");
    }

    #[test]
    fn test_parse_capset_iter() {
        let capset = parse_capset_iter(
            vec!["CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"].into_iter(),
        )
        .expect("Failed to parse capset");
        assert!(capset.has(Cap::SYS_ADMIN));
        assert!(capset.has(Cap::SYS_PTRACE));
        assert!(capset.has(Cap::DAC_READ_SEARCH));
    }

    #[test]
    fn test_capabilities_are_exploitable() {
        let mut capset = CapSet::empty();
        capset.add(Cap::SYS_ADMIN);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::SYS_PTRACE);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::SYS_MODULE);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::DAC_READ_SEARCH);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::DAC_OVERRIDE);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::FOWNER);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::CHOWN);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::SETUID);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::SETGID);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::SETFCAP);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::SYS_RAWIO);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::LINUX_IMMUTABLE);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::SYS_CHROOT);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::SYS_BOOT);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::MKNOD);
        assert!(capabilities_are_exploitable(&capset));
        capset.clear();
        capset.add(Cap::WAKE_ALARM);
        assert!(!capabilities_are_exploitable(&capset));
    }

    #[test]
    fn test_toggle_lock_config() {
        let path = PathBuf::from("/tmp/test");
        let file = File::create(&path).expect("Failed to create file");
        let res = toggle_lock_config(&path, ImmutableLock::Set);
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let capeff = status
            .lines()
            .find(|line| line.starts_with("CapEff:"))
            .expect("Failed to find CapEff line");
        let effhex = capeff
            .split(':')
            .last()
            .expect("Failed to get effective capabilities")
            .trim();
        let eff = u64::from_str_radix(effhex, 16).expect("Failed to parse effective capabilities");
        if eff & ((1 << Cap::LINUX_IMMUTABLE as u8) as u64) != 0 {
            assert!(res.is_ok());
        } else {
            assert!(res.is_err());
            // stop test
            return;
        }
        let mut val = 0;
        let fd = file.as_raw_fd();
        if unsafe { nix::libc::ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
            panic!("Failed to get flags");
        }
        assert_eq!(val & FS_IMMUTABLE_FL, FS_IMMUTABLE_FL);
        //test to write on file
        let file = File::create(&path);
        assert!(file.is_err());
        let res = toggle_lock_config(&path, ImmutableLock::Unset);
        assert!(res.is_ok());
        let file = File::create(&path);
        assert!(file.is_ok());
        let res = fs::remove_file(&path);
        assert!(res.is_ok());
    }
}
