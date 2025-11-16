use std::{
    fs::{File, OpenOptions},
    io::{self, ErrorKind, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
};

use capctl::{prctl, CapState};
use capctl::{Cap, CapSet, ParseCapError};

use chrono::Duration;
use konst::{iter, option, primitive::parse_i64, result, slice, string, unwrap_ctx};
use libc::{FS_IOC_GETFLAGS, FS_IOC_SETFLAGS};
use log::{debug, warn};
use nix::fcntl::{Flock, FlockArg};
use serde::Serialize;

use crate::database::options::{
    EnvBehavior, PathBehavior, SAuthentication, SBounding, SInfo, SPrivileged, SUMask,
    TimestampType,
};

#[cfg(feature = "finder")]
use crate::database::score::CmdMin;

pub const RST: &str = "\x1B[0m";
pub const BOLD: &str = "\x1B[1m";
pub const UNDERLINE: &str = "\x1B[4m";
pub const RED: &str = "\x1B[31m";

// Hardened enum values used for critical enums to mitigate attacks like Rowhammer.
// See for example https://arxiv.org/pdf/2309.02545.pdf
// The values are copied from https://github.com/sudo-project/sudo/commit/7873f8334c8d31031f8cfa83bd97ac6029309e4f#diff-b8ac7ab4c3c4a75aed0bb5f7c5fd38b9ea6c81b7557f775e46c6f8aa115e02cd
pub const HARDENED_ENUM_VALUE_0: u32 = 0x052a2925; // 0101001010100010100100100101
pub const HARDENED_ENUM_VALUE_1: u32 = 0x0ad5d6da; // 1010110101011101011011011010
pub const HARDENED_ENUM_VALUE_2: u32 = 0x69d61fc8; // 1101001110101100001111111001000
pub const HARDENED_ENUM_VALUE_3: u32 = 0x1629e037; // 0010110001010011110000000110111
pub const HARDENED_ENUM_VALUE_4: u32 = 0x1fc8d3ac; // 11111110010001101001110101100

pub const ENV_PATH_BEHAVIOR: PathBehavior = result::unwrap_or!(
    PathBehavior::try_parse(env!("RAR_PATH_DEFAULT")),
    PathBehavior::Delete
);

pub const ENV_PATH_ADD_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_PATH_ADD_LIST"), ":"),
        map(string::trim),
);

pub const ENV_PATH_REMOVE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_PATH_REMOVE_LIST"), ":"),
        map(string::trim),
);

//=== ENV ===
pub const ENV_DEFAULT_BEHAVIOR: EnvBehavior = result::unwrap_or!(
    EnvBehavior::try_parse(env!("RAR_ENV_DEFAULT")),
    EnvBehavior::Delete
);

pub const ENV_KEEP_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_KEEP_LIST"), ","),
        map(string::trim),
);

pub const ENV_CHECK_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_CHECK_LIST"), ","),
        map(string::trim),
);

pub const ENV_DELETE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_DELETE_LIST"), ","),
        map(string::trim),
);

pub const ENV_SET_LIST_SLICE: &[(&str, &str)] = &iter::collect_const!((&str, &str) =>
    string::split(env!("RAR_ENV_SET_LIST"), "\n"),
        filter_map(|s| {
            if let Some((key,value)) = string::split_once(s, '=') {
                Some((string::trim(key),string::trim(value)))
            } else {
                None
            }
        })
);

pub const ENV_OVERRIDE_BEHAVIOR: bool = result::unwrap_or!(
    konst::primitive::parse_bool(env!("RAR_ENV_OVERRIDE_BEHAVIOR")),
    false
);

pub static ENV_KEEP_LIST: [&str; ENV_KEEP_LIST_SLICE.len()] =
    *unwrap_ctx!(slice::try_into_array(ENV_KEEP_LIST_SLICE));

pub static ENV_CHECK_LIST: [&str; ENV_CHECK_LIST_SLICE.len()] =
    *unwrap_ctx!(slice::try_into_array(ENV_CHECK_LIST_SLICE));

pub static ENV_DELETE_LIST: [&str; ENV_DELETE_LIST_SLICE.len()] =
    *unwrap_ctx!(slice::try_into_array(ENV_DELETE_LIST_SLICE));

pub static ENV_SET_LIST: [(&str, &str); ENV_SET_LIST_SLICE.len()] =
    *unwrap_ctx!(slice::try_into_array(ENV_SET_LIST_SLICE));

//=== STimeout ===

pub const TIMEOUT_TYPE: TimestampType = result::unwrap_or!(
    TimestampType::try_parse(env!("RAR_TIMEOUT_TYPE")),
    TimestampType::PPID
);

pub const TIMEOUT_DURATION: Duration = option::unwrap_or!(
    result::unwrap_or!(
        convert_string_to_duration(env!("RAR_TIMEOUT_DURATION")),
        None
    ),
    Duration::seconds(5)
);

#[derive(Debug)]
struct DurationParseError;
impl std::fmt::Display for DurationParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid duration format")
    }
}

const fn convert_string_to_duration(
    s: &str,
) -> Result<Option<chrono::TimeDelta>, DurationParseError> {
    let parts = string::split(s, ':');
    let (hours, parts) = match parts.next() {
        Some(h) => h,
        None => return Err(DurationParseError),
    };
    let (minutes, parts) = match parts.next() {
        Some(m) => m,
        None => return Err(DurationParseError),
    };
    let (seconds, _) = match parts.next() {
        Some(sec) => sec,
        None => return Err(DurationParseError),
    };

    let hours: i64 = unwrap_ctx!(parse_i64(hours));
    let minutes: i64 = unwrap_ctx!(parse_i64(minutes));
    let seconds: i64 = unwrap_ctx!(parse_i64(seconds));
    Ok(Some(Duration::seconds(
        hours * 3600 + minutes * 60 + seconds,
    )))
}

pub const TIMEOUT_MAX_USAGE: u64 = result::unwrap_or!(
    konst::primitive::parse_u64(env!("RAR_TIMEOUT_MAX_USAGE")),
    0
);

pub const BOUNDING: SBounding = result::unwrap_or!(
    SBounding::try_parse(env!("RAR_BOUNDING")),
    SBounding::Strict
);

pub const AUTHENTICATION: SAuthentication = result::unwrap_or!(
    SAuthentication::try_parse(env!("RAR_AUTHENTICATION")),
    SAuthentication::Perform
);

pub const PRIVILEGED: SPrivileged = result::unwrap_or!(
    SPrivileged::try_parse(env!("RAR_USER_CONSIDERED")),
    SPrivileged::User
);

pub const UMASK: SUMask = SUMask(result::unwrap_or!(
    konst::primitive::parse_u16(env!("RAR_UMASK")),
    0o022
));

pub const INFO: SInfo =
    result::unwrap_or!(SInfo::try_parse(env!("RAR_EXEC_INFO_DISPLAY")), SInfo::Hide);

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

pub fn immutable_required_privileges<F, R>(file: &File, f: F) -> std::io::Result<R>
where
    F: FnOnce() -> std::io::Result<R>,
{
    let metadata = file.metadata()?;
    let uid = metadata.uid();
    let gid = metadata.gid();
    let effective_uid = nix::unistd::Uid::effective();
    let effective_gid = nix::unistd::Gid::effective();

    let caps = if effective_uid != nix::unistd::Uid::from_raw(uid)
        && effective_gid != nix::unistd::Gid::from_raw(gid)
    {
        vec![Cap::LINUX_IMMUTABLE, Cap::FOWNER, Cap::DAC_OVERRIDE]
    } else {
        vec![Cap::LINUX_IMMUTABLE]
    };
    with_privileges(&caps, f)
}

pub(crate) fn is_immutable(file: &File) -> std::io::Result<bool> {
    let mut val = 0;
    if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(val & FS_IMMUTABLE_FL != 0)
}

/// Perform a writing operation on a writable opened file descriptor with the immutable flag set
/// The function will temporarily remove the immutable flag, perform the operation and set it back
pub fn with_mutable_config<F, R>(file: &mut File, f: F) -> std::io::Result<R>
where
    F: FnOnce(&mut File) -> io::Result<R>,
{
    let mut val = unlock_immutable(file)?;
    let res = f(file);
    val |= FS_IMMUTABLE_FL;
    lock_immutable(file, val)?;
    res
}

pub fn lock_immutable(file: &mut File, mut val: u32) -> Result<(), io::Error> {
    immutable_required_privileges(file, || {
        if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_SETFLAGS, &mut val) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    })?;
    Ok(())
}

pub fn unlock_immutable(file: &mut File) -> Result<u32, io::Error> {
    let mut val = 0;
    if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if val & FS_IMMUTABLE_FL != 0 {
        val &= !(FS_IMMUTABLE_FL);
        immutable_required_privileges(file, || {
            if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_SETFLAGS, &mut val) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })?;
    } else {
        warn!("Config file was not immutable.");
    }
    Ok(val)
}

pub fn warn_if_mutable(file: &File, return_err: bool) -> std::io::Result<()> {
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { nix::libc::ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if val & FS_IMMUTABLE_FL == 0 {
        if return_err {
            return Err(std::io::Error::new(
                ErrorKind::ReadOnlyFilesystem,
                "Config file is not immutable, ask your administrator to solve this issue",
            ));
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

pub fn optimized_serialize_capset(capset: &CapSet) -> u64 {
    // convert capset to u64
    let bits: u64 = capset.iter().fold(0, |acc, cap| acc | (1 << (cap as u64)));
    bits
}

pub fn definitive_drop(needed: &[Cap]) -> Result<(), capctl::Error> {
    let capset = !CapSet::from_iter(needed.iter().cloned());
    capctl::ambient::clear()?;
    let mut current = CapState::get_current()?;
    current.permitted -= capset;
    current.inheritable.clear();
    current.effective.clear();
    current.set_current()?;
    Ok(())
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

pub fn all_paths_from_env<P: AsRef<Path>>(env_path: &[&str], exe_name: P) -> Vec<PathBuf> {
    env_path
        .iter()
        .filter_map(|dir| {
            let full_path = Path::new(dir).join(&exe_name);
            debug!("Checking path: {:?}", full_path);
            full_path.is_file().then_some(full_path)
        })
        .collect()
}

#[cfg(feature = "finder")]
pub fn match_single_path(cmd_path: &PathBuf, role_path: &str) -> CmdMin {
    if !role_path.ends_with(cmd_path.to_str().unwrap()) || !role_path.starts_with("/") {
        // the files could not be the same
        return CmdMin::default();
    }
    let mut match_status = CmdMin::default();
    debug!("Matching path {:?} with {:?}", cmd_path, role_path);
    if cmd_path == Path::new(role_path) {
        match_status.set_matching();
    } else if cfg!(feature = "glob") {
        use glob::Pattern;
        if let Ok(pattern) = Pattern::new(role_path) {
            if pattern.matches_path(cmd_path) {
                use crate::database::score::CmdOrder;
                match_status.union_order(CmdOrder::WildcardPath);
            }
        }
    }
    if !match_status.matching() {
        debug!(
            "No match for path ``{:?}`` for evaluated path : ``{:?}``",
            cmd_path, role_path
        );
    }
    match_status
}

#[cfg(debug_assertions)]
pub fn subsribe(_: &str) -> io::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .format_module_path(true)
        .init();
    Ok(())
}

#[cfg(not(debug_assertions))]
pub fn subsribe(tool: &str) -> io::Result<()> {
    use log::LevelFilter;
    use syslog::Facility;
    syslog::init(Facility::LOG_AUTH, LevelFilter::Info, Some(tool)).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to connect to syslog: {}", e),
        )
    })?;
    Ok(())
}

pub fn drop_effective() -> Result<(), capctl::Error> {
    stated_drop_effective(CapState::get_current()?)
}

pub fn stated_drop_effective(mut current: CapState) -> Result<(), capctl::Error> {
    current.effective.clear();
    current.set_current()
}

pub fn initialize_capabilities(cap: &[Cap]) -> Result<CapState, capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.add_all(cap.iter().cloned());
    current
        .set_current()
        .inspect_err(|e| debug!("initialize_capabilities error: {}", e))?;
    Ok(current)
}

pub fn with_privileges<F, R>(cap: &[Cap], f: F) -> std::io::Result<R>
where
    F: FnOnce() -> std::io::Result<R>,
{
    let state = initialize_capabilities(cap)?;
    let res = f();
    stated_drop_effective(state)?;
    res
}

pub fn has_privileges(cap: &[Cap]) -> Result<bool, capctl::Error> {
    let current = CapState::get_current()?;
    Ok(cap.iter().all(|c| current.permitted.has(*c)))
}

pub fn activates_no_new_privs() -> Result<(), capctl::Error> {
    prctl::set_no_new_privs()
}

pub fn write_json_config<T: Serialize>(settings: &T, file: &mut impl Write) -> std::io::Result<()> {
    serde_json::to_writer_pretty(file, &settings)?;
    Ok(())
}

pub fn write_cbor_config<T: Serialize>(settings: &T, file: &mut impl Write) -> std::io::Result<()> {
    cbor4ii::serde::to_writer(file, &settings)
        .map_err(|e| std::io::Error::other(format!("Failed to write cbor config: {}", e)))
}

pub fn create_with_privileges<P: AsRef<Path>>(p: P) -> std::io::Result<File> {
    std::fs::File::create(&p).or_else(|e| {
        if e.kind() != std::io::ErrorKind::PermissionDenied {
            return Err(e);
        }
        with_privileges(&[Cap::DAC_OVERRIDE], || std::fs::File::create(p))
    })
}

pub fn open_lock_with_privileges<P: AsRef<Path>>(
    p: P,
    options: OpenOptions,
    lock: FlockArg,
) -> std::io::Result<Flock<File>> {
    options
        .open(&p)
        .or_else(|e| {
            if e.kind() != std::io::ErrorKind::PermissionDenied {
                return Err(e);
            }
            debug!(
                "Permission denied while opening {} file, retrying with privileges",
                p.as_ref().display()
            );
            with_privileges(&[Cap::DAC_READ_SEARCH], || options.open(&p)).or_else(|e| {
                if e.kind() != std::io::ErrorKind::PermissionDenied {
                    return Err(e);
                }
                with_privileges(&[Cap::DAC_OVERRIDE], || options.open(&p))
            })
        })
        .and_then(|file| Ok(nix::fcntl::Flock::lock(file, lock).map_err(|(_, e)| e)?))
}

pub fn read_with_privileges<P: AsRef<Path>>(p: P) -> std::io::Result<File> {
    debug!("Opening file {:?}", p.as_ref());
    std::fs::File::open(&p).or_else(|e| {
        if e.kind() != std::io::ErrorKind::PermissionDenied {
            return Err(e);
        }
        debug!(
            "Permission denied while opening {} file, retrying with privileges",
            p.as_ref().display()
        );
        with_privileges(&[Cap::DAC_READ_SEARCH], || std::fs::File::open(&p)).or_else(|e| {
            if e.kind() != std::io::ErrorKind::PermissionDenied {
                return Err(e);
            }
            with_privileges(&[Cap::DAC_OVERRIDE], || std::fs::File::open(&p))
        })
    })
}

pub fn remove_with_privileges<P: AsRef<Path>>(p: P) -> std::io::Result<()> {
    std::fs::remove_file(&p).or_else(|e| {
        if e.kind() != std::io::ErrorKind::PermissionDenied {
            return Err(e);
        }
        debug!(
            "Permission denied while removing {} file, retrying with privileges",
            p.as_ref().display()
        );
        with_privileges(&[Cap::DAC_OVERRIDE], || std::fs::remove_file(&p))
    })
}

pub fn create_dir_all_with_privileges<P: AsRef<Path>>(p: P) -> std::io::Result<()> {
    std::fs::create_dir_all(&p).or_else(|e| {
        if e.kind() != std::io::ErrorKind::PermissionDenied {
            return Err(e);
        }
        debug!(
            "Permission denied while creating {} directory, retrying with privileges",
            p.as_ref().display()
        );
        with_privileges(&[Cap::DAC_OVERRIDE], || std::fs::create_dir_all(p))
    })
}

#[cfg(test)]
mod test {
    use std::{
        fs,
        io::{ErrorKind, Write},
    };

    use super::*;

    pub struct Defer<F: FnOnce()>(Option<F>);

    impl<F: FnOnce()> Defer<F> {
        pub fn new(f: F) -> Self {
            Defer(Some(f))
        }
    }

    impl<F: FnOnce()> Drop for Defer<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f();
            }
        }
    }

    pub fn defer<F: FnOnce()>(f: F) -> Defer<F> {
        Defer::new(f)
    }

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
    fn test_with_mutable_config() {
        let current = CapState::get_current().expect("Failed to get current capabilities");
        if !current.permitted.has(Cap::LINUX_IMMUTABLE) {
            eprintln!("Skipping test, requires CAP_LINUX_IMMUTABLE");
            return;
        }
        let path = PathBuf::from("/tmp/rar_test_lock_config.lock");
        let mut file = File::create(&path).expect("Failed to create file");
        let _defer = defer(|| {
            if fs::remove_file(&path).is_err() {
                // remove the immutable flag if set
                with_privileges(&[Cap::LINUX_IMMUTABLE], || {
                    let file = File::open(&path).expect("Failed to open file");
                    let mut val = 0;
                    if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut val) } < 0
                    {
                        eprintln!("Failed to get flags");
                        return Err(std::io::Error::last_os_error());
                    }
                    if val & FS_IMMUTABLE_FL != 0 {
                        val &= !(FS_IMMUTABLE_FL);
                        immutable_required_privileges(&file, || {
                            if unsafe {
                                nix::libc::ioctl(file.as_raw_fd(), FS_IOC_SETFLAGS, &mut val)
                            } < 0
                            {
                                eprintln!("Failed to remove immutable flag");
                            }
                            Ok(())
                        })
                        .ok();
                    }
                    fs::remove_file(&path)
                })
                .unwrap();
            }
        });
        assert!(with_privileges(&[Cap::LINUX_IMMUTABLE], || {
            let mut val = 0;
            assert!(unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut val) } == 0);
            val |= FS_IMMUTABLE_FL;
            immutable_required_privileges(&file, || {
                if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_SETFLAGS, &mut val) } < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
        })
        .and_then(|_| {
            assert_eq!(
                File::create(&path).unwrap_err().kind(),
                ErrorKind::PermissionDenied
            );
            with_mutable_config(&mut file, |file| {
                file.write_all(b"Test content")?;
                Ok(())
            })
        })
        .is_ok());
    }

    #[test]
    fn test_convert_string_to_duration() {
        let duration = convert_string_to_duration("01:30:00");
        assert!(duration.is_ok());
        assert_eq!(
            duration.unwrap(),
            Some(Duration::hours(1) + Duration::minutes(30))
        );
        let invalid_duration = convert_string_to_duration("invalid");
        assert!(invalid_duration.is_err());
    }
}
