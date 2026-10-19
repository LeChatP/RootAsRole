use core::fmt;
use std::{
    fmt::Display,
    fs::{File, OpenOptions},
    io::{self, ErrorKind, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    str::FromStr,
};

use capctl::{Cap, CapSet, ParseCapError};
use capctl::{CapState, prctl};

use jiff::SignedDuration;
use konst::{eq_str, iter, result, string};
use libc::{FS_IOC_GETFLAGS, FS_IOC_SETFLAGS};
use log::{debug, error, warn};
use nix::{
    fcntl::{Flock, FlockArg},
    unistd::{Gid, Group},
};
use serde::{Deserialize, Serialize};

use crate::database::options::{
    EnvBehavior, PathBehavior, SAuthentication, SBounding, SInfo, SPrivileged, SUMask,
    TimestampType, WorkdirBehavior,
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
pub const HARDENED_ENUM_VALUE_0: u32 = 0x052a_2925; // 0101001010100010100100100101
pub const HARDENED_ENUM_VALUE_1: u32 = 0x0ad5_d6da; // 1010110101011101011011011010
pub const HARDENED_ENUM_VALUE_2: u32 = 0x69d6_1fc8; // 1101001110101100001111111001000
pub const HARDENED_ENUM_VALUE_3: u32 = 0x1629_e037; // 0010110001010011110000000110111
pub const HARDENED_ENUM_VALUE_4: u32 = 0x1fc8_d3ac; // 11111110010001101001110101100

#[cfg(not(test))]
pub(super) const RAR_CFG_PATH: &str = env!("RAR_CFG_PATH");
#[cfg(test)]
pub(super) const RAR_CFG_PATH: &str = "target/rootasrole.json";

#[cfg(not(test))]
pub const RAR_CFG_DATA_PATH: &str = env!("RAR_CFG_DATA_PATH");
#[cfg(test)]
pub const RAR_CFG_DATA_PATH: &str = "target/rootasrole.json";

#[cfg(debug_assertions)]
pub(super) const RAR_CFG_IMMUTABLE: bool = false;
#[cfg(not(debug_assertions))]
pub(super) const RAR_CFG_IMMUTABLE: bool = eq_str(env!("RAR_CFG_IMMUTABLE"), "true");

pub const RAR_CFG_TYPE: StorageMethod = StorageMethod::const_parse(env!("RAR_CFG_TYPE"));

pub const ENV_PATH_BEHAVIOR: PathBehavior = PathBehavior::const_parse(env!("RAR_PATH_DEFAULT"));

pub const ENV_PATH_ADD_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_PATH_ADD_LIST"), ":"),
        map(str::trim_ascii),
);

pub const ENV_PATH_REMOVE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_PATH_REMOVE_LIST"), ":"),
        map(str::trim_ascii),
);

//=== ENV ===
pub const ENV_DEFAULT_BEHAVIOR: EnvBehavior = EnvBehavior::const_parse(env!("RAR_ENV_DEFAULT"));

pub const ENV_KEEP_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_KEEP_LIST"), ","),
        map(str::trim_ascii),
);

pub const ENV_CHECK_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_CHECK_LIST"), ","),
        map(str::trim_ascii),
);

pub const ENV_DELETE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_DELETE_LIST"), ","),
        map(str::trim_ascii),
);

pub const ENV_SET_LIST_SLICE: &[(&str, &str)] = &iter::collect_const!((&str, &str) =>
    string::split(env!("RAR_ENV_SET_LIST"), "\n"),
        filter_map(|s| {
            if string::trim_matches(s, ' ').is_empty() {
                None
            } else if let Some((key,value)) = string::split_once(s, '=') {
                Some((str::trim_ascii(key),str::trim_ascii(value)))
            } else {
                panic!("Invalid ENV_SET_LIST entry, must be in the form KEY=VALUE");
            }
        })
);

pub const ENV_OVERRIDE_BEHAVIOR: bool = result::unwrap_or!(
    konst::primitive::parse_bool(env!("RAR_ENV_OVERRIDE_BEHAVIOR")),
    false
);

pub static ENV_KEEP_LIST: &[&str; ENV_KEEP_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(ENV_KEEP_LIST_SLICE));

pub static ENV_CHECK_LIST: &[&str; ENV_CHECK_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(ENV_CHECK_LIST_SLICE));

pub static ENV_DELETE_LIST: &[&str; ENV_DELETE_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(ENV_DELETE_LIST_SLICE));

pub static ENV_SET_LIST: &[(&str, &str); ENV_SET_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(ENV_SET_LIST_SLICE));

//=== STimeout ===

pub const TIMEOUT_TYPE: TimestampType = TimestampType::const_parse(env!("RAR_TIMEOUT_TYPE"));

pub const TIMEOUT_DURATION: Option<jiff::SignedDuration> = match option_env!("RAR_TIMEOUT_DURATION")
{
    Some(s) => match convert_string_to_duration(s) {
        Ok(d) => Some(d),
        Err(_) => None,
    },
    None => None,
};

pub const TIMEOUT_MAX_USAGE: Option<u64> = match option_env!("RAR_TIMEOUT_MAX_USAGE") {
    Some(s) => match u64::from_str_radix(s, 10) {
        Ok(n) => Some(n),
        Err(_) => None,
    },
    None => None,
};

pub const WORKDIR_BEHAVIOR: WorkdirBehavior =
    assert_valid_workdir_behavior(WorkdirBehavior::const_parse(env!("RAR_WORKDIR_BEHAVIOR")));

const fn assert_valid_workdir_behavior(e: WorkdirBehavior) -> WorkdirBehavior {
    match e {
        WorkdirBehavior::Inherit => panic!("Workdir behavior cannot be inherit"),
        e => e,
    }
}

pub const WORKDIR_FALLBACK: Option<&str> = option_env!("RAR_WORKDIR_FALLBACK");

pub const WORKDIR_ADD_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_WORKDIR_ADD_LIST"), ","),
        map(str::trim_ascii),
);

pub const WORKDIR_REMOVE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_WORKDIR_REMOVE_LIST"), ","),
        map(str::trim_ascii),
);

pub static WORKDIR_ADD_LIST: &[&str; WORKDIR_ADD_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(WORKDIR_ADD_LIST_SLICE));

pub static WORKDIR_REMOVE_LIST: &[&str; WORKDIR_REMOVE_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(WORKDIR_REMOVE_LIST_SLICE));

pub const BOUNDING: SBounding = SBounding::const_parse(env!("RAR_BOUNDING"));

pub const AUTHENTICATION: SAuthentication =
    SAuthentication::const_parse(env!("RAR_AUTHENTICATION"));

pub const PRIVILEGED: SPrivileged = SPrivileged::const_parse(env!("RAR_USER_CONSIDERED"));

pub const UMASK: SUMask = SUMask(result::unwrap_or!(
    u16::from_str_radix(env!("RAR_UMASK"), 10),
    0o022
));

pub const INFO: SInfo = SInfo::const_parse(env!("RAR_EXEC_INFO_DISPLAY"));

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Copy)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum StorageMethod {
    JSON,
    CBOR,
    //    SQLite,
    //    PostgreSQL,
    //    MySQL,
}

impl Default for StorageMethod {
    fn default() -> Self {
        RAR_CFG_TYPE
    }
}

impl StorageMethod {
    pub const VARIANTS: &'static [&str] = &["cbor", "json"];
    /// # Panics
    /// Panics if the string does not correspond to a valid storage method.
    #[must_use]
    pub const fn const_parse(s: &str) -> Self {
        match s {
            _ if eq_str(s, "cbor") | eq_str(s, "CBOR") => Self::CBOR,
            _ if eq_str(s, "json") | eq_str(s, "JSON") => Self::JSON,
            _ => panic!("fail to parse StorageMethod from string: invalid value"),
        }
    }

    #[must_use]
    pub const fn is_cbor(&self) -> bool {
        matches!(self, Self::CBOR)
    }
    #[must_use]
    pub const fn is_json(&self) -> bool {
        matches!(self, Self::JSON)
    }
}

impl Display for StorageMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CBOR => write!(f, "cbor"),
            Self::JSON => write!(f, "json"),
        }
    }
}

impl FromStr for StorageMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cbor" => Ok(Self::CBOR),
            "json" => Ok(Self::JSON),
            _ => Err(format!("Invalid StorageMethod value: {s}")),
        }
    }
}

/// `Either` is a type that represents either type A ([`Left`]) or type B ([`Right`]).
#[derive(Debug, Hash, Copy, Clone)]
#[must_use]
pub enum Either<L, R> {
    /// Contains the Left value
    Left(L),
    /// Contains the Right value
    Right(R),
}
impl<L, R> Either<L, R> {
    pub const fn left(&self) -> Option<&L> {
        match self {
            Self::Left(l) => Some(l),
            Self::Right(_) => None,
        }
    }
    pub const fn right(&self) -> Option<&R> {
        match self {
            Self::Left(_) => None,
            Self::Right(r) => Some(r),
        }
    }
    pub fn map<T>(&self, left: impl Fn(&L) -> T, right: impl Fn(&R) -> T) -> T {
        match self {
            Self::Left(l) => left(l),
            Self::Right(r) => right(r),
        }
    }
}

impl<L, R> From<Result<L, R>> for Either<L, R> {
    fn from(value: Result<L, R>) -> Self {
        match value {
            Ok(l) => Self::Left(l),
            Err(r) => Self::Right(r),
        }
    }
}

#[must_use]
pub fn either_to_gid(either: &Either<Group, Gid>) -> Gid {
    either.map(|l| l.gid, |r| *r)
}

#[derive(Debug)]
struct DurationParseError;
impl std::fmt::Display for DurationParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid duration format")
    }
}

const fn convert_string_to_duration(s: &str) -> Result<SignedDuration, DurationParseError> {
    let mut parts = string::split(s, ':');
    let Some(hours) = parts.next() else {
        return Err(DurationParseError);
    };
    let Some(minutes) = parts.next() else {
        return Err(DurationParseError);
    };
    let Some(seconds) = parts.next() else {
        return Err(DurationParseError);
    };

    let hours: i64 = if let Ok(hours) = i64::from_str_radix(hours, 10) {
        hours
    } else {
        return Err(DurationParseError);
    };
    let minutes: i64 = if let Ok(minutes) = i64::from_str_radix(minutes, 10) {
        minutes
    } else {
        return Err(DurationParseError);
    };
    let seconds: i64 = if let Ok(seconds) = i64::from_str_radix(seconds, 10) {
        seconds
    } else {
        return Err(DurationParseError);
    };
    Ok(SignedDuration::from_secs(
        hours * 3600 + minutes * 60 + seconds,
    ))
}

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

const FS_IMMUTABLE_FL: u32 = 0x0000_0010;

/// # Errors
/// Returns an error if the internal function fails, or if the file
pub fn immutable_required_privileges<F, R>(file: &File, f: F) -> std::io::Result<R>
where
    F: FnOnce() -> std::io::Result<R>,
{
    let metadata = file.metadata()?;
    let uid = metadata.uid();
    let effective_uid = nix::unistd::Uid::effective();

    // Changing the flags of a file requires to own it or CAP_FOWNER, its group does not matter
    let caps = if effective_uid == nix::unistd::Uid::from_raw(uid) {
        vec![Cap::LINUX_IMMUTABLE]
    } else {
        vec![Cap::LINUX_IMMUTABLE, Cap::FOWNER, Cap::DAC_OVERRIDE]
    };
    with_privileges(&caps, f)
}

pub(crate) fn is_immutable(file: &File) -> std::io::Result<bool> {
    let mut val = 0;
    // SAFETY: FS_IOC_GETFLAGS writes an int through the pointer, `val` is a valid and writable u32
    if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(val & FS_IMMUTABLE_FL != 0)
}

/// Perform a writing operation on a writable opened file descriptor with the immutable flag set
/// The function will temporarily remove the immutable flag, perform the operation and set it back
/// # Errors
/// Returns an error if the file cannot be unlocked, if the operation fails, or if the file cannot be locked again
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

/// # Errors
/// Returns an error if the file cannot be locked
pub fn lock_immutable(file: &mut File, mut val: u32) -> Result<(), io::Error> {
    immutable_required_privileges(file, || {
        // SAFETY: FS_IOC_SETFLAGS reads an int through the pointer, `val` is a valid u32
        if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_SETFLAGS, &mut val) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    })?;
    Ok(())
}

/// # Errors
/// Returns an error if the file cannot be unlocked
pub fn unlock_immutable(file: &mut File) -> Result<u32, io::Error> {
    let mut val = 0;
    // SAFETY: FS_IOC_GETFLAGS writes an int through the pointer, `val` is a valid and writable u32
    if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if val & FS_IMMUTABLE_FL != 0 {
        val &= !(FS_IMMUTABLE_FL);
        immutable_required_privileges(file, || {
            // SAFETY: FS_IOC_SETFLAGS reads an int through the pointer, `val` is a valid u32
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

/// # Errors
/// Returns an error if the file cannot be checked for immutability, or if the file is not immutable and `return_err` is true
pub fn warn_if_mutable(file: &File, return_err: bool) -> std::io::Result<()> {
    let mut val = 0;
    let fd = file.as_raw_fd();
    // SAFETY: FS_IOC_GETFLAGS writes an int through the pointer, `val` is a valid and writable u32
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

/// Parse string iterator to capset
/// # Errors
/// Returns an error if any of the strings cannot be parsed to a valid capability
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
#[must_use]
pub fn capabilities_are_exploitable(caps: CapSet) -> bool {
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

#[must_use]
pub fn optimized_serialize_capset(capset: &CapSet) -> u64 {
    // convert capset to u64
    let bits: u64 = capset.iter().fold(0, |acc, cap| acc | (1 << (cap as u64)));
    bits
}

/// # Errors
/// Returns an error if any of the bits in the u64 do not correspond to a valid system capability
/// Or if dropping any of the capabilities is not permitted by the current capability state
pub fn definitive_drop(needed: &[Cap]) -> Result<(), capctl::Error> {
    let capset = !needed.iter().copied().collect::<CapSet>();
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

/// Whether `s` is a valid environment variable name: `[A-Za-z_][A-Za-z0-9_]*`.
#[must_use]
pub fn is_valid_env_name(s: &str) -> bool {
    s.bytes()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// Whether `s` is a valid environment variable pattern: a variable name in which `*` may
/// stand for any sequence of characters (e.g. `LC_*`, `*_PROXY`, `*`).
#[must_use]
pub fn is_valid_env_pattern(s: &str) -> bool {
    s.bytes()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_' || c == b'*')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'*')
}

/// Whether `subject` matches `pattern`, where `*` matches any sequence of characters,
/// including an empty one. No other character is special.
#[must_use]
pub fn wildcard_match(pattern: &str, subject: &str) -> bool {
    let (pattern, subject) = (pattern.as_bytes(), subject.as_bytes());
    let (mut p, mut s) = (0, 0);
    // position in the pattern after the last `*`, and the subject position it matched from
    let mut backtrack = None;
    while s < subject.len() {
        if pattern.get(p) == Some(&b'*') {
            p += 1;
            backtrack = Some((p, s));
        } else if pattern.get(p) == Some(&subject[s]) {
            p += 1;
            s += 1;
        } else if let Some((star_p, star_s)) = backtrack {
            // let the last `*` match one more character
            p = star_p;
            s = star_s + 1;
            backtrack = Some((star_p, s));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// Whether a value of the user's environment is a shell function definition (`() { ...; }`).
///
/// Such a value is never passed to a command, whatever the policy lists say. Bash exports its
/// functions as variables whose value starts with `()` (`BASH_FUNC_name%%`), and every bash run
/// by the command imports them: a kept function could replace a command used by a script that
/// runs with the task's privileges. The lists of the policy select variables by name, this rule
/// applies to their value.
#[must_use]
pub fn is_shell_function(value: &str) -> bool {
    value.starts_with("()")
}

/// Refuse a policy file that other users can write, or that is in a directory they can write.
///
/// Policy files decide who may run what. A warning is logged when other users can read it.
/// The owner is not checked: in `RootAsRole`, root is not trusted more than any other account.
/// # Errors
/// Returns `PermissionDenied` when other users can write the file or its directory,
/// or an error if the metadata cannot be read.
pub fn check_others_permissions(path: &Path, file: &File) -> io::Result<()> {
    const OTHERS_READ: u32 = 0o004;
    const OTHERS_WRITE: u32 = 0o002;
    let writable = |what: &Path| {
        let message = format!(
            "{} is writable by other users, refusing to use it",
            what.display()
        );
        error!("{message}");
        io::Error::new(ErrorKind::PermissionDenied, message)
    };
    let mode = file.metadata()?.mode();
    if mode & OTHERS_WRITE != 0 {
        return Err(writable(path));
    }
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let dir_mode = std::fs::metadata(dir)
        .or_else(|e| {
            if e.kind() != ErrorKind::PermissionDenied {
                return Err(e);
            }
            with_privileges(&[Cap::DAC_READ_SEARCH], || std::fs::metadata(dir))
        })?
        .mode();
    if dir_mode & OTHERS_WRITE != 0 {
        return Err(writable(dir));
    }
    if mode & OTHERS_READ != 0 {
        warn!(
            "{} is readable by other users, consider `chmod o-r` on it",
            path.display()
        );
    }
    Ok(())
}

/// Refuse a policy file without the immutable flag, when the policy is declared immutable.
///
/// Owner and mode are not enough: uid 0 without any capability still owns `/etc/security` and
/// could add a policy file. Setting the flag requires `CAP_LINUX_IMMUTABLE`, which chsr has.
/// # Errors
/// Returns `PermissionDenied` when the flag is not set, or an error if the flags cannot be read.
pub fn check_immutable(path: &Path, file: &File) -> io::Result<()> {
    if is_immutable(file)? {
        return Ok(());
    }
    let message = format!(
        "{} is not immutable, refusing to use it: write it with chsr or set its immutable flag",
        path.display()
    );
    error!("{message}");
    Err(io::Error::new(ErrorKind::PermissionDenied, message))
}

/// Run `f`, which adds or removes a file in `dir`, with the immutable flag of `dir` lifted.
///
/// An immutable directory accepts no new entry. Nothing is lifted when `dir` has no flag, or
/// when its filesystem has no flags at all.
/// # Errors
/// Returns an error if the flag cannot be lifted or set back, or the error of `f`.
pub fn with_mutable_dir<F, R>(dir: &Path, f: F) -> io::Result<R>
where
    F: FnOnce() -> io::Result<R>,
{
    let Ok(mut dir_file) = File::open(dir) else {
        return f();
    };
    if !is_immutable(&dir_file).unwrap_or(false) {
        return f();
    }
    let val = unlock_immutable(&mut dir_file)?;
    let res = f();
    lock_immutable(&mut dir_file, val | FS_IMMUTABLE_FL)?;
    res
}

/// Candidates for `exe_name` in the directories of `env_path`.
/// Relative directories (`.`, empty entries…) are ignored: they would make the result depend
/// on the current directory, which the user controls.
pub fn all_paths_from_env<P: AsRef<Path>>(env_path: &[&str], exe_name: P) -> Vec<PathBuf> {
    env_path
        .iter()
        .filter(|dir| Path::new(dir).is_absolute())
        .filter_map(|dir| {
            let full_path = Path::new(dir).join(&exe_name);
            debug!("Checking path: {}", full_path.display());
            full_path.is_file().then_some(full_path)
        })
        .collect()
}

/// Whether the command `cmd_path` matches the path `role_path` of the policy.
///
/// `role_path` must be absolute. With the `glob` feature, it can be a pattern (globset syntax): `*`, `?`
/// and `[...]` match within one path component, `**` across components, `{a,b}` is an
/// alternative. A command path with a `.` or `..` component never matches a pattern, as
/// `/usr/bin/**` would otherwise match `/usr/bin/../../tmp/x`.
#[cfg(feature = "finder")]
#[must_use]
pub fn match_single_path(cmd_path: &Path, role_path: &str) -> CmdMin {
    let mut match_status = CmdMin::default();
    if !role_path.starts_with('/') {
        return match_status;
    }
    debug!("Matching path {} with {role_path:?}", cmd_path.display());
    if cmd_path == Path::new(role_path) {
        match_status.set_matching();
    } else {
        #[cfg(feature = "glob")]
        if glob_matches(role_path, cmd_path) {
            use crate::database::score::CmdOrder;
            match_status.set_matching();
            match_status.union_order(CmdOrder::WildcardPath);
        }
    }
    if !match_status.matching() {
        debug!(
            "No match for path ``{}`` for evaluated path : ``{role_path:?}``",
            cmd_path.display()
        );
    }
    match_status
}

#[cfg(all(feature = "finder", feature = "glob"))]
fn glob_matches(pattern: &str, path: &Path) -> bool {
    use std::path::Component;
    let normal = path
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    normal
        && globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .inspect_err(|e| debug!("Invalid path pattern {pattern:?}: {e}"))
            .is_ok_and(|glob| glob.compile_matcher().is_match(path))
}

/// # Errors
/// Returns an error if dropping the effective capabilities fails
pub fn drop_effective() -> Result<(), capctl::Error> {
    stated_drop_effective(CapState::get_current()?)
}

/// # Errors
/// Returns an error if dropping the effective capabilities fails
pub fn stated_drop_effective(mut current: CapState) -> Result<(), capctl::Error> {
    current.effective.clear();
    current.set_current()
}

/// # Errors
/// Returns an error if obtaining the current capability state fails
pub fn initialize_capabilities(cap: &[Cap]) -> Result<CapState, capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.add_all(cap.iter().copied());
    current
        .set_current()
        .inspect_err(|e| debug!("initialize_capabilities error: {e}"))?;
    Ok(current)
}

/// Temporarily add capabilities to the effective set to perform an operation, then drop them again
/// # Errors
/// Returns an error if obtaining the current capability state fails,
/// if adding the capabilities to the effective set fails,
/// if setting the new capability state fails,
/// if the operation fails,
/// or if dropping the effective capabilities at the end
pub fn with_privileges<F, R>(cap: &[Cap], f: F) -> std::io::Result<R>
where
    F: FnOnce() -> std::io::Result<R>,
{
    let state = initialize_capabilities(cap)?;
    let res = f();
    stated_drop_effective(state)?;
    res
}

/// # Errors
/// Returns an error if getting the capabilities state fails
pub fn has_privileges(cap: &[Cap]) -> Result<bool, capctl::Error> {
    let current = CapState::get_current()?;
    Ok(cap.iter().all(|c| current.permitted.has(*c)))
}

/// # Errors
/// Returns an error if setting ``no_new_privs`` fails
pub fn activates_no_new_privs() -> Result<(), capctl::Error> {
    prctl::set_no_new_privs()
}

/// # Errors
/// Returns an error if the internal write operation fails
pub fn write_config<T: Serialize>(
    settings: &T,
    file: &mut impl Write,
    method: StorageMethod,
) -> std::io::Result<()> {
    match method {
        StorageMethod::JSON => write_json_config(settings, file),
        StorageMethod::CBOR => write_cbor_config(settings, file),
    }
}

/// # Errors
/// Returns an error if the internal write operation fails
fn write_json_config<T: Serialize>(settings: &T, file: &mut impl Write) -> std::io::Result<()> {
    serde_json::to_writer_pretty(file, &settings)?;
    Ok(())
}

/// # Errors
/// Returns an error if the internal write operation fails
fn write_cbor_config<T: Serialize>(settings: &T, file: &mut impl Write) -> std::io::Result<()> {
    cbor4ii::serde::to_writer(file, &settings)
        .map_err(|e| std::io::Error::other(format!("Failed to write cbor config: {e}")))
}

/// # Errors
/// Returns an error if the file cannot be created with the required privileges
#[deprecated(
    since = "4.0.3",
    note = "follows symbolic links with CAP_DAC_OVERRIDE: open the file relative to a checked directory with O_NOFOLLOW instead"
)]
pub fn create_with_privileges<P: AsRef<Path>>(p: P) -> std::io::Result<File> {
    std::fs::File::create(&p).or_else(|e| {
        if e.kind() != std::io::ErrorKind::PermissionDenied {
            return Err(e);
        }
        with_privileges(&[Cap::DAC_OVERRIDE], || std::fs::File::create(p))
    })
}

/// # Errors
/// Returns an error if the file cannot be opened with the required privileges,
/// or if locking the file fails
pub fn open_lock_with_privileges<P: AsRef<Path>>(
    p: P,
    options: &OpenOptions,
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

/// # Errors
/// Returns an error if the file cannot be opened with the required privileges
pub fn read_with_privileges<P: AsRef<Path>>(p: P) -> std::io::Result<File> {
    debug!("Opening file {}", p.as_ref().display());
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

/// # Errors
/// Returns an error if the process does not have the required privileges to remove the file
/// or if the internal remove operation fails
#[deprecated(
    since = "4.0.3",
    note = "follows symbolic links with CAP_DAC_OVERRIDE: open the file relative to a checked directory with O_NOFOLLOW instead"
)]
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

/// # Errors
/// Returns an error if the process does not have the required privileges to create the directories
#[deprecated(
    since = "4.0.3",
    note = "follows symbolic links with CAP_DAC_OVERRIDE: open the file relative to a checked directory with O_NOFOLLOW instead"
)]
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

#[allow(clippy::undocumented_unsafe_blocks)]
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
            Self(Some(f))
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
    fn test_wildcard_match() {
        assert!(wildcard_match("LC_*", "LC_ALL"));
        assert!(wildcard_match("LC_*", "LC_"));
        assert!(!wildcard_match("LC_*", "LC"));
        assert!(wildcard_match("*_PROXY", "HTTPS_PROXY"));
        assert!(wildcard_match("XDG_*_DIR", "XDG_CONFIG_DIR"));
        assert!(!wildcard_match("XDG_*_DIR", "XDG_CONFIG_DIRS"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("A*B*C", "AxxBxxBxxC"));
        assert!(!wildcard_match("A*B*C", "AxxBxx"));
        assert!(wildcard_match("HOME", "HOME"));
        assert!(!wildcard_match("HOME", "HOMES"));
        // no other character is special
        assert!(!wildcard_match("LC_.*", "LC_ALL"));
        assert!(wildcard_match("LC_.*", "LC_.ALL"));
    }

    #[cfg(feature = "finder")]
    #[test]
    fn test_match_single_path() {
        let matches = |cmd: &str, role: &str| match_single_path(Path::new(cmd), role);
        // exact path
        let exact = matches("/usr/bin/ls", "/usr/bin/ls");
        assert!(exact.matching());
        assert!(exact.order.is_empty());
        assert!(!matches("/usr/bin/ls", "/usr/bin/cat").matching());
        // the policy path must be absolute
        assert!(!matches("/usr/bin/ls", "usr/bin/ls").matching());
        assert!(!matches("ls", "ls").matching());
    }

    #[cfg(all(feature = "finder", feature = "glob"))]
    #[test]
    fn test_match_single_path_patterns() {
        use crate::database::score::CmdOrder;
        let matches = |cmd: &str, role: &str| match_single_path(Path::new(cmd), role).matching();
        let wildcard = match_single_path(Path::new("/usr/bin/ls"), "/usr/bin/*");
        assert!(wildcard.matching());
        assert_eq!(wildcard.order, CmdOrder::WildcardPath);
        // `*` stays within one component, `**` crosses them
        assert!(!matches("/usr/bin/x/ls", "/usr/bin/*"));
        assert!(matches("/usr/bin/x/ls", "/usr/bin/**"));
        assert!(matches("/usr/bin/python3.12", "/usr/bin/python3.*"));
        assert!(matches("/usr/bin/cat", "/usr/bin/{ls,cat}"));
        assert!(!matches("/usr/bin/rm", "/usr/bin/{ls,cat}"));
        // a command path with `..` or `.` never matches a pattern
        assert!(!matches("/usr/bin/../../tmp/evil", "/usr/bin/**"));
        assert!(!matches("/usr/bin/./ls", "/usr/bin/*"));
        // an invalid pattern matches nothing
        assert!(!matches("/usr/bin/ls", "/usr/bin/[ls"));
    }

    #[test]
    fn test_is_shell_function() {
        assert!(is_shell_function("() { evil; }"));
        assert!(is_shell_function("()"));
        assert!(!is_shell_function(" () { evil; }"));
        assert!(!is_shell_function("value ()"));
        assert!(!is_shell_function(""));
    }

    #[test]
    fn test_env_name_and_pattern() {
        assert!(is_valid_env_name("_A1"));
        assert!(!is_valid_env_name("1A"));
        assert!(!is_valid_env_name("A*"));
        assert!(!is_valid_env_name(""));
        assert!(is_valid_env_pattern("A*"));
        assert!(is_valid_env_pattern("*"));
        assert!(is_valid_env_pattern("*_PROXY"));
        assert!(!is_valid_env_pattern("LC_.*"));
        assert!(!is_valid_env_pattern("A|B"));
        assert!(!is_valid_env_pattern("1*"));
        assert!(!is_valid_env_pattern(""));
    }

    #[test]
    fn test_default_keep_list_has_the_x_authority_file() {
        // X11 clients find their cookie through XAUTHORITY
        assert!(ENV_KEEP_LIST_SLICE.contains(&"XAUTHORITY"));
        assert!(!ENV_KEEP_LIST_SLICE.contains(&"XAUTHORY"));
    }

    #[test]
    fn test_check_others_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let set_mode = |path: &Path, mode: u32| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };
        let dir = std::env::temp_dir().join(format!("rar_check_others_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        set_mode(&dir, 0o755);
        let path = dir.join("policy.json");
        fs::write(&path, "{}").unwrap();
        let check = |path: &Path| check_others_permissions(path, &File::open(path).unwrap());

        set_mode(&path, 0o600);
        assert!(check(&path).is_ok());
        // readable by others: only a warning
        set_mode(&path, 0o644);
        assert!(check(&path).is_ok());
        // writable by others: refused
        set_mode(&path, 0o646);
        assert_eq!(
            check(&path).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        // directory writable by others: refused, even with the sticky bit
        set_mode(&path, 0o600);
        set_mode(&dir, 0o1777);
        assert_eq!(
            check(&path).unwrap_err().kind(),
            ErrorKind::PermissionDenied
        );
        set_mode(&dir, 0o755);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_check_immutable_refuses_a_mutable_file() {
        let dir = std::env::temp_dir().join(format!("rar_check_immutable_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let path = dir.join("planted.json");
        fs::write(&path, "{}").unwrap();
        // without CAP_LINUX_IMMUTABLE, the flag cannot be set: such a file is refused
        assert!(check_immutable(&path, &File::open(&path).unwrap()).is_err());
        // a directory without the flag is left as is
        with_mutable_dir(&dir, || fs::write(dir.join("new.json"), "{}")).unwrap();
        assert!(dir.join("new.json").is_file());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_with_mutable_dir_sets_the_flag_back() {
        let current = capctl::CapState::get_current().unwrap();
        if !current.permitted.has(Cap::LINUX_IMMUTABLE) {
            eprintln!("Skipping test, requires CAP_LINUX_IMMUTABLE");
            return;
        }
        let dir = std::env::temp_dir().join(format!("rar_mutable_dir_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let mut dir_file = File::open(&dir).unwrap();
        let Ok(flags) = unlock_immutable(&mut dir_file) else {
            eprintln!("Skipping test, the filesystem has no flags");
            return;
        };
        lock_immutable(&mut dir_file, flags | FS_IMMUTABLE_FL).unwrap();
        // no new entry in an immutable directory
        assert!(fs::write(dir.join("refused.json"), "{}").is_err());
        with_mutable_dir(&dir, || fs::write(dir.join("added.json"), "{}")).unwrap();
        assert!(dir.join("added.json").is_file());
        assert!(is_immutable(&File::open(&dir).unwrap()).unwrap());
        unlock_immutable(&mut dir_file).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_all_paths_from_env_ignores_relative_directories() {
        // the tests run in the crate directory, which contains Cargo.toml
        assert!(all_paths_from_env(&[".", "", "src/.."], "Cargo.toml").is_empty());
        let dir = std::env::current_dir().unwrap();
        assert_eq!(
            all_paths_from_env(&[".", dir.to_str().unwrap()], "Cargo.toml"),
            vec![dir.join("Cargo.toml")]
        );
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
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::SYS_PTRACE);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::SYS_MODULE);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::DAC_READ_SEARCH);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::DAC_OVERRIDE);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::FOWNER);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::CHOWN);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::SETUID);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::SETGID);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::SETFCAP);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::SYS_RAWIO);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::LINUX_IMMUTABLE);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::SYS_CHROOT);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::SYS_BOOT);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::MKNOD);
        assert!(capabilities_are_exploitable(capset));
        capset.clear();
        capset.add(Cap::WAKE_ALARM);
        assert!(!capabilities_are_exploitable(capset));
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
        assert!(
            with_privileges(&[Cap::LINUX_IMMUTABLE], || {
                let mut val = 0;
                assert!(
                    unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut val) } == 0
                );
                val |= FS_IMMUTABLE_FL;
                immutable_required_privileges(&file, || {
                    if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_SETFLAGS, &mut val) } < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                })
            })
            .and_then(|()| {
                assert_eq!(
                    File::create(&path).unwrap_err().kind(),
                    ErrorKind::PermissionDenied
                );
                with_mutable_config(&mut file, |file| {
                    file.write_all(b"Test content")?;
                    Ok(())
                })
            })
            .is_ok()
        );
    }

    #[test]
    fn test_convert_string_to_duration() {
        let duration = convert_string_to_duration("01:30:00");
        assert!(duration.is_ok());
        assert_eq!(
            duration.unwrap(),
            SignedDuration::from_hours(1) + SignedDuration::from_mins(30)
        );
        let invalid_duration = convert_string_to_duration("invalid");
        assert!(invalid_duration.is_err());
        assert!(convert_string_to_duration("01").is_err());
        assert!(convert_string_to_duration("01:30").is_err());
        assert!(convert_string_to_duration("xx:30:00").is_err());
        assert!(convert_string_to_duration("01:xx:00").is_err());
        assert!(convert_string_to_duration("01:30:xx").is_err());
    }
}
