use std::{
    error::Error,
    fs::File,
    io::{self, BufReader, Seek},
    os::fd::OwnedFd,
    path::{Component, Path, PathBuf},
};

use capctl::Cap;
use log::{debug, error, warn};
use nix::{
    errno::Errno,
    fcntl::{Flock, FlockArg, OFlag, open, openat},
    libc::dev_t,
    libc::{pid_t, uid_t},
    sys::stat::{FileStat, Mode, SFlag, fstat, mkdirat},
    time::{ClockId, clock_gettime},
    unistd::{Gid, Uid, UnlinkatFlags, getsid, setfsgid, setfsuid, unlinkat},
};
use serde::{Deserialize, Serialize};

use rootasrole_core::{
    Cred,
    database::options::{STimeout, TimestampType},
    util::with_privileges,
};

use crate::procfs;

/// This module checks the validity of a user's credentials
/// This module allow to users to not have to re-enter their password in a short period of time

#[derive(Serialize, Deserialize, Debug, Clone)]
#[repr(u8)]
enum CookieVersion {
    V2(Cookiev2) = 57,
}

/// Context in which a cookie can be reused. Processes are identified with their start time,
/// so that a recycled pid does not match (same as sudo-rs `RecordScope`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum ParentRecord {
    Tty {
        tty: dev_t,
        session: pid_t,
        session_start: u64,
    },
    Ppid {
        ppid: pid_t,
        ppid_start: u64,
        /// The session of dosr: a child of the same parent in another session (after
        /// `setsid(2)`) does not reuse the cookie. Only the id is kept: the session leader may be
        /// gone while the session lives on, without a start time to read.
        session: pid_t,
    },
    None,
}

impl ParentRecord {
    /// Returns `None` when the context cannot be determined, cookies must not be used then.
    fn new(ttype: TimestampType, user: &Cred) -> Option<Self> {
        match (ttype, user.tty) {
            (TimestampType::TTY, Some(tty)) => {
                let session = getsid(None).ok()?;
                Some(Self::Tty {
                    tty,
                    session: session.as_raw(),
                    session_start: procfs::start_time(session).ok()?,
                })
            }
            // Without a controlling terminal, fall back to the parent process like sudo-rs
            (TimestampType::TTY | TimestampType::PPID, _) => Some(Self::Ppid {
                ppid: user.ppid.as_raw(),
                ppid_start: procfs::start_time(user.ppid).ok()?,
                session: getsid(None).ok()?.as_raw(),
            }),
            (TimestampType::UID, _) => Some(Self::None),
        }
    }
}

/// Times are seconds since boot (`CLOCK_BOOTTIME`), so changes of the system clock do not affect them.
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Cookiev2 {
    timestamp_type: TimestampType,
    start_time: i64,
    timestamp: i64,
    usage: u64,
    parent_record: ParentRecord,
    auth_uid: uid_t,
}

fn boottime() -> Option<i64> {
    clock_gettime(ClockId::CLOCK_BOOTTIME)
        .ok()
        .map(|t| t.tv_sec())
}

#[cfg(not(test))]
const TS_LOCATION: &str = env!("RAR_TIMEOUT_STORAGE");
#[cfg(test)]
const TS_LOCATION: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/ts");

/// Directory from which every component of the timestamp location is checked.
/// Tests cannot rely on root-owned directories, so they start from the target directory.
#[cfg(not(test))]
const TRUSTED_ROOT: &str = "/";
#[cfg(test)]
const TRUSTED_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target");

const DIR_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
const COOKIE_FLAGS: OFlag = OFlag::O_RDWR
    .union(OFlag::O_CREAT)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// Owner of the timestamp directory and cookie files.
/// Tests cannot create root-owned files, so they use the current user instead.
fn ts_owner() -> Uid {
    if cfg!(test) {
        Uid::effective()
    } else {
        Uid::from_raw(0)
    }
}

/// Run `f` with the filesystem uid/gid of the timestamp owner, so every file or directory
/// created by `f` belongs to root from the start, without any window where the calling user owns it.
///
/// Switching the filesystem uid from non-zero to 0 makes the kernel raise the filesystem
/// capabilities of the permitted set (`CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_FOWNER`...)
/// into the effective set, and switching back clears them (see capabilities(7)).
fn as_ts_owner<F, R>(f: F) -> io::Result<R>
where
    F: FnOnce() -> io::Result<R>,
{
    let owner = ts_owner();
    if Uid::effective() == owner {
        return f();
    }
    let group = Gid::from_raw(0);
    with_privileges(&[Cap::SETUID, Cap::SETGID], || {
        let prev_uid = setfsuid(owner);
        let prev_gid = setfsgid(group);
        // setfsuid and setfsgid do not report errors, they return the previous value
        let res = if setfsuid(owner) == owner && setfsgid(group) == group {
            f()
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Failed to switch filesystem ids",
            ))
        };
        setfsgid(prev_gid);
        setfsuid(prev_uid);
        if setfsuid(prev_uid) != prev_uid || setfsgid(prev_gid) != prev_gid {
            error!("Failed to restore filesystem ids, aborting");
            std::process::abort();
        }
        res
    })
}

/// Same checks as sudo-rs `checks()` (sudo-rs/src/system/audit.rs): the entry must be of
/// the expected type, owned by root (or the timestamp owner), and not writable by anyone else.
fn is_secure(stat: &FileStat, kind: SFlag) -> bool {
    let mode = stat.st_mode;
    mode & SFlag::S_IFMT.bits() == kind.bits()
        && (stat.st_uid == 0 || stat.st_uid == ts_owner().as_raw())
        && (stat.st_gid == 0 || mode & Mode::S_IWGRP.bits() == 0)
        && mode & Mode::S_IWOTH.bits() == 0
}

/// A cookie file must also be readable by its owner only, and must not be a hard link.
fn is_secure_cookie(stat: &FileStat) -> bool {
    is_secure(stat, SFlag::S_IFREG)
        && stat.st_uid == ts_owner().as_raw()
        && stat.st_nlink == 1
        && stat.st_mode & Mode::S_IRWXG.union(Mode::S_IRWXO).bits() == 0
}

fn insecure(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{} must be owned by root and not writable by other users",
            path.display()
        ),
    )
}

/// Open the timestamp directory, creating the missing components with mode 0700.
/// Every component is opened without following symbolic links and must pass `is_secure`,
/// so the calling user cannot redirect where cookies are read or written.
/// Must be called through `as_ts_owner`.
fn open_secure_dir(location: &Path) -> io::Result<OwnedFd> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} must be an absolute path without '..'",
                location.display()
            ),
        )
    };
    let relative = location.strip_prefix(TRUSTED_ROOT).map_err(|_| invalid())?;
    let mut dir = open(TRUSTED_ROOT, DIR_FLAGS, Mode::empty())?;
    let mut current = PathBuf::from(TRUSTED_ROOT);
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(invalid());
        };
        current.push(name);
        let next = match openat(&dir, name, DIR_FLAGS, Mode::empty()) {
            // `dir` passed the checks, so only root can have created this symbolic link
            // (e.g. /var/run -> /run), the directory it points to is checked below.
            Err(Errno::ELOOP | Errno::ENOTDIR) => openat(
                &dir,
                name,
                DIR_FLAGS.difference(OFlag::O_NOFOLLOW),
                Mode::empty(),
            )?,
            Err(Errno::ENOENT) => {
                debug!("Creating {}", current.display());
                match mkdirat(&dir, name, Mode::S_IRWXU) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(e) => return Err(e.into()),
                }
                openat(&dir, name, DIR_FLAGS, Mode::empty())?
            }
            res => res?,
        };
        if !is_secure(&fstat(&next)?, SFlag::S_IFDIR) {
            return Err(insecure(&current));
        }
        dir = next;
    }
    Ok(dir)
}

/// Cookie file of a user, exclusively locked until dropped.
struct CookieFile(Flock<File>);

impl CookieFile {
    fn open(user: &Cred) -> io::Result<Self> {
        Self::open_in(Path::new(TS_LOCATION), user.user.uid)
    }

    fn open_in(location: &Path, uid: Uid) -> io::Result<Self> {
        let name = uid.as_raw().to_string();
        let mode = Mode::S_IRUSR | Mode::S_IWUSR;
        let fd = as_ts_owner(|| {
            let dir = open_secure_dir(location)?;
            let fd = openat(&dir, name.as_str(), COOKIE_FLAGS, mode)?;
            if is_secure_cookie(&fstat(&fd)?) {
                return Ok(fd);
            }
            // The directory is secure, so this file was left by a previous version,
            // which created cookie files owned by the calling user: replace it.
            warn!("Replacing insecure timestamp cookie file {name}");
            drop(fd);
            unlinkat(&dir, name.as_str(), UnlinkatFlags::NoRemoveDir)?;
            Ok(openat(
                &dir,
                name.as_str(),
                COOKIE_FLAGS | OFlag::O_EXCL,
                mode,
            )?)
        })?;
        let file = Flock::lock(File::from(fd), FlockArg::LockExclusive).map_err(|(_, e)| e)?;
        Ok(Self(file))
    }

    fn read(&mut self) -> Vec<CookieVersion> {
        cbor4ii::serde::from_reader(BufReader::new(&mut *self.0)).unwrap_or_else(|e| {
            debug!("No valid cookies found: {e}");
            Vec::new()
        })
    }

    fn write(&mut self, cookies: &[CookieVersion]) -> Result<(), Box<dyn Error>> {
        debug!("Saving cookies: {cookies:?}");
        self.0.set_len(0)?;
        self.0.rewind()?;
        cbor4ii::serde::to_writer(&mut *self.0, &cookies)?;
        Ok(())
    }
}

fn find_valid_cookie(
    cookies: &mut Vec<CookieVersion>,
    from: &Cred,
    cred_asked: &Cred,
    constraint: &STimeout,
    editcookie: fn(&mut CookieVersion),
) -> Option<CookieVersion> {
    let mut res = None;

    debug!(
        "Constraints for {} : {:?}",
        &cred_asked.user.uid.as_raw(),
        constraint
    );

    let ttype = constraint.type_field.unwrap_or_default();
    let (Some(now), Some(record)) = (boottime(), ParentRecord::new(ttype, from)) else {
        debug!("Unable to determine the timestamp context");
        return None;
    };
    let duration = constraint.duration.unwrap_or_default().as_secs(); // Span::default() is 0s

    cookies.retain_mut(|cookiev| match cookiev {
        CookieVersion::V2(cookie) => {
            debug!("Checking cookie: {cookie:?}");

            if cookie.auth_uid != cred_asked.user.uid.as_raw()
                || cookie.timestamp_type != ttype
                || cookie.parent_record != record
            {
                return true;
            }
            //let max_usage_ok = constraint.max_usage.is_none()
            //|| cookie.usage < constraint.max_usage.unwrap_or(u64::MAX);
            let max_usage_ok = constraint.max_usage.is_none()
                || cookie.usage < constraint.max_usage.unwrap_or(u64::MAX);
            debug!(
                "Max usage ok: {max_usage_ok}, usage: {}, max_usage: {:?}",
                cookie.usage, constraint.max_usage
            );

            let expires_at = cookie.timestamp.saturating_add(duration);

            // A cookie from the future was not written during this boot
            let timeofuse = cookie.timestamp <= now && now < expires_at;

            debug!(
                "timestamp: {}, now: {}, offset_secs: {}, expires_at: {}\nremaining_secs: {}",
                cookie.timestamp,
                now,
                duration,
                expires_at,
                expires_at.saturating_sub(now)
            );
            debug!("Time of use: {timeofuse}, max_usage: {max_usage_ok}");

            if timeofuse && max_usage_ok && res.is_none() {
                editcookie(cookiev);
                res = Some(cookiev.clone());
                true
            } else {
                false
            }
        }
    });
    res
}

/// Check if the credentials are valid
/// @param from: the credentials of the user that want to execute a command
/// @param ``cred_asked``: the credentials of the user that is asked to execute a command
/// @param ``max_offset``: the maximum offset between the current time and the time of the credentials, including the type of the offset
/// @return true if the credentials are valid, false otherwise
pub fn is_valid(from: &Cred, cred_asked: &Cred, constraint: &STimeout) -> bool {
    let mut file = match CookieFile::open(from) {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to open timestamp cookie file: {e}");
            return false;
        }
    };
    let mut cookies = file.read();
    let res = find_valid_cookie(&mut cookies, from, cred_asked, constraint, |_c| {
        debug!("Found valid cookie ");
    });
    if let Err(e) = file.write(&cookies) {
        debug!("Failed to save cookies {e:?}");
    }
    res.is_some()
}

/// Add a cookie to the user's cookie file
pub fn update_cookie(
    from: &Cred,
    cred_asked: &Cred,
    constraint: &STimeout,
) -> Result<(), Box<dyn Error>> {
    let mut file = CookieFile::open(from)?;
    let mut cookies = file.read();
    let res = find_valid_cookie(
        &mut cookies,
        from,
        cred_asked,
        constraint,
        |cookie| match cookie {
            CookieVersion::V2(cookie) => {
                cookie.usage += 1;
                cookie.timestamp = boottime().unwrap_or(cookie.timestamp);
                debug!("Updating cookie: {cookie:?}");
            }
        },
    );
    if res.is_none() {
        let ttype = constraint.type_field.unwrap_or_default();
        let (Some(now), Some(parent_record)) = (boottime(), ParentRecord::new(ttype, from)) else {
            return Err("Unable to determine the timestamp context".into());
        };
        let cookie = CookieVersion::V2(Cookiev2 {
            auth_uid: cred_asked.user.uid.as_raw(),
            timestamp_type: ttype,
            start_time: now,
            timestamp: now,
            usage: 0,
            parent_record,
        });
        cookies.insert(0, cookie);
    }
    file.write(&cookies)
}

pub fn clear_cookies(user: &Cred) -> Result<(), Box<dyn Error>> {
    let name = user.user.uid.as_raw().to_string();
    as_ts_owner(|| {
        let dir = open_secure_dir(Path::new(TS_LOCATION))?;
        match unlinkat(&dir, name.as_str(), UnlinkatFlags::NoRemoveDir) {
            Ok(()) | Err(Errno::ENOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::{
        fs::{self, Permissions},
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    };

    use jiff::SignedDuration;
    use nix::unistd::{Pid, User};
    use serde_json::Map;
    use test_log::test;

    use super::*;

    static MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A previous run as another user (e.g. tests run as root) may have left the directory.
    fn setup() {
        fs::create_dir_all(TRUSTED_ROOT).unwrap();
        if let Ok(meta) = fs::symlink_metadata(TS_LOCATION)
            && meta.uid() != Uid::effective().as_raw()
        {
            fs::remove_dir_all(TS_LOCATION).unwrap();
        }
    }

    fn test_location(name: &str) -> PathBuf {
        fs::create_dir_all(TRUSTED_ROOT).unwrap();
        let location = Path::new(TRUSTED_ROOT).join(name);
        let _ = fs::remove_dir_all(&location);
        location
    }

    #[test]
    fn test_cookie() {
        let _guard = MUTEX.lock().unwrap();
        setup();
        let cred = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            curdir: "".into(),
            groups: vec![],
            tty: None,
            ppid: Pid::parent(),
        };
        clear_cookies(&cred).unwrap();
        let constraint = STimeout {
            type_field: Some(TimestampType::TTY),
            duration: Some(SignedDuration::from_secs(10)),
            max_usage: Some(1),
            extra_fields: Map::default(),
        };
        assert!(!is_valid(&cred, &cred, &constraint));
        assert!(update_cookie(&cred, &cred, &constraint).is_ok());
        assert!(is_valid(&cred, &cred, &constraint));
        assert!(update_cookie(&cred, &cred, &constraint).is_ok());
        assert!(!is_valid(&cred, &cred, &constraint));
        clear_cookies(&cred).unwrap();
    }

    #[test]
    fn test_cookie_requires_matching_ppid() {
        let _guard = MUTEX.lock().unwrap();
        setup();
        let creator = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            curdir: "".into(),
            groups: vec![],
            tty: None,
            ppid: Pid::parent(),
        };
        let other_process = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            curdir: "".into(),
            groups: vec![],
            tty: None,
            ppid: Pid::this(),
        };
        let constraint = STimeout {
            type_field: Some(TimestampType::PPID),
            duration: Some(SignedDuration::from_secs(10)),
            max_usage: Some(1),
            extra_fields: Map::default(),
        };

        clear_cookies(&creator).unwrap();
        update_cookie(&creator, &creator, &constraint).unwrap();
        assert!(is_valid(&creator, &creator, &constraint));
        assert!(!is_valid(&other_process, &other_process, &constraint));
        clear_cookies(&creator).unwrap();
    }

    /// Create a valid cookie, alter it with `edit`, and check whether it is still valid
    fn is_valid_after(edit: fn(&mut Cookiev2)) -> bool {
        let cred = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            curdir: "".into(),
            groups: vec![],
            tty: None,
            ppid: Pid::parent(),
        };
        let constraint = STimeout {
            type_field: Some(TimestampType::PPID),
            duration: Some(SignedDuration::from_secs(10)),
            max_usage: None,
            extra_fields: Map::default(),
        };
        clear_cookies(&cred).unwrap();
        update_cookie(&cred, &cred, &constraint).unwrap();
        assert!(is_valid(&cred, &cred, &constraint));
        {
            let mut file = CookieFile::open(&cred).unwrap();
            let mut cookies = file.read();
            for CookieVersion::V2(cookie) in &mut cookies {
                edit(cookie);
            }
            file.write(&cookies).unwrap();
        }
        let res = is_valid(&cred, &cred, &constraint);
        clear_cookies(&cred).unwrap();
        res
    }

    #[test]
    fn test_cookie_requires_matching_process_start_time() {
        let _guard = MUTEX.lock().unwrap();
        setup();
        // same parent pid, but recycled by another process
        assert!(!is_valid_after(|cookie| {
            if let ParentRecord::Ppid { ppid_start, .. } = &mut cookie.parent_record {
                *ppid_start += 1;
            }
        }));
    }

    #[test]
    fn test_cookie_requires_matching_session() {
        let _guard = MUTEX.lock().unwrap();
        setup();
        // same parent process, but dosr runs in another session
        assert!(!is_valid_after(|cookie| {
            if let ParentRecord::Ppid { session, .. } = &mut cookie.parent_record {
                *session += 1;
            }
        }));
    }

    /// The cookie types of 4.1.0, whose PPID scope has no session.
    mod v4_1_0 {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug)]
        pub enum CookieVersion {
            V2(Cookiev2),
        }

        #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
        #[serde(rename_all = "UPPERCASE")]
        pub enum ParentRecord {
            Tty {
                tty: u64,
                session: i32,
                session_start: u64,
            },
            Ppid {
                ppid: i32,
                ppid_start: u64,
            },
            None,
        }

        #[derive(Serialize, Deserialize, Debug)]
        pub struct Cookiev2 {
            pub timestamp_type: rootasrole_core::database::options::TimestampType,
            pub start_time: i64,
            pub timestamp: i64,
            pub usage: u64,
            pub parent_record: ParentRecord,
            pub auth_uid: u32,
        }
    }

    fn ppid_constraint() -> STimeout {
        STimeout {
            type_field: Some(TimestampType::PPID),
            duration: Some(SignedDuration::from_secs(10)),
            max_usage: None,
            extra_fields: Map::default(),
        }
    }

    fn root_cred() -> Cred {
        Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            curdir: "".into(),
            groups: vec![],
            tty: None,
            ppid: Pid::parent(),
        }
    }

    #[test]
    fn test_cookie_of_4_1_0_is_not_reused() {
        let _guard = MUTEX.lock().unwrap();
        setup();
        let cred = root_cred();
        let constraint = ppid_constraint();
        clear_cookies(&cred).unwrap();
        let old = v4_1_0::CookieVersion::V2(v4_1_0::Cookiev2 {
            timestamp_type: TimestampType::PPID,
            start_time: boottime().unwrap(),
            timestamp: boottime().unwrap(),
            usage: 0,
            parent_record: v4_1_0::ParentRecord::Ppid {
                ppid: cred.ppid.as_raw(),
                ppid_start: procfs::start_time(cred.ppid).unwrap(),
            },
            auth_uid: 0,
        });
        {
            let mut file = CookieFile::open(&cred).unwrap();
            file.0.set_len(0).unwrap();
            cbor4ii::serde::to_writer(&mut *file.0, &[old]).unwrap();
        }
        // a cookie without the session asks for the password again, then a new one is saved
        assert!(!is_valid(&cred, &cred, &constraint));
        update_cookie(&cred, &cred, &constraint).unwrap();
        assert!(is_valid(&cred, &cred, &constraint));
        clear_cookies(&cred).unwrap();
    }

    #[test]
    fn test_cookie_is_read_by_4_1_0() {
        let _guard = MUTEX.lock().unwrap();
        setup();
        let cred = root_cred();
        let constraint = ppid_constraint();
        clear_cookies(&cred).unwrap();
        update_cookie(&cred, &cred, &constraint).unwrap();
        let cookies: Vec<v4_1_0::CookieVersion> = {
            let file = CookieFile::open(&cred).unwrap();
            cbor4ii::serde::from_reader(BufReader::new(&*file.0)).unwrap()
        };
        clear_cookies(&cred).unwrap();
        // after a downgrade, 4.1.0 ignores the session and keeps its own scope
        let [v4_1_0::CookieVersion::V2(cookie)] = cookies.as_slice() else {
            panic!("one cookie expected: {cookies:?}");
        };
        assert_eq!(
            cookie.parent_record,
            v4_1_0::ParentRecord::Ppid {
                ppid: cred.ppid.as_raw(),
                ppid_start: procfs::start_time(cred.ppid).unwrap(),
            }
        );
    }

    #[test]
    fn test_cookie_from_the_future_is_rejected() {
        let _guard = MUTEX.lock().unwrap();
        setup();
        assert!(is_valid_after(|_| {}));
        assert!(!is_valid_after(|cookie| cookie.timestamp += 5));
        assert!(!is_valid_after(|cookie| cookie.timestamp -= 10));
    }

    #[test]
    fn test_parent_record_without_tty_uses_parent_process() {
        let mut cred = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            curdir: "".into(),
            groups: vec![],
            tty: None,
            ppid: Pid::parent(),
        };
        let ppid_record = ParentRecord::new(TimestampType::PPID, &cred).unwrap();
        assert!(matches!(
            ppid_record,
            ParentRecord::Ppid { session, .. } if session == getsid(None).unwrap().as_raw()
        ));
        assert_eq!(
            ParentRecord::new(TimestampType::TTY, &cred).unwrap(),
            ppid_record
        );
        cred.tty = Some(0x8800);
        assert!(matches!(
            ParentRecord::new(TimestampType::TTY, &cred).unwrap(),
            ParentRecord::Tty { tty: 0x8800, .. }
        ));
        assert_eq!(
            ParentRecord::new(TimestampType::UID, &cred).unwrap(),
            ParentRecord::None
        );
        // a process that does not exist cannot be identified
        cred.ppid = Pid::from_raw(-1);
        assert!(ParentRecord::new(TimestampType::PPID, &cred).is_none());
    }

    #[test]
    fn test_cookie_file_symlink_is_not_followed() {
        let location = test_location("ts_test_symlink");
        let victim = Path::new(TRUSTED_ROOT).join("ts_test_symlink_victim");
        fs::write(&victim, b"untouched").unwrap();
        as_ts_owner(|| open_secure_dir(&location)).unwrap();
        symlink(&victim, location.join("4242")).unwrap();

        assert!(CookieFile::open_in(&location, Uid::from_raw(4242)).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");

        fs::remove_dir_all(&location).unwrap();
        fs::remove_file(&victim).unwrap();
    }

    #[test]
    fn test_insecure_cookie_file_is_replaced() {
        let location = test_location("ts_test_forged");
        let uid = Uid::from_raw(4242);
        let cookie = CookieVersion::V2(Cookiev2 {
            timestamp_type: TimestampType::UID,
            start_time: boottime().unwrap(),
            timestamp: boottime().unwrap(),
            usage: 0,
            parent_record: ParentRecord::None,
            auth_uid: uid.as_raw(),
        });
        CookieFile::open_in(&location, uid)
            .unwrap()
            .write(&[cookie])
            .unwrap();
        let path = location.join("4242");
        fs::set_permissions(&path, Permissions::from_mode(0o666)).unwrap();

        let mut file = CookieFile::open_in(&location, uid).unwrap();
        assert!(file.read().is_empty());
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);

        drop(file);
        fs::remove_dir_all(&location).unwrap();
    }

    #[test]
    fn test_insecure_directory_is_rejected() {
        let parent = test_location("ts_test_insecure");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, Permissions::from_mode(0o777)).unwrap();
        let location = parent.join("ts");

        assert!(CookieFile::open_in(&location, Uid::from_raw(4242)).is_err());
        assert!(!location.exists());

        fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn test_relative_location_is_rejected() {
        assert!(as_ts_owner(|| open_secure_dir(Path::new("target/ts"))).is_err());
        assert!(as_ts_owner(|| open_secure_dir(&Path::new(TRUSTED_ROOT).join("../ts"))).is_err());
    }
}
