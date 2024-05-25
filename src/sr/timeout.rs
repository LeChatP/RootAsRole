use std::{
    error::Error,
    io::{BufReader, Read, Write},
    path::Path,
    thread::sleep,
    time,
};

use chrono::Utc;
use nix::{
    libc::dev_t,
    libc::{pid_t, uid_t},
    sys::signal::kill,
};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::common::{
    create_dir_all_with_privileges, create_with_privileges,
    database::{
        finder::Cred,
        options::{STimeout, TimestampType},
    },
    open_with_privileges, remove_with_privileges,
};

/// This module checks the validity of a user's credentials
/// This module allow to users to not have to re-enter their password in a short period of time

#[derive(Serialize, Deserialize, Debug, Clone)]
#[repr(u8)]
enum CookieVersion {
    V1(Cookiev1) = 56,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
enum ParentRecord {
    TTY(dev_t),
    PPID(pid_t),
    None,
}

impl Default for ParentRecord {
    fn default() -> Self {
        match TimestampType::default() {
            TimestampType::TTY => Self::TTY(0),
            TimestampType::PPID => Self::PPID(0),
            TimestampType::UID => Self::None,
        }
    }
}

impl ParentRecord {
    fn new(ttype: &TimestampType, user: &Cred) -> Self {
        match ttype {
            TimestampType::TTY => {
                if let Some(tty) = user.tty {
                    Self::TTY(tty)
                } else {
                    Self::None
                }
            }
            TimestampType::PPID => Self::PPID(user.ppid.as_raw()),
            TimestampType::UID => Self::None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Cookiev1 {
    timestamp_type: TimestampType,
    start_time: i64,
    timestamp: i64,
    usage: u64,
    parent_record: ParentRecord,
    auth_uid: uid_t,
}

impl Default for Cookiev1 {
    fn default() -> Self {
        Self {
            timestamp_type: TimestampType::default(),
            start_time: Utc::now().timestamp(),
            timestamp: Utc::now().timestamp(),
            usage: 0,
            parent_record: ParentRecord::default(),
            auth_uid: uid_t::MAX,
        }
    }
}

fn wait_for_lockfile(lockfile_path: &Path) -> Result<(), Box<dyn Error>> {
    let max_retries = 10;
    let retry_interval = time::Duration::from_secs(1);
    let pid_contents: pid_t;
    if lockfile_path.exists() {
        if let Ok(mut lockfile) = open_with_privileges(lockfile_path) {
            let mut be: [u8; 4] = [u8::MAX; 4];
            if lockfile.read_exact(&mut be).is_err() {
                debug!(
                    "Lockfile located at {:?} is empty, continuing...",
                    lockfile_path
                );
                remove_with_privileges(lockfile_path).expect("Failed to remove lockfile");
                return Ok(());
            }
            pid_contents = i32::from_be_bytes(be);
            if kill(nix::unistd::Pid::from_raw(pid_contents), None).is_err() {
                debug!("Lockfile located at {:?} was owned by process {:?}, but not released, remove it, and continuing...", lockfile_path, pid_contents.to_string());
                remove_with_privileges(lockfile_path).expect("Failed to remove lockfile");
                return Ok(());
            }
        } else {
            debug!(
                "Lockfile located at {:?} was not found, continuing...",
                lockfile_path
            );
            return Ok(());
        }
    } else {
        debug!(
            "Lockfile located at {:?} was not found, continuing...",
            lockfile_path
        );
        return Ok(());
    }

    for i in 0..max_retries {
        if lockfile_path.exists() {
            if i > 0 {
                print!("\r");
            }
            println!(
                "Lockfile exists, waiting {} seconds{}",
                i,
                ".".repeat(i as usize % 3 + 1)
            );
            sleep(retry_interval);
        } else {
            debug!("Lockfile not found, continuing...");
            return Ok(());
        }
    }
    debug!(
        "Lockfile located at {:?} is owned by process {:?}, and not released, failing",
        lockfile_path,
        pid_contents.to_string()
    );
    Err("Lockfile was not released".into())
}

fn write_lockfile(lockfile_path: &Path) {
    let mut lockfile = create_with_privileges(lockfile_path).expect("Failed to create lockfile");
    let pid_contents = nix::unistd::getpid().as_raw();
    lockfile
        .write_all(&pid_contents.to_be_bytes())
        .expect("Failed to write to lockfile");
}

const TS_LOCATION: &str = "/var/run/rar/ts";

fn read_cookies(user: &Cred) -> Result<Vec<CookieVersion>, Box<dyn Error>> {
    let path = Path::new(TS_LOCATION).join(&user.user.name);
    let lockpath = Path::new(TS_LOCATION)
        .join(user.user.uid.as_raw().to_string()) // Convert u32 to String
        .with_extension("lock");
    if !path.exists() {
        return Ok(Vec::new());
    }
    wait_for_lockfile(&lockpath)?;
    write_lockfile(&lockpath);
    let mut file = open_with_privileges(&path)?;
    let reader = BufReader::new(&mut file);
    let res = ciborium::de::from_reader::<Vec<CookieVersion>, BufReader<_>>(reader)?;
    Ok(res)
}

fn save_cookies(user: &Cred, cookies: &[CookieVersion]) -> Result<(), Box<dyn Error>> {
    debug!("Saving cookies: {:?}", cookies);
    let path = Path::new(TS_LOCATION).join(&user.user.name);
    create_dir_all_with_privileges(path.parent().unwrap())?;
    let lockpath = Path::new(TS_LOCATION)
        .join(&user.user.name)
        .with_extension("lock");
    let mut file = create_with_privileges(&path)?;
    ciborium::ser::into_writer(cookies, &mut file)?;
    if let Err(err) = remove_with_privileges(lockpath) {
        debug!("Failed to remove lockfile: {}", err);
    }
    Ok(())
}
fn find_valid_cookie(
    from: &Cred,
    cred_asked: &Cred,
    constraint: &STimeout,
    editcookie: fn(&mut CookieVersion),
) -> Option<CookieVersion> {
    let mut cookies = read_cookies(from).unwrap_or_default();
    let mut to_remove = Vec::new();
    let mut res = None;
    debug!(
        "Constraints for {} : {:?}",
        cred_asked.user.uid.as_raw(),
        constraint
    );
    for (a, cookiev) in cookies.iter_mut().enumerate() {
        match cookiev {
            CookieVersion::V1(cookie) => {
                debug!("Checking cookie: {:?}", cookie);
                if cookie.auth_uid != cred_asked.user.uid.as_raw()
                    || cookie.timestamp_type != constraint.type_field.unwrap_or_default()
                {
                    continue;
                }
                let max_usage_ok =
                    constraint.max_usage.is_none() || cookie.usage < constraint.max_usage.unwrap();
                debug!("timestamp: {}, now: {}, offset {}, now + offset : {}\ntimestamp-now+offset : {}", cookie.timestamp, Utc::now().timestamp(), constraint.duration.unwrap_or_default().num_seconds(), Utc::now().timestamp() + constraint.duration.unwrap_or_default().num_seconds(), cookie.timestamp - Utc::now().timestamp() + constraint.duration.unwrap_or_default().num_seconds());
                let timeofuse: bool = cookie.timestamp - Utc::now().timestamp()
                    + constraint.duration.unwrap_or_default().num_seconds()
                    > 0;
                debug!("Time of use: {}, max_usage : {}", timeofuse, max_usage_ok);
                if timeofuse && max_usage_ok && res.is_none() {
                    editcookie(cookiev);
                    res = Some(cookiev.clone());
                } else {
                    to_remove.push(a);
                }
            }
        }
    }
    for a in to_remove {
        cookies.remove(a);
    }
    if let Err(e) = save_cookies(from, &cookies) {
        debug!("Failed to save cookies {:?}", e);
    }
    res
}

/// Check if the credentials are valid
/// @param from: the credentials of the user that want to execute a command
/// @param cred_asked: the credentials of the user that is asked to execute a command
/// @param max_offset: the maximum offset between the current time and the time of the credentials, including the type of the offset
/// @return true if the credentials are valid, false otherwise
pub(crate) fn is_valid(from: &Cred, cred_asked: &Cred, constraint: &STimeout) -> bool {
    find_valid_cookie(from, cred_asked, constraint, |_c| {
        debug!("Found valid cookie ");
    })
    .is_some()
}

/// Add a cookie to the user's cookie file
pub(crate) fn update_cookie(
    from: &Cred,
    cred_asked: &Cred,
    constraint: &STimeout,
) -> Result<(), Box<dyn Error>> {
    let res = find_valid_cookie(from, cred_asked, constraint, |cookie| match cookie {
        CookieVersion::V1(cookie) => {
            cookie.usage += 1;
            cookie.timestamp = Utc::now().timestamp();
            debug!("Updating cookie: {:?}", cookie);
        }
    });
    if res.is_none() {
        let mut cookies = read_cookies(from).unwrap_or_default();
        let parent_record = ParentRecord::new(&constraint.type_field.unwrap_or_default(), from);
        let cookie = CookieVersion::V1(Cookiev1 {
            auth_uid: cred_asked.user.uid.as_raw(),
            timestamp_type: constraint.type_field.unwrap_or_default(),
            start_time: Utc::now().timestamp(),
            timestamp: Utc::now().timestamp(),
            usage: 0,
            parent_record,
        });
        cookies.insert(0, cookie);
        save_cookies(from, &cookies)?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use test_log::test;

    use super::*;

    #[test]
    fn test_lockfile() {
        let lockpath = std::path::Path::new("/tmp/test.lock");
        assert!(wait_for_lockfile(lockpath).is_ok());
        write_lockfile(lockpath);
        assert!(wait_for_lockfile(lockpath).is_err());
        std::fs::remove_file(lockpath).unwrap();
        assert!(wait_for_lockfile(lockpath).is_ok());
    }
}
