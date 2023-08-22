use std::{io::{BufReader, Read, Write}, fs::{File, self}, path::Path, error::Error, time, thread::sleep};

use chrono::{Utc, TimeZone};
use ciborium::de;
use nix::{libc::dev_t, libc::{pid_t, uid_t}, sys::signal::{kill, Signal}};
use serde::{Serialize, Deserialize};
use tracing::debug;
use std::str::FromStr;

use crate::{finder::Cred, config::structs::CookieConstraint};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum TimestampType {
    Global,
    TTY,
    PPID,
}

impl Default for TimestampType {
    fn default() -> Self {
        TimestampType::PPID
    }
}

impl FromStr for TimestampType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "global" => Ok(TimestampType::Global),
            "tty" => Ok(TimestampType::TTY),
            "ppid" => Ok(TimestampType::PPID),
            _ => {
                debug!("Invalid timestamp type: {}", s);
                Err(())
            },
        }
    }
}



/// This module checks the validity of a user's credentials
/// This module allow to users to not have to re-enter their password in a short period of time

#[derive(Serialize, Deserialize, Debug)]
#[repr(u8)]
enum CookieVersion {
    V1(Cookiev1) = 56,
}
#[derive(Serialize, Deserialize, Debug)]
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
            TimestampType::Global => Self::None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Cookiev1 {
    timestamp_type: TimestampType,
    start_time: i64,
    timestamp: i64,
    usage: u32,
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
        if let Ok(mut lockfile) = File::open(lockfile_path) {
            let mut be : [u8; 4] = [u8::MAX; 4];
            if lockfile.read_exact(&mut be).is_err() {
                debug!("Lockfile located at {:?} is empty, continuing...", lockfile_path);
                fs::remove_file(lockfile_path).expect("Failed to remove lockfile");
                return Ok(());
            }
            pid_contents = i32::from_be_bytes(be);
            if let Err(err) = kill(nix::unistd::Pid::from_raw(pid_contents),None) {
                debug!("Lockfile located at {:?} was owned by process {:?}, but not released, remove it, and continuing...", lockfile_path, pid_contents.to_string());
                fs::remove_file(lockfile_path).expect("Failed to remove lockfile");
                return Ok(());
            }
        } else {
            debug!("Lockfile located at {:?} was not found, continuing...", lockfile_path);
            return Ok(());
        }
    } else {
        debug!("Lockfile located at {:?} was not found, continuing...", lockfile_path);
        return Ok(());
    }
    
    for i in 0..max_retries {
        if lockfile_path.exists() {
            if i > 0 {
                print!("\r");
            }
            println!("Lockfile exists, waiting {} seconds{}",i, ".".repeat(i as usize % 3+1));
            sleep(retry_interval);
        } else {
            debug!("Lockfile not found, continuing...");
            return Ok(());
        }
    }
    debug!("Lockfile located at {:?} is owned by process {:?}, and not released, failing", lockfile_path, pid_contents.to_string());
    return Err("Lockfile was not released".into());
    
}

fn write_lockfile(lockfile_path: &Path) {
    let mut lockfile = File::create(lockfile_path).expect("Failed to create lockfile");
    let pid_contents = nix::unistd::getpid().as_raw();
    lockfile.write_all(&pid_contents.to_be_bytes()).expect("Failed to write to lockfile");
}

const TS_LOCATION : &str = "/var/run/rar/ts";

fn read_cookies(user: &Cred) -> Result<Vec<CookieVersion>, Box<dyn Error>> {
    let path = Path::new(TS_LOCATION).join(&user.user.name);
    let lockpath = Path::new(TS_LOCATION).join(&user.user.name).with_extension("lock");
    if ! path.exists() {
        return Ok(Vec::new());
    }
    wait_for_lockfile(&lockpath)?;
    write_lockfile(&lockpath);
    let mut file = File::open(&path)?;
    let reader = BufReader::new(&mut file);
    let res =ciborium::de::from_reader::<Vec<CookieVersion>, BufReader<_>>(reader)?;
    Ok(res)
}

fn save_cookies(user: &Cred, cookies: &Vec<CookieVersion>) -> Result<(), Box<dyn Error>> {
    let path = Path::new(TS_LOCATION).join(&user.user.name);
    fs::create_dir_all(path.parent().unwrap())?;
    let lockpath = Path::new(TS_LOCATION).join(&user.user.name).with_extension("lock");
    let mut file = File::create(&path)?;
    ciborium::ser::into_writer(cookies,&mut file)?;
    if let Err(err) = fs::remove_file(lockpath) {
        debug!("Failed to remove lockfile: {}", err);
    }
    Ok(())
}

/// Check if the credentials are valid
/// @param from: the credentials of the user that want to execute a command
/// @param cred_asked: the credentials of the user that is asked to execute a command
/// @param max_offset: the maximum offset between the current time and the time of the credentials, including the type of the offset
/// @return true if the credentials are valid, false otherwise
pub(crate) fn is_valid(from: &Cred, cred_asked: &Cred, constraint: &CookieConstraint) -> bool {
    let mut cookies = read_cookies(from).unwrap_or_default();
    let mut valid = false;
    let mut to_remove = Vec::new();

    for (a, cookie) in cookies.iter_mut().enumerate() {
        match cookie {
            CookieVersion::V1(cookie) => {
                if cookie.auth_uid != cred_asked.user.uid.as_raw() || cookie.timestamp_type != constraint.timestamptype.parse().unwrap() {
                    continue;
                }
                let max_usage_ok = constraint.max_usage.is_some() && cookie.usage < constraint.max_usage.unwrap();
                if Utc.timestamp_opt(cookie.timestamp, 0).unwrap() < Utc::now() + constraint.offset || max_usage_ok  {
                    cookie.timestamp = Utc::now().timestamp();
                    cookie.usage += 1;
                    valid = true;
                } else {
                    to_remove.push(a);
                }
            }
        }
    }
    for a in to_remove {
        cookies.remove(a);
    }
    if save_cookies(from, &cookies).is_err() {
        debug!("Failed to save cookies");
    }
    valid
}

/// Add a cookie to the user's cookie file
pub(crate) fn add_cookie(user: &Cred, cred_asked: &Cred) -> Result<(), Box<dyn Error>> {
    let mut cookies = read_cookies(user)?;
    let cookie = CookieVersion::V1(Cookiev1 {
        auth_uid: cred_asked.user.uid.as_raw(),
        timestamp_type: TimestampType::default(),
        start_time: Utc::now().timestamp(),
        timestamp: Utc::now().timestamp(),
        usage: 0,
        parent_record: ParentRecord::default(),
    });
    cookies.insert(0,cookie);
    save_cookies(user, &cookies)?;
    Ok(())
}