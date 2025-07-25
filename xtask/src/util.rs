use std::{
    collections::HashMap,
    error::Error,
    fs::{self, File},
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
    process::Command,
};

use anyhow::{anyhow, Context};
use capctl::Cap;
use capctl::CapState;
use chrono::Duration;
use clap::ValueEnum;
use log::debug;
use nix::libc::{FS_IOC_GETFLAGS, FS_IOC_SETFLAGS};
use serde::{de, Deserialize, Serialize};
use serde_json::Value;
use strum::{Display, EnumIs, EnumIter, EnumString};

#[derive(Debug, Clone, ValueEnum, EnumIs, EnumIter, Display, PartialEq, Eq, Hash)]
#[clap(rename_all = "lowercase")]
pub enum OsTarget {
    #[clap(alias = "deb")]
    Debian,
    #[clap(alias = "ubu")]
    Ubuntu,
    #[clap(alias = "rh")]
    RedHat,
    #[clap(alias = "fed")]
    Fedora,
    #[clap(alias = "arch")]
    ArchLinux,
}

impl OsTarget {
    pub fn detect() -> Result<Self, anyhow::Error> {
        for file in glob::glob("/etc/*-release")? {
            let file = file?;
            let os = std::fs::read_to_string(&file)?.to_ascii_lowercase();
            if os.contains("debian") {
                return Ok(OsTarget::Debian);
            } else if os.contains("ubuntu") {
                return Ok(OsTarget::Ubuntu);
            } else if os.contains("fedora") {
                return Ok(OsTarget::Fedora);
            } else if os.contains("arch") {
                return Ok(OsTarget::ArchLinux);
            } else if os.contains("redhat") || os.contains("rhel") {
                return Ok(OsTarget::RedHat);
            }
        }
        Err(anyhow!("Unsupported OS"))
    }
}

pub const RST: &str = "\x1B[0m";
pub const BOLD: &str = "\x1B[1m";
pub const UNDERLINE: &str = "\x1B[4m";
pub const RED: &str = "\x1B[31m";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SettingsFile {
    pub storage: Settings,
    #[serde(default)]
    #[serde(flatten)]
    pub _extra_fields: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, EnumString)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
pub enum StorageMethod {
    JSON,
    CBOR,
    //    SQLite,
    //    PostgreSQL,
    //    MySQL,
    //    LDAP,
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Settings {
    pub method: StorageMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<RemoteStorageSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Opt>,
    #[serde(default)]
    #[serde(flatten)]
    pub _extra_fields: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoteStorageSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immutable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    #[serde(flatten)]
    pub _extra_fields: Value,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PathBehavior {
    Delete,
    KeepSafe,
    KeepUnsafe,
    #[default]
    Inherit,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone, Copy, Display, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TimestampType {
    #[default]
    PPID,
    TTY,
    UID,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
pub struct STimeout {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_field: Option<TimestampType>,
    #[serde(
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration",
        skip_serializing_if = "Option::is_none"
    )]
    pub duration: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_usage: Option<u64>,
    #[serde(default)]
    #[serde(flatten)]
    pub _extra_fields: Value,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct SPathOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    pub default_behavior: PathBehavior,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "del")]
    pub sub: Option<Vec<String>>,
    #[serde(default)]
    #[serde(flatten)]
    pub _extra_fields: Value,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum EnvBehavior {
    Delete,
    Keep,
    #[default]
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
pub struct SEnvOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    pub default_behavior: EnvBehavior,
    #[serde(alias = "override", default, skip_serializing_if = "Option::is_none")]
    pub override_behavior: Option<bool>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub set: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete: Option<Vec<String>>,
    #[serde(default, flatten)]
    pub _extra_fields: Value,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SBounding {
    Strict,
    Ignore,
    #[default]
    Inherit,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SPrivileged {
    Privileged,
    #[default]
    User,
    Inherit,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SAuthentication {
    Skip,
    #[default]
    Perform,
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Opt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<SPathOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<SEnvOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<SPrivileged>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounding: Option<SBounding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SAuthentication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard_denied: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<STimeout>,
    #[serde(default, flatten)]
    pub _extra_fields: Value,
}

const FS_IMMUTABLE_FL: u32 = 0x00000010;
pub const ROOTASROLE: &str = env!("RAR_CFG_PATH");

#[derive(Debug, EnumIs)]
pub enum ImmutableLock {
    Set,
    Unset,
}

pub fn is_default<T: PartialEq + Default>(t: &T) -> bool {
    t == &T::default()
}

fn serialize_duration<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // hh:mm:ss format
    match value {
        Some(value) => serializer.serialize_str(&format!(
            "{:#02}:{:#02}:{:#02}",
            value.num_hours(),
            value.num_minutes() % 60,
            value.num_seconds() % 60
        )),
        None => serializer.serialize_none(),
    }
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match convert_string_to_duration(&s) {
        Ok(d) => Ok(d),
        Err(e) => Err(de::Error::custom(e)),
    }
}

pub fn convert_string_to_duration(s: &String) -> Result<Option<chrono::TimeDelta>, Box<dyn Error>> {
    let mut parts = s.split(':');
    //unwrap or error
    if let (Some(hours), Some(minutes), Some(seconds)) = (parts.next(), parts.next(), parts.next())
    {
        let hours: i64 = hours.parse()?;
        let minutes: i64 = minutes.parse()?;
        let seconds: i64 = seconds.parse()?;
        return Ok(Some(
            Duration::hours(hours) + Duration::minutes(minutes) + Duration::seconds(seconds),
        ));
    }
    Err("Invalid duration format".into())
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

pub fn change_dir_to_git_root() -> Result<(), anyhow::Error> {
    let output = Command::new("git")
        .args(&["rev-parse", "--show-toplevel"])
        .output()?;
    let git_root = String::from_utf8(output.stdout)?.trim().to_string();
    debug!("Changing directory to git root: {}", git_root);
    std::env::set_current_dir(git_root)?;
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

    immutable_required_privileges(&file, true)?;
    if unsafe { nix::libc::ioctl(fd, FS_IOC_SETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    immutable_required_privileges(&file, false)?;
    Ok(())
}

pub fn cap_effective(cap: Cap, enable: bool) -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.set_state(cap, enable);
    current.set_current()
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

pub fn open_with_privileges<P: AsRef<Path>>(p: P) -> Result<File, std::io::Error> {
    std::fs::File::open(&p).or_else(|_| {
        read_effective(true).or(dac_override_effective(true))?;
        let res = std::fs::File::open(p);
        read_effective(false)?;
        dac_override_effective(false)?;
        res
    })
}

pub fn files_are_equal(path1: &str, path2: &str) -> io::Result<bool> {
    let file1_content = fs::read(path1)?;
    let file2_content = fs::read(path2)?;

    Ok(file1_content == file2_content)
}

pub fn get_os(os: Option<OsTarget>) -> Result<OsTarget, anyhow::Error> {
    Ok(if let Some(os) = os {
        os
    } else {
        OsTarget::detect()
            .map(|t| {
                debug!("Detected OS is : {}", t);
                t
            })
            .context("Failed to detect the OS")?
    })
}

pub fn detect_priv_bin() -> Option<String> {
    // is /usr/bin/sr exist ?
    if std::fs::metadata("/usr/bin/sr").is_ok() {
        Some("/usr/bin/sr".to_string())
    } else if std::fs::metadata("/usr/bin/sudo").is_ok() {
        Some("/usr/bin/sudo".to_string())
    } else if std::fs::metadata("/usr/bin/doas").is_ok() {
        Some("/usr/bin/doas".to_string())
    } else {
        None
    }
}

pub fn cap_clear(state: &mut capctl::CapState) -> Result<(), anyhow::Error> {
    state.effective.clear();
    state.set_current()?;
    Ok(())
}

#[cfg(test)]
mod test {
    use std::{fs, path::PathBuf};

    use super::*;

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
