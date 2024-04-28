use std::{cell::RefCell, error::Error, fs::File, os::fd::AsRawFd, path::PathBuf, rc::Rc};

use crate::rc_refcell;
use chrono::Duration;
use libc::{FS_IOC_GETFLAGS, FS_IOC_SETFLAGS};
use linked_hash_set::LinkedHashSet;
use serde::{de, Deserialize, Serialize};
use tracing::warn;

use self::{migration::Migration, options::EnvKey, structs::SConfig, version::Versioning};

use super::{
    config::{RemoteStorageSettings, Settings, ROOTASROLE},
    dac_override_effective, immutable_effective,
    util::parse_capset_iter,
};

pub mod finder;
mod migration;
pub mod options;
pub mod structs;
mod version;
pub mod wrapper;

const FS_IMMUTABLE_FL: u32 = 0x00000010;

fn toggle_lock_config(file: &PathBuf, lock: bool) -> Result<(), String> {
    let file = match File::open(file) {
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
    if unsafe { nix::libc::ioctl(fd, FS_IOC_SETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub fn make_weak_config(config: &Rc<RefCell<SConfig>>) {
    for role in &config.as_ref().borrow().roles {
        role.as_ref().borrow_mut()._config = Some(Rc::downgrade(&config));
        for task in &role.as_ref().borrow().tasks {
            task.as_ref().borrow_mut()._role = Some(Rc::downgrade(&role));
        }
    }
}

fn warn_if_mutable(file: &File, return_err: bool) -> Result<(), Box<dyn Error>> {
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

pub fn read_json_config(settings: &Settings) -> Result<Rc<RefCell<SConfig>>, Box<dyn Error>> {
    let default_remote: RemoteStorageSettings = RemoteStorageSettings::default();

    let file = std::fs::File::open(
        settings
            .settings
            .as_ref()
            .unwrap_or(&default_remote)
            .path
            .as_ref()
            .unwrap_or(&ROOTASROLE.into()),
    )?;
    warn_if_mutable(
        &file,
        settings
            .settings
            .as_ref()
            .unwrap_or(&default_remote)
            .immutable
            .unwrap_or(true),
    )?;

    let versionned_config: Versioning<SConfig> = serde_json::from_reader(file)?;
    let config = rc_refcell!(versionned_config.data);
    if Migration::migrate(
        &versionned_config.version,
        &mut *config.as_ref().borrow_mut(),
        version::JSON_MIGRATIONS,
    )? {
        save_json(settings, config.clone())?;
    }
    make_weak_config(&config);

    Ok(config.clone())
}

pub fn save_json(settings: &Settings, config: Rc<RefCell<SConfig>>) -> Result<(), Box<dyn Error>> {
    immutable_effective(true)?;
    dac_override_effective(true)?;
    let default_remote: RemoteStorageSettings = RemoteStorageSettings::default();
    // remove immutable flag
    let into = ROOTASROLE.into();
    let path = settings
        .settings
        .as_ref()
        .unwrap_or(&default_remote)
        .path
        .as_ref()
        .unwrap_or(&into);
    toggle_lock_config(path, false)?;
    write_json_config(&settings, config)?;
    toggle_lock_config(path, true)?;
    dac_override_effective(false)?;
    immutable_effective(false)?;
    Ok(())
}

fn write_json_config(
    settings: &Settings,
    config: Rc<RefCell<SConfig>>,
) -> Result<(), Box<dyn Error>> {
    let default_remote = RemoteStorageSettings::default();
    let file = std::fs::File::create(
        settings
            .settings
            .as_ref()
            .unwrap_or(&default_remote)
            .path
            .as_ref()
            .unwrap_or(&ROOTASROLE.into()),
    )?;
    serde_json::to_writer_pretty(file, &*config.borrow())?;
    Ok(())
}

// deserialize the linked hash set
fn lhs_deserialize_envkey<'de, D>(deserializer: D) -> Result<LinkedHashSet<EnvKey>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let v: Vec<EnvKey> = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().collect())
}

// serialize the linked hash set
fn lhs_serialize_envkey<S>(value: &LinkedHashSet<EnvKey>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let v: Vec<EnvKey> = value.iter().cloned().collect();
    v.serialize(serializer)
}

// deserialize the linked hash set
fn lhs_deserialize<'de, D>(deserializer: D) -> Result<LinkedHashSet<String>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let v: Vec<String> = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().collect())
}

// serialize the linked hash set
fn lhs_serialize<S>(value: &LinkedHashSet<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let v: Vec<String> = value.iter().cloned().collect();
    v.serialize(serializer)
}

pub fn is_default<T: PartialEq + Default>(t: &T) -> bool {
    t == &T::default()
}

fn serialize_duration<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // hh:mm:ss format
    serializer.serialize_str(&format!(
        "{}:{}:{}",
        value.num_hours(),
        value.num_minutes() % 60,
        value.num_seconds() % 60
    ))
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let mut parts = s.split(':');
    //unwrap or error
    if let (Some(hours), Some(minutes), Some(seconds)) = (parts.next(), parts.next(), parts.next())
    {
        let hours: i64 = hours.parse().map_err(de::Error::custom)?;
        let minutes: i64 = minutes.parse().map_err(de::Error::custom)?;
        let seconds: i64 = seconds.parse().map_err(de::Error::custom)?;
        return Ok(Duration::hours(hours) + Duration::minutes(minutes) + Duration::seconds(seconds));
    }
    Err(de::Error::custom("Invalid duration format"))
}

fn deserialize_capset<'de, D>(deserializer: D) -> Result<capctl::CapSet, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s: Vec<String> = Vec::deserialize(deserializer)?;
    let res = parse_capset_iter(s.iter().map(|s| s.as_ref()));
    match res {
        Ok(capset) => Ok(capset),
        Err(_) => Err(de::Error::custom("Invalid capset format")),
    }
}

fn serialize_capset<S>(value: &capctl::CapSet, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let v: Vec<String> = value.iter().map(|cap| cap.to_string()).collect();
    v.serialize(serializer)
}
