use std::{cell::RefCell, error::Error, rc::Rc};

use crate::common::config::save_settings;
use crate::common::read_effective;
use crate::common::util::toggle_lock_config;
use crate::common::version::PACKAGE_VERSION;

use chrono::Duration;
use linked_hash_set::LinkedHashSet;
use serde::{de, Deserialize, Serialize};
use tracing::debug;

use self::{migration::Migration, options::EnvKey, structs::SConfig, version::Versioning};

use super::config::SettingsFile;
use super::util::warn_if_mutable;
use super::write_json_config;
use super::{
    config::{RemoteStorageSettings, ROOTASROLE},
    dac_override_effective, immutable_effective,
    util::parse_capset_iter,
};

pub mod finder;
pub mod migration;
pub mod options;
pub mod structs;
pub mod version;
pub mod wrapper;

pub fn make_weak_config(config: &Rc<RefCell<SConfig>>) {
    for role in &config.as_ref().borrow().roles {
        role.as_ref().borrow_mut()._config = Some(Rc::downgrade(config));
        for task in &role.as_ref().borrow().tasks {
            task.as_ref().borrow_mut()._role = Some(Rc::downgrade(role));
        }
    }
}

pub fn read_json_config(
    settings: Rc<RefCell<SettingsFile>>,
) -> Result<Rc<RefCell<SConfig>>, Box<dyn Error>> {
    let default_remote: RemoteStorageSettings = RemoteStorageSettings::default();
    let default = &ROOTASROLE.into();
    let binding = settings.as_ref().borrow();
    let path = binding
        .storage
        .settings
        .as_ref()
        .unwrap_or(&default_remote)
        .path
        .as_ref()
        .unwrap_or(default);
    if path == default {
        make_weak_config(&settings.as_ref().borrow().config);
        Ok(settings.as_ref().borrow().config.clone())
    } else {
        let file = std::fs::File::open(path)?;
        warn_if_mutable(
            &file,
            settings
                .as_ref()
                .borrow()
                .storage
                .settings
                .as_ref()
                .unwrap_or(&default_remote)
                .immutable
                .unwrap_or(true),
        )?;
        let versionned_config: Versioning<Rc<RefCell<SConfig>>> = serde_json::from_reader(file)?;
        let config = versionned_config.data;
        if Migration::migrate(
            &versionned_config.version,
            &mut *config.as_ref().borrow_mut(),
            version::JSON_MIGRATIONS,
        )? {
            save_json(settings.clone(), config.clone())?;
        }
        make_weak_config(&config);
        Ok(config)
    }
}

pub fn save_json(
    settings: Rc<RefCell<SettingsFile>>,
    config: Rc<RefCell<SConfig>>,
) -> Result<(), Box<dyn Error>> {
    let default_remote: RemoteStorageSettings = RemoteStorageSettings::default();
    // remove immutable flag
    let into = ROOTASROLE.into();
    let binding = settings.as_ref().borrow();
    let path = binding
        .storage
        .settings
        .as_ref()
        .unwrap_or(&default_remote)
        .path
        .as_ref()
        .unwrap_or(&into);
    if path == &into {
        // if /etc/security/rootasrole.json then you need to consider the settings to save in addition to the config
        return save_settings(settings.clone());
    }
    debug!("Setting immutable privilege");
    immutable_effective(true)?;
    debug!("Toggling immutable on for config file");
    toggle_lock_config(path, true)?;
    immutable_effective(false)?;
    debug!("Writing config file");
    let versionned: Versioning<Rc<RefCell<SConfig>>> = Versioning {
        version: PACKAGE_VERSION.to_owned().parse()?,
        data: config,
    };
    write_sconfig(&settings.as_ref().borrow(), versionned)?;
    debug!("Toggling immutable off for config file");
    immutable_effective(true)?;
    toggle_lock_config(path, false)?;
    
    debug!("Resetting immutable privilege");
    immutable_effective(false)?;
    Ok(())
}

fn write_sconfig(
    settings: &SettingsFile,
    config: Versioning<Rc<RefCell<SConfig>>>,
) -> Result<(), Box<dyn Error>> {
    let default_remote = RemoteStorageSettings::default();
    let binding = ROOTASROLE.into();
    let path = settings
        .storage
        .settings
        .as_ref()
        .unwrap_or(&default_remote)
        .path
        .as_ref()
        .unwrap_or(&binding);
    write_json_config(&config, path);
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
        return Ok(Duration::hours(hours)
            + Duration::minutes(minutes)
            + Duration::seconds(seconds));
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
