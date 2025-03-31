use std::path::Path;
use std::{cell::RefCell, error::Error, rc::Rc};

use crate::{save_settings, StorageMethod, PACKAGE_VERSION};
use crate::util::{toggle_lock_config, ImmutableLock};

use actor::{SGroups, SUserType};
use bon::{builder, Builder};
use chrono::Duration;
use linked_hash_set::LinkedHashSet;
use log::{debug, error};
use options::EnvBehavior;
use serde::{de, Deserialize, Serialize};

use self::{migration::Migration, options::EnvKey, structs::SConfig, versionning::Versioning};

use crate::util::warn_if_mutable;
use crate::SettingsFile;
use crate::{open_with_privileges, write_json_config};
use crate::{util::immutable_effective, RemoteStorageSettings, ROOTASROLE};

pub mod actor;
#[cfg(feature = "finder")]
pub mod finder;
pub mod migration;
pub mod options;
pub mod structs;
pub mod versionning;

#[derive(Debug, Default, Builder)]
#[builder(on(_, overwritable))]
pub struct FilterMatcher {
    pub role: Option<String>,
    pub task: Option<String>,
    pub env_behavior: Option<EnvBehavior>,
    #[builder(into)]
    pub user: Option<SUserType>,
    pub group: Option<SGroups>,
}

pub fn make_weak_config(config: &Rc<RefCell<SConfig>>) {
    for role in &config.as_ref().borrow().roles {
        role.as_ref().borrow_mut()._config = Some(Rc::downgrade(config));
        for task in &role.as_ref().borrow().tasks {
            task.as_ref().borrow_mut()._role = Some(Rc::downgrade(role));
        }
    }
}

pub fn read_sconfig<P: AsRef<Path>>(
    settings: Rc<RefCell<SettingsFile>>,
    settings_path: P,
) -> Result<Rc<RefCell<SConfig>>, Box<dyn Error>> {
    let default_remote: RemoteStorageSettings = RemoteStorageSettings::default();
    let binding = settings.as_ref().borrow();
    let path = binding
        .storage
        .settings
        .as_ref()
        .unwrap_or(&default_remote)
        .path
        .as_ref();
    if path.is_none() || path.is_some_and(|p| p == settings_path.as_ref()) {
        make_weak_config(&settings.as_ref().borrow().config);
        return Ok(settings.as_ref().borrow().config.clone());
    } else {
        let file = open_with_privileges(path.unwrap())?;
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
        let versionned_config: Versioning<Rc<RefCell<SConfig>>> = match settings.as_ref().borrow().storage.method {
            StorageMethod::JSON => {
                serde_json::from_reader(file)?
            },
            StorageMethod::CBOR => {
                ciborium::from_reader(file)?
            },
            _ => {
                error!("Unsupported storage method");
                return Err("Unsupported storage method".into());
            }
        };
        let config = versionned_config.data;
        if let Ok(true) = Migration::migrate(
            &versionned_config.version,
            &mut *config.as_ref().borrow_mut(),
            versionning::JSON_MIGRATIONS,
        ) {
            save_sconfig(settings.clone(), config.clone())?;
        } else {
            debug!("No migrations needed");
        }
        make_weak_config(&config);
        Ok(config)
    }
}

pub fn save_sconfig(
    settings: Rc<RefCell<SettingsFile>>,
    config: Rc<RefCell<SConfig>>,
) -> Result<(), Box<dyn Error>> {
    let default_remote: RemoteStorageSettings = RemoteStorageSettings::default();
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

    debug!("Writing config file");
    let versionned: Versioning<Rc<RefCell<SConfig>>> = Versioning {
        version: PACKAGE_VERSION.to_owned().parse()?,
        data: config,
    };
    if let Some(settings) = &settings.as_ref().borrow().storage.settings {
        if settings.immutable.unwrap_or(true) {
            debug!("Toggling immutable on for config file");
            toggle_lock_config(path, ImmutableLock::Unset)?;
        }
    }
    write_sconfig(&settings.as_ref().borrow(), versionned)?;
    if let Some(settings) = &settings.as_ref().borrow().storage.settings {
        if settings.immutable.unwrap_or(true) {
            debug!("Toggling immutable off for config file");
            toggle_lock_config(path, ImmutableLock::Set)?;
        }
    }
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
    write_json_config(&config, path)?;
    Ok(())
}

// deserialize the linked hash set
fn lhs_deserialize_envkey<'de, D>(
    deserializer: D,
) -> Result<Option<LinkedHashSet<EnvKey>>, D::Error>
where
    D: de::Deserializer<'de>,
{
    if let Ok(v) = Vec::<EnvKey>::deserialize(deserializer) {
        Ok(Some(v.into_iter().collect()))
    } else {
        Ok(None)
    }
}

// serialize the linked hash set
fn lhs_serialize_envkey<S>(
    value: &Option<LinkedHashSet<EnvKey>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(v) = value {
        let v: Vec<EnvKey> = v.iter().cloned().collect();
        v.serialize(serializer)
    } else {
        serializer.serialize_none()
    }
}

// deserialize the linked hash set
fn lhs_deserialize<'de, D>(deserializer: D) -> Result<Option<LinkedHashSet<String>>, D::Error>
where
    D: de::Deserializer<'de>,
{
    if let Ok(v) = Vec::<String>::deserialize(deserializer) {
        Ok(Some(v.into_iter().collect()))
    } else {
        Ok(None)
    }
}

// serialize the linked hash set
fn lhs_serialize<S>(value: &Option<LinkedHashSet<String>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(v) = value {
        let v: Vec<String> = v.iter().cloned().collect();
        v.serialize(serializer)
    } else {
        serializer.serialize_none()
    }
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

fn convert_string_to_duration(s: &String) -> Result<Option<chrono::TimeDelta>, Box<dyn Error>>
{
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

fn serialize_capset<S>(value: &capctl::CapSet, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let v: Vec<String> = value.iter().map(|cap| cap.to_string()).collect();
    v.serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LinkedHashSetTester<T>(LinkedHashSet<T>);

    impl<'de> Deserialize<'de> for LinkedHashSetTester<EnvKey> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(
                lhs_deserialize_envkey(deserializer).map(|v| v.unwrap())?,
            ))
        }
    }

    impl Serialize for LinkedHashSetTester<EnvKey> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            lhs_serialize_envkey(&Some(self.0.clone()), serializer)
        }
    }

    impl<'de> Deserialize<'de> for LinkedHashSetTester<String> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(lhs_deserialize(deserializer).map(|v| v.unwrap())?))
        }
    }

    impl Serialize for LinkedHashSetTester<String> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            lhs_serialize(&Some(self.0.clone()), serializer)
        }
    }

    struct DurationTester(Duration);

    impl<'de> Deserialize<'de> for DurationTester {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(
                deserialize_duration(deserializer).map(|v| v.unwrap())?,
            ))
        }
    }

    impl Serialize for DurationTester {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serialize_duration(&Some(self.0.clone()), serializer)
        }
    }

    #[test]
    fn test_lhs_deserialize_envkey() {
        let json = r#"["key1", "key2", "key3"]"#;
        let deserialized: Option<LinkedHashSetTester<EnvKey>> = serde_json::from_str(json).unwrap();
        assert!(deserialized.is_some());
        let set = deserialized.unwrap();
        assert_eq!(set.0.len(), 3);
        assert!(set.0.contains(&EnvKey::from("key1")));
        assert!(set.0.contains(&EnvKey::from("key2")));
        assert!(set.0.contains(&EnvKey::from("key3")));
    }

    #[test]
    fn test_lhs_serialize_envkey() {
        let mut set = LinkedHashSetTester(LinkedHashSet::new());
        set.0.insert(EnvKey::from("key1"));
        set.0.insert(EnvKey::from("key2"));
        set.0.insert(EnvKey::from("key3"));
        let serialized = serde_json::to_string(&Some(set)).unwrap();
        assert_eq!(serialized, r#"["key1","key2","key3"]"#);
    }

    #[test]
    fn test_lhs_deserialize() {
        let json = r#"["value1", "value2", "value3"]"#;
        let deserialized: Option<LinkedHashSetTester<String>> = serde_json::from_str(json).unwrap();
        assert!(deserialized.is_some());
        let set = deserialized.unwrap();
        assert_eq!(set.0.len(), 3);
        assert!(set.0.contains("value1"));
        assert!(set.0.contains("value2"));
        assert!(set.0.contains("value3"));
    }

    #[test]
    fn test_lhs_serialize() {
        let mut set = LinkedHashSetTester(LinkedHashSet::new());
        set.0.insert("value1".to_string());
        set.0.insert("value2".to_string());
        set.0.insert("value3".to_string());
        let serialized = serde_json::to_string(&Some(set)).unwrap();
        assert_eq!(serialized, r#"["value1","value2","value3"]"#);
    }

    #[test]
    fn test_serialize_duration() {
        let duration = Some(DurationTester(Duration::seconds(3661)));
        let serialized = serde_json::to_string(&duration).unwrap();
        assert_eq!(serialized, r#""01:01:01""#);
    }

    #[test]
    fn test_deserialize_duration() {
        let json = r#""01:01:01""#;
        let deserialized: Option<DurationTester> = serde_json::from_str(json).unwrap();
        assert!(deserialized.is_some());
        let duration = deserialized.unwrap();
        assert_eq!(duration.0.num_seconds(), 3661);
    }

    #[test]
    fn test_is_default() {
        assert!(is_default(&0));
        assert!(is_default(&String::new()));
        assert!(!is_default(&1));
        assert!(!is_default(&"non-default".to_string()));
    }
}
