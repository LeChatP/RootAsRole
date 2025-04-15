// Let's define a serde configuration struct to define the database type and connection string
// example in json:
// {
//     "storage_method": "sqlite", // storage method is where roles and permissions are stored
//     "storage_settings": {
//       "path": "/path/to/sqlite.db"
//       "host": "localhost",
//       "port": 5432,
//       "auth": {
//         "user": "user",
//         "password": "password",
//         "client_ssl": {
//           "ca_cert": "/path/to/ca_cert",
//           "client_cert": "/path/to/client_cert",
//           "client_key": "/path/to/client_key"
//         }
//       },
//       // when using rdbms as storage method
//       "database": "database",
//       "schema": "schema",
//       "table_prefix": "rar_",
//       "properties": {
//         "use_unicode": true,
//         "character_encoding": "utf8"
//       },
//       // when using ldap as storage method
//       "role_dn": "ou=roles",
//     },
//     "ldap": { // when using ldap for user and groups definition storage
//       "enabled": false,
//       "host": "localhost",
//       "port": 389,
//       "auth": {
//         "user": "user",
//         "password": "password"
//         "client_ssl": {
//           "ca_cert": "/path/to/ca_cert",
//           "client_cert": "/path/to/client_cert",
//           "client_key": "/path/to/client_key"
//         }
//       },
//       "base_dn": "dc=example,dc=com",
//       "user_dn": "ou=users",
//       "group_dn": "ou=groups",
//       "user_filter": "(&(objectClass=person)(sAMAccountName=%s))",
//       "group_filter": "(&(objectClass=group)(member=%s))"
//     }
//   }

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

use std::{cell::RefCell, error::Error, io::BufReader, path::{Path, PathBuf}, rc::Rc};

use bon::Builder;
use log::{debug, warn};
use semver::Version;
use serde::{Deserialize, Serialize};

pub mod api;
pub mod database;
pub mod plugin;
pub mod util;

use util::{
    dac_override_effective, open_with_privileges, read_effective, toggle_lock_config, write_cbor_config, write_json_config, ImmutableLock
};

use database::{
    migration::Migration, structs::SConfig, versionning::{Versioning, SETTINGS_MIGRATIONS}
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, Copy)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum StorageMethod {
    #[default]
    JSON,
    CBOR,
    //    SQLite,
    //    PostgreSQL,
    //    MySQL,
    //    LDAP,
    #[serde(other)]
    Unknown,
}

pub enum Storage {
    SConfig(Rc<RefCell<SConfig>>),
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq, Eq, Default)]
pub struct SettingsFile {
    pub storage: Settings,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq, Eq, Default)]
pub struct FullSettingsFile {
    pub storage: Settings,
    #[serde(flatten)]
    pub config: Option<Rc<RefCell<SConfig>>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq, Eq)]
pub struct Settings {
    #[builder(default = StorageMethod::JSON)]
    pub method: StorageMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<RemoteStorageSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldap: Option<LdapSettings>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, Default, PartialEq, Eq)]
pub struct RemoteStorageSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(name = not_immutable,with = || env!("RAR_CFG_IMMUTABLE") == "true")]
    pub immutable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<ConnectionAuth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Properties>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConnectionAuth {
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ssl: Option<ClientSsl>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClientSsl {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Properties {
    pub use_unicode: bool,
    pub character_encoding: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LdapSettings {
    pub enabled: bool,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<ConnectionAuth>,
    pub base_dn: String,
    pub user_dn: String,
    pub group_dn: String,
    pub user_filter: String,
    pub group_filter: String,
}


// Default implementation for Settings
impl Default for Settings {
    fn default() -> Self {
        Self {
            method: StorageMethod::JSON,
            settings: None,
            ldap: None,
        }
    }
}

pub fn make_weak_config(config: &Rc<RefCell<SConfig>>) {
    for role in &config.as_ref().borrow().roles {
        role.as_ref().borrow_mut()._config = Some(Rc::downgrade(config));
        for task in &role.as_ref().borrow().tasks {
            task.as_ref().borrow_mut()._role = Some(Rc::downgrade(role));
        }
    }
}

pub fn full_save_settings<S>(path: &S,settings: Rc<RefCell<FullSettingsFile>>, privileged: bool) -> Result<(), Box<dyn Error>>
where
    S: AsRef<Path>,
{
    Migration::migrate(&Version::parse(PACKAGE_VERSION).unwrap(), &mut *settings.as_ref().borrow_mut(), SETTINGS_MIGRATIONS)?;
    let immuable = settings.as_ref().borrow().storage.settings.as_ref().unwrap_or(&RemoteStorageSettings::default()).immutable.unwrap_or(env!("RAR_CFG_IMMUTABLE") == "true") && privileged;
    let separate = if let Some(rss) = &settings.as_ref().borrow().storage.settings {
        let default_data_path = env!("RAR_CFG_DATA_PATH").to_string().into();
        let data_path = rss.path.as_ref().unwrap_or(&default_data_path);
        if data_path != path.as_ref() {
            Some(data_path.clone())
        }
        else {
            None
        }
    } else {
        None
    };

    if let Some(data_path ) =  separate {
        debug!("Saving settings in separate file");
        return separate_save(&path, &data_path, settings.clone(), immuable);
    }
    
    if immuable {
        debug!("Toggling immutable off for config file");
        toggle_lock_config(path, ImmutableLock::Unset)?;
    }
    // a single file
    let versionned: Versioning<Rc<RefCell<FullSettingsFile>>> = Versioning::new(settings.clone());
    write_json_config(&versionned, path)?;
    if immuable {
        debug!("Toggling immutable on for config file");
        toggle_lock_config(path, ImmutableLock::Set)?;
    }
    Ok(())
}

fn separate_save<S,T>(settings_path: &S, data_path: &T, settings: Rc<RefCell<FullSettingsFile>>, immutable: bool) -> Result<(), Box<dyn Error>>
where
    S: AsRef<Path>,
    T: AsRef<Path>,
{
    {
        let storage_method = settings.as_ref().borrow().storage.method.clone();
        let binding = settings.as_ref().borrow_mut();
        let config = binding.config.as_ref().take().unwrap();
        let versioned_config: Versioning<Rc<RefCell<SConfig>>> = Versioning::new(config.clone());
        if immutable {
            debug!("Toggling immutable off for config file");
            toggle_lock_config(data_path, ImmutableLock::Unset)?;
        }
        debug!("Saving in {} : {}", data_path.as_ref().display(), serde_json::to_string_pretty(&versioned_config).unwrap());
        match storage_method {
            StorageMethod::JSON => {
                write_json_config(&versioned_config, data_path)?;
            }
            StorageMethod::CBOR => {
                write_cbor_config(&versioned_config, data_path)?;
            }
            StorageMethod::Unknown => todo!(),
        }
        if immutable {
            debug!("Toggling immutable on for config file");
            toggle_lock_config(data_path, ImmutableLock::Set)?;
        }
    }
    settings.as_ref().borrow_mut().config = None;
    let versioned_settings: Versioning<Rc<RefCell<FullSettingsFile>>> = Versioning::new(settings.clone());
    if immutable {
        debug!("Toggling immutable off for config file");
        toggle_lock_config(settings_path, ImmutableLock::Unset)?;
    }
    debug!("Saving in {} : {}", settings_path.as_ref().display(), serde_json::to_string_pretty(&versioned_settings).unwrap());
    write_json_config(&versioned_settings, settings_path)?;
    if immutable {
        debug!("Toggling immutable on for config file");
        toggle_lock_config(settings_path, ImmutableLock::Set)?;
    }
    Ok(())
}

pub fn get_full_settings<S>(path: &S) -> Result<Rc<RefCell<FullSettingsFile>>, Box<dyn Error>>
where
    S: AsRef<Path>,
{
    // if file does not exist, return default settings
    if !std::path::Path::new(path.as_ref()).exists() {
        return Ok(rc_refcell!(FullSettingsFile::default()));
    }
    // if user does not have read permission, try to enable privilege
    let file = open_with_privileges(path.as_ref())?;
    let value: Versioning<FullSettingsFile> = serde_json::from_reader(file)
        .inspect_err(|e| {
            debug!("Error reading file: {}", e);
        })
        .unwrap_or_default();
    read_effective(false).or(dac_override_effective(false))?;
    debug!("{}", serde_json::to_string_pretty(&value)?);
    let settingsfile = rc_refcell!(value.data);
    let default_remote = RemoteStorageSettings::default();
    let into = env!("RAR_CFG_DATA_PATH").to_string().into();
    {
        let mut binding = settingsfile.as_ref().borrow_mut();
        let data_path = binding
            .storage
            .settings
            .as_ref()
            .unwrap_or(&default_remote)
            .path
            .as_ref()
            .unwrap_or(&into);
        if data_path != path.as_ref() {
            binding.config = Some(retrieve_sconfig(&binding.storage.method, data_path)?);
        }
    }
    make_weak_config(settingsfile.as_ref().borrow_mut().config.as_ref().unwrap());
    Ok(settingsfile.clone())
}

fn retrieve_sconfig(
    file_type: &StorageMethod,
    path: &PathBuf,
) -> Result<Rc<RefCell<SConfig>>, Box<dyn Error>> {
    let file = open_with_privileges(path)?;
    let value: Versioning<Rc<RefCell<SConfig>>> = match file_type {
        StorageMethod::JSON => serde_json::from_reader(file)
            .inspect_err(|e| {
                debug!("Error reading file: {}", e);
            })
            .unwrap_or_default(),
        StorageMethod::CBOR => cbor4ii::serde::from_reader(BufReader::new(file))
            .inspect_err(|e| {
                debug!("Error reading file: {}", e);
            })
            .unwrap_or_default(),
        StorageMethod::Unknown => todo!(),
    };
    //read_effective(false).or(dac_override_effective(false))?;
    //assert_eq!(value.version.to_string(), PACKAGE_VERSION, "Version mismatch");
    debug!("{}", serde_json::to_string_pretty(&value)?);
    Ok(value.data)
}

pub fn get_settings<S>(path: &S) -> Result<SettingsFile, Box<dyn Error>>
where
    S: AsRef<Path>,
{
    // if user does not have read permission, try to enable privilege
    let file = open_with_privileges(path.as_ref())?;
    let value: Versioning<SettingsFile> = serde_json::from_reader(file)
        .inspect_err(|e| {
            debug!("Error reading file: {}", e);
        })
        .unwrap_or_else(|_| {
            warn!("Using default settings file!!");
            Default::default()
        });
    //read_effective(false).or(dac_override_effective(false))?;
    debug!("{}", serde_json::to_string_pretty(&value)?);
    Ok(value.data)
}


#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;

    use crate::database::actor::SActor;
    use crate::database::structs::{SCommand, SCommands, SCredentials, SRole, STask, SetBehavior};

    use super::*;

    #[test]
    fn test_get_settings_same_file() {
        // Create a test JSON file
        let value = "test_get_settings_same_file.json";
        let config = Versioning::new(Rc::new(RefCell::new(FullSettingsFile::builder()
            .storage(Settings::builder()
                .method(StorageMethod::JSON)
                .settings(RemoteStorageSettings::builder()
                    .path(value)
                    .not_immutable()
                    .build())
                .build())
            .config(SConfig::builder()
                .role(SRole::builder("test_role")
                    .actor(SActor::user(0).build())
                    .task(STask::builder("test_task")
                        .cred(SCredentials::builder()
                            .setuid(0)
                            .setgid(0)
                            .build())
                        .commands(SCommands::builder(SetBehavior::None)
                            .add(vec![SCommand::Simple("/usr/bin/true".to_string())])
                            .build())
                        .build())
                    .build())
                .build())
            .build())));
        write_json_config(&config, value).unwrap();
        let settings = get_full_settings(&value).unwrap();
        assert_eq!(*config.data.borrow(), *settings.borrow());
        fs::remove_file(value).unwrap();
    }

    #[test]
    fn test_get_settings_different_file() {
        // Create a test JSON file
        let external_file = "test_get_settings_different_file_external.json";
        let test_file = "test_get_settings_different_file.json";
        let settings_config = Versioning::new(Rc::new(RefCell::new(FullSettingsFile::builder()
            .storage(Settings::builder()
                .method(StorageMethod::JSON)
                .settings(RemoteStorageSettings::builder()
                    .path(external_file)
                    .not_immutable()
                    .build())
                .build())
            .config(SConfig::builder()
                .role(SRole::builder("IGNORED").build())
                .build())
            .build())));
        write_json_config(&settings_config, test_file).unwrap();
        let config = SConfig::builder()
            .role(SRole::builder("test_role")
                .actor(SActor::user(0).build())
                .task(STask::builder("test_task")
                    .cred(SCredentials::builder()
                        .setuid(0)
                        .setgid(0)
                        .build())
                    .commands(SCommands::builder(SetBehavior::None)
                        .add(vec![SCommand::Simple("/usr/bin/true".to_string())])
                        .build())
                    .build())
                .build())
            .build();
        write_json_config(&Versioning::new(config.clone()), &external_file).unwrap();
        let settings = get_full_settings(&test_file).unwrap();
        assert_eq!(*config.borrow(), *settings.as_ref().borrow().config.as_ref().unwrap().borrow());
        fs::remove_file(test_file).unwrap();
        fs::remove_file(external_file).unwrap();
    }

    #[test]
    fn test_save_settings_same_file() {
        let test_file = "test_save_settings_same_file.json";
        // Create a test JSON file
        let config = Rc::new(RefCell::new(FullSettingsFile::builder()
            .storage(Settings::builder()
                .method(StorageMethod::JSON)
                .settings(RemoteStorageSettings::builder()
                    .path(test_file)
                    .not_immutable()
                    .build())
                .build())
            .config(SConfig::builder()
                .role(SRole::builder("test_role")
                    .actor(SActor::user(0).build())
                    .task(STask::builder("test_task")
                        .cred(SCredentials::builder()
                            .setuid(0)
                            .setgid(0)
                            .build())
                        .commands(SCommands::builder(SetBehavior::None)
                            .add(vec![SCommand::Simple("/usr/bin/true".to_string())])
                            .build())
                        .build())
                    .build())
                .build())
            .build()));
        full_save_settings(&test_file, config.clone(), false).unwrap();
        let settings = get_full_settings(&test_file).unwrap();
        assert_eq!(*config.borrow(), *settings.borrow());
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_save_settings_different_file() {
        let external_file = "test_save_settings_different_file_external.json";
        let test_file = "test_save_settings_different_file.json";
        let sconfig = SConfig::builder()
        .role(SRole::builder("test_role")
            .actor(SActor::user(0).build())
            .task(STask::builder("test_task")
                .cred(SCredentials::builder()
                    .setuid(0)
                    .setgid(0)
                    .build())
                .commands(SCommands::builder(SetBehavior::None)
                    .add(vec![SCommand::Simple("/usr/bin/true".to_string())])
                    .build())
                .build())
            .build())
        .build();
        // Create a test JSON file
        let config = Rc::new(RefCell::new(FullSettingsFile::builder()
            .storage(Settings::builder()
                .method(StorageMethod::JSON)
                .settings(RemoteStorageSettings::builder()
                    .path(external_file)
                    .not_immutable()
                    .build())
                .build())
            .config(sconfig.clone())
            .build()));
        full_save_settings(&test_file, config.clone(), false).unwrap();
        //assert that test_external.json contains /usr/bin/true
        let mut file = open_with_privileges(external_file).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(content.contains("/usr/bin/true"));

        let mut file = open_with_privileges(test_file).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(!content.contains("/usr/bin/true"));

        let settings = get_full_settings(&test_file).unwrap();
        assert_eq!(*sconfig.borrow(), *settings.borrow().config.as_ref().unwrap().borrow());
        settings.as_ref().borrow_mut().config = None;
        assert_eq!(*config.borrow(), *settings.borrow());
        fs::remove_file(test_file).unwrap();
        fs::remove_file(external_file).unwrap();
    }

    #[test]
    fn test_save_cbor_format() {
        let external_file = "test_save_cbor_format.bin";
        let test_file = "test_save_cbor_format.json";
        let sconfig = SConfig::builder()
        .role(SRole::builder("test_role")
            .actor(SActor::user(0).build())
            .task(STask::builder("test_task")
                .cred(SCredentials::builder()
                    .setuid(0)
                    .setgid(0)
                    .build())
                .commands(SCommands::builder(SetBehavior::None)
                    .add(vec![SCommand::Simple("/usr/bin/true".to_string())])
                    .build())
                .build())
            .build())
        .build();
        let settings = Rc::new(RefCell::new(FullSettingsFile::builder()
            .storage(Settings::builder()
                .method(StorageMethod::CBOR)
                .settings(RemoteStorageSettings::builder()
                    .path(external_file)
                    .not_immutable()
                    .build())
                .build())
            .config(sconfig.clone())
            .build()));
        full_save_settings(&test_file, settings.clone(), false).unwrap();
        //asset that external_file is a binary file
        let mut file = open_with_privileges(external_file).unwrap();
        // try to parse as ciborium
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        let deserialized: Versioning<Rc<RefCell<SConfig>>> = cbor4ii::serde::from_reader(&content[..]).unwrap();
        assert_eq!(deserialized.version.to_string(), PACKAGE_VERSION);
        fs::remove_file(test_file).unwrap();
        fs::remove_file(external_file).unwrap();
    }
}