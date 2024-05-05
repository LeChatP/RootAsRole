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

#[cfg(not(test))]
pub const ROOTASROLE: &str = "/etc/security/rootasrole.json";
#[cfg(test)]
pub const ROOTASROLE: &str = "target/rootasrole.json";

use std::{
    cell::RefCell,
    error::Error,
    path::PathBuf,
    rc::Rc,
};

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    common::{
        dac_override_effective, open_with_privileges, read_effective,
        util::toggle_lock_config, write_json_config,
    },
    rc_refcell,
};

use super::database::{
    migration::Migration,
    structs::SConfig,
    version::{self, Versioning},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum StorageMethod {
    JSON,
    //    SQLite,
    //    PostgreSQL,
    //    MySQL,
    //    LDAP,
    #[serde(other)]
    Unknown,
}

pub enum Storage {
    JSON(Rc<RefCell<SConfig>>),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SettingsFile {
    pub storage: Settings,
    #[serde(flatten)]
    pub config: Rc<RefCell<SConfig>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Settings {
    pub method: StorageMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<RemoteStorageSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldap: Option<LdapSettings>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoteStorageSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immutable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectionAuth {
    pub user: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ssl: Option<ClientSsl>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientSsl {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cert: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Properties {
    pub use_unicode: bool,
    pub character_encoding: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

impl Default for SettingsFile {
    fn default() -> Self {
        Self {
            storage: Settings::default(),
            config: Rc::new(RefCell::new(SConfig::default())),
        }
    }
}

// Default implementation for Settings
impl Default for Settings {
    fn default() -> Self {
        Self {
            method: StorageMethod::JSON,
            settings: Some(RemoteStorageSettings::default()),
            ldap: None,
        }
    }
}

impl Default for RemoteStorageSettings {
    fn default() -> Self {
        Self {
            immutable: None,
            path: Some(ROOTASROLE.into()),
            host: None,
            port: None,
            auth: None,
            database: None,
            schema: None,
            table_prefix: None,
            properties: None,
        }
    }
}

pub fn save_settings(settings: Rc<RefCell<SettingsFile>>) -> Result<(), Box<dyn Error>> {
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
    if let Some(settings) = &settings.as_ref().borrow().storage.settings {
        if settings.immutable.unwrap_or(true) {
            debug!("Toggling immutable on for config file");
            toggle_lock_config(path, true)?;
        }
    }
    debug!("Writing config file");
    let versionned: Versioning<Rc<RefCell<SettingsFile>>> = Versioning::new(settings.clone());
    write_json_config(&versionned, ROOTASROLE)?;
    if let Some(settings) = &settings.as_ref().borrow().storage.settings {
        if settings.immutable.unwrap_or(true) {
            debug!("Toggling immutable off for config file");
            toggle_lock_config(path, false)?;
        }
    }
    debug!("Resetting dac privilege");
    dac_override_effective(false)?;
    Ok(())
}

pub fn get_settings() -> Result<Rc<RefCell<SettingsFile>>, Box<dyn Error>> {
    // if file does not exist, return default settings
    if !std::path::Path::new(ROOTASROLE).exists() {
        return Ok(rc_refcell!(SettingsFile::default()));
    }
    // if user does not have read permission, try to enable privilege
    let file = open_with_privileges(ROOTASROLE)?;
    let value: Versioning<SettingsFile> = serde_json::from_reader(file)
        .inspect_err(|e| {
            debug!("Error reading file: {}", e);
        })
        .unwrap_or_default();
    read_effective(false).or(dac_override_effective(false))?;
    debug!("{}", serde_json::to_string_pretty(&value)?);
    let settingsfile = rc_refcell!(value.data);
    if Migration::migrate(
        &value.version,
        &mut *settingsfile.as_ref().borrow_mut(),
        version::SETTINGS_MIGRATIONS,
    )? {
        Migration::migrate(
            &value.version,
            &mut *settingsfile
                .as_ref()
                .borrow_mut()
                .config
                .as_ref()
                .borrow_mut(),
            version::JSON_MIGRATIONS,
        )?;
        save_settings(settingsfile.clone())?;
    }
    Ok(settingsfile)
}
