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

const FILEPATH : &str = "/etc/security/rootasrole_storage.json";
pub const ROOTASROLE : &str = "/etc/security/rootasrole.json";


use std::{cell::RefCell, path::PathBuf, rc::Rc};

use serde::Deserialize;

use super::database::structs::SConfig;

#[derive(Deserialize, Debug)]
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

#[derive(Deserialize, Debug)]
pub struct Settings {
    pub storage_method: StorageMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_storage_settings: Option<RemoteStorageSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldap: Option<LdapSettings>,
}

#[derive(Deserialize, Debug)]
pub struct RemoteStorageSettings {
    pub path: Option<PathBuf>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub auth: Option<ConnectionAuth>,
    
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table_prefix: Option<String>,
    pub properties: Option<Properties>,
}

#[derive(Deserialize, Debug)]
pub struct ConnectionAuth {
    pub user: String,
    pub password: Option<String>,
    pub client_ssl: Option<ClientSsl>,
}

#[derive(Deserialize, Debug)]
pub struct ClientSsl {
    pub enabled: bool,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Properties {
    pub use_unicode: bool,
    pub character_encoding: String,
}

#[derive(Deserialize, Debug)]
pub struct LdapSettings {
    pub enabled: bool,
    pub host: String,
    pub port: Option<u16>,
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
            storage_method: StorageMethod::JSON,
            remote_storage_settings: Some(RemoteStorageSettings::default()),
            ldap: None,
        }
    }
}

impl Default for RemoteStorageSettings {
    fn default() -> Self {
        Self {
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

pub fn get_settings() -> Settings {
    // if file does not exist, return default settings
    if !std::path::Path::new(FILEPATH).exists() {
        return Settings::default();
    }
    let file = std::fs::File::open(FILEPATH).expect("Failed to open file");
    serde_json::from_reader(file).unwrap_or_default()
}