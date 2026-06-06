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

pub const PACKAGE_VERSION: semver::Version = semver::Version::new(
    result::unwrap!(u64::from_str_radix(env!("CARGO_PKG_VERSION_MAJOR"), 10)),
    result::unwrap!(u64::from_str_radix(env!("CARGO_PKG_VERSION_MINOR"), 10)),
    result::unwrap!(u64::from_str_radix(env!("CARGO_PKG_VERSION_PATCH"), 10)),
);

use std::{io::Error, path::PathBuf};

use bon::Builder;
use konst::result;
use libc::dev_t;
use nix::unistd::{Gid, Group, Pid, Uid, User, getgroups};
use serde::{Deserialize, Serialize};

//pub mod api;
pub mod database;
//pub mod plugin;
pub mod file;
#[cfg(feature = "ldap")]
pub mod ldap;
pub mod util;

#[cfg(feature = "ldap")]
use crate::ldap::LdapSettings;
use crate::util::{Either, RAR_CFG_TYPE, StorageMethod};

#[derive(Debug, Builder)]
#[allow(clippy::missing_errors_doc)]
pub struct Cred {
    #[builder(with = || -> Result<_,Error> {
        let uid = Uid::current();
        User::from_uid(uid)?.ok_or_else(|| Error::other("User not found"))})
    ]
    pub user: User,
    #[builder(with = || -> Result<_,Error> {
        Ok(getgroups()?
        .iter()
        .map(|gid| Either::from(Group::from_gid(*gid).ok().flatten().ok_or(*gid)))
        .collect())
    })]
    pub groups: Vec<Either<Group, Gid>>,
    pub tty: Option<dev_t>,
    #[builder(default = nix::unistd::getppid(), into)]
    pub ppid: Pid,
    #[builder(with = || -> Result<_, std::io::Error> { std::env::current_dir() })]
    pub curdir: PathBuf,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, Default, PartialEq, Eq)]
pub struct RemoteStorageSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(name = not_immutable,with = || false)]
    pub immutable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub path: Option<PathBuf>,
    #[cfg(feature = "sgbd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[cfg(feature = "sgbd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[cfg(feature = "sgbd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<ConnectionAuth>,
    #[cfg(feature = "sgbd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[cfg(feature = "sgbd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[cfg(feature = "sgbd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table_prefix: Option<String>,
    #[cfg(feature = "sgbd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<Properties>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Properties {
    pub use_unicode: bool,
    pub character_encoding: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq, Eq, Default)]
pub struct SettingsContent {
    #[builder(default = RAR_CFG_TYPE, into)]
    pub method: StorageMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<RemoteStorageSettings>,

    #[cfg(feature = "ldap")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldap: Option<LdapSettings>,
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

#[cfg(feature = "sgbd")]
compile_error!("SGBD feature is not yet implemented");

#[cfg(feature = "ldap")]
compile_error!("LDAP feature is not yet implemented");
