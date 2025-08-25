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

use std::{
    cell::RefCell,
    error::Error,
    fs::{File, Permissions},
    io::{BufReader, Seek},
    ops::{Deref, DerefMut},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    rc::Rc,
};

use bon::{builder, Builder};
use capctl::Cap;
use libc::dev_t;
use log::{debug, warn};
use nix::{
    fcntl::Flock,
    unistd::{getgroups, Gid, Group, Pid, Uid, User},
};
use semver::Version;
use serde::{ser::SerializeMap, Deserialize, Serialize};

//pub mod api;
pub mod database;
//pub mod plugin;
pub mod util;

use strum::EnumString;
use util::{read_with_privileges, write_cbor_config, write_json_config};

use database::{
    migration::Migration,
    structs::SConfig,
    versionning::{Versioning, SETTINGS_MIGRATIONS},
};

use crate::util::{
    has_privileges, is_immutable, open_lock_with_privileges, with_mutable_config, with_privileges,
};

#[derive(Debug, Builder)]
pub struct Cred {
    #[builder(field = User::from_uid(Uid::current()).unwrap().unwrap())]
    pub user: User,
    #[builder(field = getgroups().unwrap().iter().map(|gid| Group::from_gid(*gid).unwrap().unwrap())
    .collect())]
    pub groups: Vec<Group>,
    pub tty: Option<dev_t>,
    #[builder(default = nix::unistd::getppid(), into)]
    pub ppid: Pid,
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    Copy,
    EnumString,
    strum::VariantNames,
)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum StorageMethod {
    #[default]
    #[strum(ascii_case_insensitive)]
    JSON,
    #[strum(ascii_case_insensitive)]
    CBOR,
    //    SQLite,
    //    PostgreSQL,
    //    MySQL,
    //    LDAP,
}

pub struct LockedSettingsFile {
    path: PathBuf,
    fd: Flock<File>, // file descriptor to the opened file, to keep the lock
    pub data: Rc<RefCell<FullSettings>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq, Eq, Default)]
pub struct Settings {
    pub storage: SettingsContent,
}

#[derive(Debug, Clone, Builder, PartialEq, Eq, Default)]
pub struct FullSettings {
    pub storage: SettingsContent,
    pub config: Option<Rc<RefCell<SConfig>>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq, Eq)]
pub struct SettingsContent {
    #[builder(default = StorageMethod::JSON, into)]
    pub method: StorageMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<RemoteStorageSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldap: Option<LdapSettings>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, Default, PartialEq, Eq)]
pub struct RemoteStorageSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(name = not_immutable,with = || false)]
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

impl Serialize for FullSettings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("storage", &self.storage)?;
            // Flatten config fields into the main object
            if let Some(config) = &self.config {
                let config_value =
                    serde_json::to_value(&*config.borrow()).map_err(serde::ser::Error::custom)?;
                if let serde_json::Value::Object(obj) = config_value {
                    for (key, value) in obj {
                        map.serialize_entry(&key, &value)?;
                    }
                }
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("s", &self.storage)?;
            // For non-human readable (CBOR), still flatten but use short keys if needed
            if let Some(config) = &self.config {
                let config_value =
                    serde_json::to_value(&*config.borrow()).map_err(serde::ser::Error::custom)?;
                if let serde_json::Value::Object(obj) = config_value {
                    for (key, value) in obj {
                        map.serialize_entry(&key, &value)?;
                    }
                }
            }
            map.end()
        }
    }
}

impl<'de> Deserialize<'de> for FullSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct FullSettingsVisitor;

        impl<'de> serde::de::Visitor<'de> for FullSettingsVisitor {
            type Value = FullSettings;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct FullSettings")
            }

            fn visit_map<V>(self, mut map: V) -> Result<FullSettings, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut storage = None;
                let mut config_fields = std::collections::HashMap::new();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "storage" | "s" => {
                            if storage.is_some() {
                                return Err(serde::de::Error::duplicate_field("storage"));
                            }
                            storage = Some(map.next_value()?);
                        }
                        // Collect all other fields as potential config fields
                        _ => {
                            config_fields.insert(key, map.next_value::<serde_json::Value>()?);
                        }
                    }
                }

                let storage = storage.ok_or_else(|| serde::de::Error::missing_field("storage"))?;

                // If we have config fields, deserialize them into SConfig
                let config = if !config_fields.is_empty() {
                    let config_value = serde_json::Value::Object(
                        config_fields.into_iter().map(|(k, v)| (k, v)).collect(),
                    );
                    Some(Rc::new(RefCell::new(
                        SConfig::deserialize(config_value).map_err(serde::de::Error::custom)?,
                    )))
                } else {
                    None
                };

                Ok(FullSettings { storage, config })
            }
        }

        deserializer.deserialize_map(FullSettingsVisitor)
    }
}

// Default implementation for Settings
impl Default for SettingsContent {
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

/// This opens, deserialize and locks a settings file, and keeps the file descriptor open to keep the lock
/// it allows to save the settings file later
impl LockedSettingsFile {
    pub fn open<S>(path: S, options: std::fs::OpenOptions, write: bool) -> std::io::Result<Self>
    where
        S: AsRef<Path>,
    {
        if write && path.as_ref().exists() {
            let mut file = read_with_privileges(&path)?;
            if is_immutable(&file)? {
                return Ok(with_mutable_config(&mut file, |_| {
                    let file = open_lock_with_privileges(
                        path.as_ref(),
                        options,
                        nix::fcntl::FlockArg::LockExclusive,
                    )?;

                    return Ok(LockedSettingsFile {
                        path: path.as_ref().to_path_buf(),
                        data: load_full_settings(&path, &file.deref())
                            .unwrap_or(Rc::new(RefCell::new(FullSettings::default()))),
                        fd: file,
                    });
                })?);
            }
        }

        let file =
            open_lock_with_privileges(path.as_ref(), options, nix::fcntl::FlockArg::LockExclusive)?;

        Ok(LockedSettingsFile {
            path: path.as_ref().to_path_buf(),
            data: load_full_settings(&path, &file.deref())
                .unwrap_or(Rc::new(RefCell::new(FullSettings::default()))),
            fd: file,
        })
    }

    pub fn save(&mut self) -> Result<(), Box<dyn Error>> {
        debug!("Saving settings file: {}", self.path.display());
        Migration::migrate(
            &Version::parse(PACKAGE_VERSION).unwrap(),
            &mut *self.data.as_ref().borrow_mut(),
            SETTINGS_MIGRATIONS,
        )?;
        debug!("Migrated settings to version {}", PACKAGE_VERSION);
        let immuable = self
            .data
            .as_ref()
            .borrow()
            .storage
            .settings
            .as_ref()
            .unwrap_or(&RemoteStorageSettings::default())
            .immutable
            .unwrap_or(env!("RAR_CFG_IMMUTABLE") == "true")
            && has_privileges(&[Cap::LINUX_IMMUTABLE])?;
        debug!("Settings file immutable: {}", immuable);
        let separate = if let Some(rss) = &self.data.as_ref().borrow().storage.settings {
            let default_data_path = env!("RAR_CFG_DATA_PATH").to_string().into();
            let data_path = rss.path.as_ref().unwrap_or(&default_data_path);
            if *data_path != self.path {
                Some(data_path.clone())
            } else {
                None
            }
        } else {
            None
        };
        debug!("Settings file separate: {:?}", separate);
        if let Some(data_path) = separate {
            debug!("Saving settings in separate file");
            return self.separate_save(&data_path, immuable);
        }
        let versionned: Versioning<Rc<RefCell<FullSettings>>> = Versioning::new(self.data.clone());
        if immuable {
            debug!("Toggling immutable off for config file");
            with_mutable_config(self.fd.deref_mut(), |file| {
                debug!("Toggled immutable off for config file");
                file.rewind()?;
                write_json_config(&versionned, file)
            })?;
        } else {
            let file = self.fd.deref_mut();
            debug!("Writing config file");
            file.rewind()?;
            debug!("Rewound config file for writing");
            file.set_len(0)?;
            debug!("Truncated config file");
            write_json_config(&versionned, file)?;
            // clear the rest of the file if any
            debug!("Wrote config file");
        }
        Ok(())
    }

    fn separate_save<T>(&mut self, data_path: &T, immutable: bool) -> Result<(), Box<dyn Error>>
    where
        T: AsRef<Path>,
    {
        {
            let storage_method = self.data.as_ref().borrow().storage.method.clone();
            let binding = self.data.as_ref().borrow_mut();
            let config = binding.config.as_ref().take().unwrap();
            let versioned_config: Versioning<Rc<RefCell<SConfig>>> =
                Versioning::new(config.clone());
            let mut file = open_lock_with_privileges(
                data_path.as_ref(),
                std::fs::OpenOptions::new()
                    .truncate(true)
                    .write(true)
                    .create(true)
                    .to_owned(),
                nix::fcntl::FlockArg::LockExclusive,
            )?;
            if immutable {
                with_mutable_config(file.deref_mut(), |file| {
                    write_storage_settings()
                        .path(data_path.as_ref())
                        .fd(file)
                        .method(storage_method)
                        .config(&versioned_config)
                        .set_read_only(!cfg!(test))
                        .set_root_owner(!cfg!(test))
                        .call()
                })?;
            } else {
                write_storage_settings()
                    .path(data_path.as_ref())
                    .fd(&mut file)
                    .method(storage_method)
                    .config(&versioned_config)
                    .set_read_only(!cfg!(test))
                    .set_root_owner(!cfg!(test))
                    .call()?;
            }
        }
        self.data.as_ref().borrow_mut().config = None;
        let versioned_settings: Versioning<Rc<RefCell<FullSettings>>> =
            Versioning::new(self.data.clone());
        self.fd.deref_mut().rewind()?;
        if immutable {
            debug!("Toggling immutable off for config file");
            with_mutable_config(&mut self.fd, |file| {
                write_json_config(&versioned_settings, file)
            })?;
        } else {
            write_json_config(&versioned_settings, self.fd.deref_mut())?;
        }
        Ok(())
    }
}

#[builder]
fn write_storage_settings<P>(
    path: P,
    fd: &mut File,
    method: StorageMethod,
    config: &Versioning<Rc<RefCell<SConfig>>>,
    #[builder(default = false)] set_read_only: bool,
    #[builder(default = false)] set_root_owner: bool,
) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    debug!(
        "Saving in {} : {}",
        path.as_ref().display(),
        serde_json::to_string_pretty(&config).unwrap()
    );
    match method {
        StorageMethod::JSON => write_json_config(config, fd),
        StorageMethod::CBOR => write_cbor_config(config, fd),
    }?;
    if set_read_only {
        if Uid::current().as_raw() == path.as_ref().metadata()?.uid() {
            let perms = Permissions::from_mode(0o400);
            std::fs::set_permissions(path.as_ref(), perms)?;
        } else {
            with_privileges(&[Cap::FOWNER], || {
                let perms = Permissions::from_mode(0o400);
                std::fs::set_permissions(path.as_ref(), perms)
            })?;
        }
    }
    if set_root_owner {
        with_privileges(&[Cap::CHOWN], || {
            nix::unistd::chown(
                path.as_ref(),
                Some(Uid::from_raw(0)),
                Some(Gid::from_raw(0)),
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
        })?;
    }
    Ok(())
}

pub fn read_full_settings<S>(path: &S) -> Result<Rc<RefCell<FullSettings>>, Box<dyn Error>>
where
    S: AsRef<Path>,
{
    // if user does not have read permission, try to enable privilege
    let file = read_with_privileges(path.as_ref())?;
    load_full_settings(path, &file)
}

fn load_full_settings<S: AsRef<Path>>(
    path: &S,
    file: &File,
) -> Result<Rc<RefCell<FullSettings>>, Box<dyn Error>> {
    let value: Versioning<FullSettings> = serde_json::from_reader(file).inspect_err(|e| {
        debug!("Error reading file: {}", e);
    })?;
    let settingsfile = rc_refcell!(value.data);
    debug!("settingsfile: {:?}", settingsfile);
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
        } else if let Some(config) = &binding.config {
            make_weak_config(config);
        }
    }
    Ok(settingsfile)
}

pub fn retrieve_sconfig(
    file_type: &StorageMethod,
    path: &PathBuf,
) -> Result<Rc<RefCell<SConfig>>, Box<dyn Error>> {
    let file = read_with_privileges(path)?;
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
    };
    make_weak_config(&value.data);
    //read_effective(false).or(dac_override_effective(false))?;
    //assert_eq!(value.version.to_string(), PACKAGE_VERSION, "Version mismatch");
    debug!("{}", serde_json::to_string_pretty(&value)?);
    Ok(value.data)
}

pub fn migrate_settings(settings: &mut FullSettings) -> Result<(), Box<dyn Error>> {
    Migration::migrate(
        &Version::parse(PACKAGE_VERSION).unwrap(),
        settings,
        SETTINGS_MIGRATIONS,
    )?;
    Ok(())
}

pub fn get_settings<S>(path: &S) -> Result<Settings, Box<dyn Error>>
where
    S: AsRef<Path>,
{
    // if user does not have read permission, try to enable privilege
    let file = read_with_privileges(path.as_ref())?;
    let value: Versioning<Settings> = serde_json::from_reader(file)
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

    pub struct Defer<F: FnOnce()>(Option<F>);

    impl<F: FnOnce()> Defer<F> {
        pub fn new(f: F) -> Self {
            Defer(Some(f))
        }
    }

    impl<F: FnOnce()> Drop for Defer<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f();
            }
        }
    }

    pub fn defer<F: FnOnce()>(f: F) -> Defer<F> {
        Defer::new(f)
    }

    #[test]
    fn test_get_settings_same_file() {
        // Create a test JSON file
        let value = "/tmp/test_get_settings_same_file.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(value).canonicalize().unwrap_or(value.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let mut file = File::create(value).unwrap();
        let config = Versioning::new(Rc::new(RefCell::new(
            FullSettings::builder()
                .storage(
                    SettingsContent::builder()
                        .method(StorageMethod::JSON)
                        .settings(
                            RemoteStorageSettings::builder()
                                .path(value)
                                .not_immutable()
                                .build(),
                        )
                        .build(),
                )
                .config(
                    SConfig::builder()
                        .role(
                            SRole::builder("test_role")
                                .actor(SActor::user(0).build())
                                .task(
                                    STask::builder("test_task")
                                        .cred(SCredentials::builder().setuid(0).setgid(0).build())
                                        .commands(
                                            SCommands::builder(SetBehavior::None)
                                                .add(vec![SCommand::Simple(
                                                    "/usr/bin/true".to_string(),
                                                )])
                                                .build(),
                                        )
                                        .build(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )));
        write_json_config(&config, &mut file).unwrap();
        let settings = read_full_settings(&value).unwrap();
        assert_eq!(*config.data.borrow(), *settings.as_ref().borrow());
        fs::remove_file(value).unwrap();
    }

    #[test]
    fn test_get_settings_different_file() {
        // Create a test JSON file
        let external_file_path = "/tmp/test_get_settings_different_file_external.json";
        let test_file_path = "/tmp/test_get_settings_different_file.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file_path)
                .canonicalize()
                .unwrap_or(test_file_path.into());
            if std::fs::remove_file(&test_file_path).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let _cleanup2 = defer(|| {
            let filename = PathBuf::from(external_file_path)
                .canonicalize()
                .unwrap_or(external_file_path.into());
            if std::fs::remove_file(&external_file_path).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let mut external_file = File::create(external_file_path).unwrap();
        let mut test_file = File::create(test_file_path).unwrap();
        let settings_config = Versioning::new(Rc::new(RefCell::new(
            FullSettings::builder()
                .storage(
                    SettingsContent::builder()
                        .method(StorageMethod::JSON)
                        .settings(
                            RemoteStorageSettings::builder()
                                .path(external_file_path)
                                .not_immutable()
                                .build(),
                        )
                        .build(),
                )
                .config(
                    SConfig::builder()
                        .role(SRole::builder("IGNORED").build())
                        .build(),
                )
                .build(),
        )));
        write_json_config(&settings_config, &mut test_file).unwrap();
        let config = SConfig::builder()
            .role(
                SRole::builder("test_role")
                    .actor(SActor::user(0).build())
                    .task(
                        STask::builder("test_task")
                            .cred(SCredentials::builder().setuid(0).setgid(0).build())
                            .commands(
                                SCommands::builder(SetBehavior::None)
                                    .add(vec![SCommand::Simple("/usr/bin/true".to_string())])
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .build();
        write_json_config(&Versioning::new(config.clone()), &mut external_file).unwrap();
        let settings = read_full_settings(&test_file_path).unwrap();
        assert_eq!(
            *config.borrow(),
            *settings.as_ref().borrow().config.as_ref().unwrap().borrow()
        );
        fs::remove_file(test_file_path).unwrap();
        fs::remove_file(external_file_path).unwrap();
    }

    #[test]
    fn test_save_settings_same_file() {
        let test_file = "/tmp/test_save_settings_same_file.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or(test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        // Create a test JSON file
        let config = Rc::new(RefCell::new(
            FullSettings::builder()
                .storage(
                    SettingsContent::builder()
                        .method(StorageMethod::JSON)
                        .settings(
                            RemoteStorageSettings::builder()
                                .path(test_file)
                                .not_immutable()
                                .build(),
                        )
                        .build(),
                )
                .config(
                    SConfig::builder()
                        .role(
                            SRole::builder("test_role")
                                .actor(SActor::user(0).build())
                                .task(
                                    STask::builder("test_task")
                                        .cred(SCredentials::builder().setuid(0).setgid(0).build())
                                        .commands(
                                            SCommands::builder(SetBehavior::None)
                                                .add(vec![SCommand::Simple(
                                                    "/usr/bin/true".to_string(),
                                                )])
                                                .build(),
                                        )
                                        .build(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .build(),
        ));
        let file = File::create(test_file).unwrap();
        let file = Flock::lock(file, nix::fcntl::FlockArg::LockExclusive).unwrap();
        let mut settingsfile = LockedSettingsFile {
            path: PathBuf::from(test_file),
            fd: file,
            data: config.clone(),
        };
        settingsfile.save().unwrap();
        let settings = read_full_settings(&test_file).unwrap();
        assert_eq!(*config.borrow(), *settings.borrow());
        fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_save_settings_different_file() {
        let external_file = "/tmp/test_save_settings_different_file_external.json";
        let test_file = "/tmp/test_save_settings_different_file.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or(test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let _cleanup2 = defer(|| {
            let filename = PathBuf::from(external_file)
                .canonicalize()
                .unwrap_or(external_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let sconfig = SConfig::builder()
            .role(
                SRole::builder("test_role")
                    .actor(SActor::user(0).build())
                    .task(
                        STask::builder("test_task")
                            .cred(SCredentials::builder().setuid(0).setgid(0).build())
                            .commands(
                                SCommands::builder(SetBehavior::None)
                                    .add(vec![SCommand::Simple("/usr/bin/true".to_string())])
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .build();
        // Create a test JSON file
        let config = Rc::new(RefCell::new(
            FullSettings::builder()
                .storage(
                    SettingsContent::builder()
                        .method(StorageMethod::JSON)
                        .settings(
                            RemoteStorageSettings::builder()
                                .path(external_file)
                                .not_immutable()
                                .build(),
                        )
                        .build(),
                )
                .config(sconfig.clone())
                .build(),
        ));
        let file = File::create(test_file).unwrap();
        let file = Flock::lock(file, nix::fcntl::FlockArg::LockExclusive).unwrap();
        let mut settingsfile = LockedSettingsFile {
            path: PathBuf::from(test_file),
            fd: file,
            data: config.clone(),
        };
        settingsfile.save().unwrap();
        //assert that test_external.json contains /usr/bin/true
        let mut file = read_with_privileges(external_file).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(content.contains("/usr/bin/true"));

        let mut file = read_with_privileges(test_file).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(!content.contains("/usr/bin/true"));

        let settings = read_full_settings(&test_file).unwrap();
        assert_eq!(
            *sconfig.borrow(),
            *settings.borrow().config.as_ref().unwrap().borrow()
        );
        settings.as_ref().borrow_mut().config = None;
        assert_eq!(*config.borrow(), *settings.borrow());
        fs::remove_file(test_file).unwrap();
        fs::remove_file(external_file).unwrap();
    }

    #[test]
    fn test_save_cbor_format() {
        let external_file = "/tmp/test_save_cbor_format.bin";
        let test_file = "/tmp/test_save_cbor_format.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or(test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let _cleanup2 = defer(|| {
            let filename = PathBuf::from(external_file)
                .canonicalize()
                .unwrap_or(external_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let sconfig = SConfig::builder()
            .role(
                SRole::builder("test_role")
                    .actor(SActor::user(0).build())
                    .task(
                        STask::builder("test_task")
                            .cred(SCredentials::builder().setuid(0).setgid(0).build())
                            .commands(
                                SCommands::builder(SetBehavior::None)
                                    .add(vec![SCommand::Simple("/usr/bin/true".to_string())])
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .build();
        let settings = Rc::new(RefCell::new(
            FullSettings::builder()
                .storage(
                    SettingsContent::builder()
                        .method(StorageMethod::CBOR)
                        .settings(
                            RemoteStorageSettings::builder()
                                .path(external_file)
                                .not_immutable()
                                .build(),
                        )
                        .build(),
                )
                .config(sconfig.clone())
                .build(),
        ));
        let file = File::create(test_file).unwrap();
        let file = Flock::lock(file, nix::fcntl::FlockArg::LockExclusive).unwrap();
        let mut settingsfile = LockedSettingsFile {
            path: PathBuf::from(test_file),
            fd: file,
            data: settings.clone(),
        };
        settingsfile.save().unwrap();
        //asset that external_file is a binary file
        let mut file = read_with_privileges(external_file).unwrap();
        // try to parse as ciborium
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        let deserialized: Versioning<Rc<RefCell<SConfig>>> =
            cbor4ii::serde::from_reader(&content[..]).unwrap();
        assert_eq!(deserialized.version.to_string(), PACKAGE_VERSION);
        fs::remove_file(test_file).unwrap();
        fs::remove_file(external_file).unwrap();
    }
}
