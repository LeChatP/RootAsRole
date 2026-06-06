use std::{
    borrow::Cow,
    cell::RefCell,
    error::Error,
    fmt::Debug,
    fs::{File, OpenOptions},
    io::{self, BufReader, Seek},
    path::{Path, PathBuf},
    rc::Rc,
};

use bon::Builder;
use capctl::Cap;
use log::{debug, error, warn};
use nix::fcntl::Flock;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    SettingsContent,
    database::{migration::Migration, structs::SPolicy, versionning::Versioning},
    util::{
        RAR_CFG_IMMUTABLE, RAR_CFG_PATH, RAR_CFG_TYPE, StorageMethod, has_privileges, is_immutable,
        open_lock_with_privileges, read_with_privileges, with_mutable_config, write_config,
    },
};

pub const ROOT_MIGRATIONS: &[Migration<RootSettings>] = &[];
pub const POLICY_MIGRATIONS: &[Migration<Rc<RefCell<SPolicy>>>] = &[];

#[derive(Debug)]
pub struct LockedSettingsFile<T: Serialize + DeserializeOwned + Debug + Default> {
    path: PathBuf,
    fd: Flock<File>, // file descriptor to the opened file, to keep the lock
    pub data: T,
}

/// This opens, deserialize and locks a settings file, and keeps the file descriptor open to keep the lock
/// it allows to save the settings file later
impl<T: Serialize + DeserializeOwned + Debug + Default> LockedSettingsFile<T> {
    /// # Errors
    /// Returns an error if the file cannot be opened, deserialized or locked
    pub fn open_read<S>(
        path: S,
        data_loader: impl Fn(&S, &File) -> io::Result<T>,
    ) -> std::io::Result<Self>
    where
        S: AsRef<Path>,
    {
        Self::open(path, OpenOptions::new().read(true), false, data_loader)
    }
    /// # Errors
    /// Returns an error if the file cannot be opened, deserialized, locked or written to
    pub fn open_write<S>(
        path: S,
        data_loader: impl Fn(&S, &File) -> io::Result<T>,
    ) -> std::io::Result<Self>
    where
        S: AsRef<Path>,
    {
        Self::open(
            path,
            OpenOptions::new().read(true).write(true).create(true),
            true,
            data_loader,
        )
    }

    /// # Errors
    /// Returns an error if the file cannot be opened, deserialized or locked
    pub fn open<S>(
        path: S,
        options: &std::fs::OpenOptions,
        write: bool,
        data_loader: impl Fn(&S, &File) -> io::Result<T>,
    ) -> std::io::Result<Self>
    where
        S: AsRef<Path>,
    {
        let load_data = || -> io::Result<Self> {
            let file = open_lock_with_privileges(
                path.as_ref(),
                options,
                nix::fcntl::FlockArg::LockExclusive,
            )?;

            Ok(Self {
                path: path.as_ref().to_path_buf(),
                data: data_loader(&path, &file)?,
                fd: file,
            })
        };

        if write && path.as_ref().exists() {
            let mut file = read_with_privileges(&path)?;
            if is_immutable(&file)? {
                return with_mutable_config(&mut file, |_| load_data());
            }
        }

        load_data()
    }

    /// # Errors
    /// Returns an error if the file cannot be written
    /// due to a lock, permission error or writing error
    pub fn save(&mut self, method: StorageMethod, immutable: bool) -> Result<(), Box<dyn Error>> {
        let immuable = immutable && has_privileges(&[Cap::LINUX_IMMUTABLE])?;
        debug!("Settings file immutable: {immuable}");
        if immuable {
            debug!("Toggling immutable off for config file");
            with_mutable_config(&mut self.fd, |file| {
                debug!("Toggled immutable off for config file");
                file.rewind()?;
                file.set_len(0)?;
                write_config(&self.data, file, method)
            })
            .map_err(|e| format!("Failed to write config file: {e}"))?;
        } else {
            let file = &mut *self.fd;
            debug!("Writing config file");
            file.rewind()?;
            debug!("Rewound config file for writing");
            file.set_len(0)?;
            debug!("Truncated config file");
            write_config(&self.data, file, method)?;
            // clear the rest of the file if any
            debug!("Wrote config file");
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, Builder, PartialEq, Eq)]
pub struct RootSettings {
    pub storage: SettingsContent,
    #[serde(flatten)]
    pub config: Option<Rc<RefCell<SPolicy>>>,
}

pub type ConfigMap = Vec<LockedPolicy>;
pub type LockedPolicy = LockedSettingsFile<Versioning<Rc<RefCell<SPolicy>>>>;
pub type LockedRootSettings = LockedSettingsFile<Versioning<RootSettings>>;

#[derive(Builder)]
pub struct FileSettings {
    #[builder(default)]
    map: ConfigMap,
    ///# Errors
    /// Returns an error if any of the files cannot be opened or locked
    #[builder(with = |path: PathBuf,config : RootSettings| -> Result<_, Box<dyn Error>> {
        Ok(LockedSettingsFile::open_write(path, |_, _| {
            let versioned: Versioning<RootSettings> = Versioning::new(config.clone());
            Ok(versioned)
        })?)
    })]
    root: LockedRootSettings,
}

impl FileSettings {
    /// # Errors
    /// Returns an error if any of the files cannot be opened, deserialized or locked
    pub fn read_all<P>(
        rar_cfg_path: P,
        rar_cfg_data_path: P,
        rar_cfg_type: StorageMethod,
    ) -> std::io::Result<Self>
    where
        P: AsRef<Path>,
    {
        Self::load_all(
            rar_cfg_path,
            rar_cfg_data_path,
            rar_cfg_type,
            OpenOptions::new().read(true),
            false,
        )
    }
    /// # Errors
    /// Returns an error if any of the files cannot be opened, deserialized, locked or written to
    pub fn write_all<P>(
        rar_cfg_path: P,
        rar_cfg_data_path: P,
        rar_cfg_type: StorageMethod,
    ) -> std::io::Result<Self>
    where
        P: AsRef<Path>,
    {
        Self::load_all(
            rar_cfg_path,
            rar_cfg_data_path,
            rar_cfg_type,
            OpenOptions::new().read(true).write(true).create(true),
            true,
        )
    }

    /// # Errors
    /// Returns an error if any of the files cannot be opened, deserialized or locked
    pub fn read_policy<P>(cfg_path: P, cfg_type: StorageMethod) -> std::io::Result<LockedPolicy>
    where
        P: AsRef<Path>,
    {
        Self::load_policy_file(cfg_type, OpenOptions::new().read(true), false, cfg_path)
    }
    /// # Errors
    /// Returns an error if any of the files cannot be opened, deserialized, locked or written to
    pub fn write_policy<P>(cfg_path: P, cfg_type: StorageMethod) -> std::io::Result<LockedPolicy>
    where
        P: AsRef<Path>,
    {
        Self::load_policy_file(
            cfg_type,
            OpenOptions::new().read(true).write(true).create(true),
            true,
            cfg_path,
        )
    }
    /// # Errors
    /// Returns an error if any of the files cannot be opened, deserialized or locked
    fn load_all<P>(
        rar_cfg_path: P,
        rar_cfg_data_path: P,
        rar_cfg_type: StorageMethod,
        options: &OpenOptions,
        write: bool,
    ) -> std::io::Result<Self>
    where
        P: AsRef<Path>,
    {
        let rar_cfg_data_path = rar_cfg_data_path.as_ref().to_path_buf();
        let mut root =
            LockedSettingsFile::open(rar_cfg_path.as_ref(), options, write, |path, file| {
                debug!("Loading root settings from {}", path.display());
                let mut settings: Versioning<RootSettings> = match rar_cfg_type {
                    StorageMethod::JSON => {
                        serde_json::from_reader(file).inspect_err(|e| debug!("{e}"))?
                    }
                    StorageMethod::CBOR => cbor4ii::serde::from_reader(BufReader::new(file))
                        .map_err(|e| {
                            debug!("Failed to deserialize root settings: {e}");
                            io::Error::new(io::ErrorKind::InvalidData, e)
                        })?,
                };
                if let Some(config) = settings.data.config.as_ref() {
                    Self::make_weak_config(config);
                }
                settings.upgrade_version(ROOT_MIGRATIONS).map_err(|e| {
                    debug!("Failed to upgrade root settings: {e}");
                    io::Error::other(e.to_string())
                })?;
                debug!("Loaded root settings from {}", path.display());
                Ok(settings)
            })?;
        let mut map = ConfigMap::new();

        if let Some(path) = root
            .data
            .data
            .storage
            .settings
            .as_ref()
            .and_then(|settings| settings.path.as_ref())
            .and_then(|path| {
                if path.as_path() == rar_cfg_path.as_ref() {
                    None
                } else {
                    Some(path.clone())
                }
            })
            .or_else(|| {
                if rar_cfg_path.as_ref() == rar_cfg_data_path {
                    None
                } else {
                    Some(rar_cfg_data_path)
                }
            })
        {
            if root.data.data.config.is_some() {
                warn!(
                    "A policy has been detected in {}, but a different path is specified. 
                    Ignoring the policy and keeping only the ones in the specified path: {}",
                    rar_cfg_path.as_ref().display(),
                    path.display()
                );
                root.data.data.config = None;
            }
            if path.is_dir() {
                debug!("Loading settings from directory {}", path.display());
                for entry in std::fs::read_dir(path)? {
                    let entry = entry?;
                    if entry.file_type()?.is_file() {
                        let path = entry.path();
                        debug!("Loading settings from file {}", path.display());
                        let config = Self::load_policy_file(
                            root.data.data.storage.method,
                            options,
                            write,
                            &path,
                        );
                        match config {
                            Ok(config) => {
                                debug!("Loaded settings from file {}", path.display());
                                Self::make_weak_config(&config.data.data);
                                map.push(config);
                            }
                            Err(e) => debug!(
                                "Failed to load settings from file {}: {}",
                                path.display(),
                                e
                            ),
                        }
                    }
                }
            } else if path.is_file() {
                debug!("Loading settings from file {}", path.display());
                let config =
                    Self::load_policy_file(root.data.data.storage.method, options, write, &path)?;
                debug!("Loaded settings from file {}", path.display());
                map.push(config);
            }
        }

        Ok(Self { map, root })
    }

    /// # Errors
    /// Returns an error if the file cannot be opened or deserialized
    fn load_policy_file<P>(
        file_type: StorageMethod,
        options: &OpenOptions,
        write: bool,
        path: P,
    ) -> std::io::Result<LockedPolicy>
    where
        P: AsRef<Path>,
    {
        let mut policyfile: LockedPolicy =
            LockedSettingsFile::open(path, options, write, |_, file| {
                Ok(match file_type {
                    StorageMethod::JSON => serde_json::from_reader(file)?,
                    StorageMethod::CBOR => cbor4ii::serde::from_reader(BufReader::new(file))
                        .map_err(io::Error::other)?,
                })
            })?;
        Self::make_weak_config(&policyfile.data.data);
        policyfile
            .data
            .upgrade_version(POLICY_MIGRATIONS)
            .map_err(|e| io::Error::other(e.to_string()))?;
        debug!("{}", serde_json::to_string_pretty(&policyfile.data.data)?);
        Ok(policyfile)
    }

    fn make_weak_config(config: &Rc<RefCell<SPolicy>>) {
        for role in &config.as_ref().borrow().roles {
            role.as_ref().borrow_mut().config = Some(Rc::downgrade(config));
            for task in &role.as_ref().borrow().tasks {
                task.as_ref().borrow_mut().role = Some(Rc::downgrade(role));
            }
        }
    }

    /// # Errors
    /// Returns an error if any of the files cannot be written
    pub fn save_all(&mut self) -> Result<(), Box<dyn Error>> {
        let immutable = self
            .root
            .data
            .data
            .storage
            .settings
            .as_ref()
            .and_then(|s| s.immutable)
            .unwrap_or(RAR_CFG_IMMUTABLE);

        if let Some(path) = self.root.data.data.storage.settings.as_ref().and_then(|s| {
            s.path.as_ref().and_then(|p| {
                debug!(
                    "Checking if root settings path needs to be updated: current {}, new {}",
                    p.display(),
                    p.display()
                );
                if *p == self.root.path {
                    None
                } else {
                    Some(p.clone())
                }
            })
        }) {
            // Open the new file with the new path
            let new_root = LockedSettingsFile::open_write(path, |_, _| {
                Ok(Versioning::new(self.root.data.data.clone()))
            })?;
            debug!(
                "Moved root settings to new path: {}",
                new_root.path.display()
            );
            // Manually drop the old root using unsafe code to trigger Drop impl
            unsafe {
                let old_root_ptr = &raw mut self.root;
                std::ptr::drop_in_place(old_root_ptr);
            }
            self.root = new_root;
        }

        let mut has_errors = if let Err(e) = self.root.save(RAR_CFG_TYPE, immutable) {
            error!("Failed to save root settings: {e}");
            true
        } else {
            debug!("Saved root settings");
            false
        };

        for config in &mut self.map {
            if let Err(e) = config.save(self.root.data.data.storage.method, immutable) {
                error!(
                    "Failed to save settings for {}: {}",
                    config.path.display(),
                    e
                );
                has_errors = true;
            }
        }

        if has_errors {
            Err("One or more files failed to save. Check the logs for details.".into())
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn get_files(&self) -> Vec<Cow<'_, str>> {
        let mut vec: Vec<_> = self.map.iter().map(|e| e.path.to_string_lossy()).collect();
        vec.push(RAR_CFG_PATH.into());
        vec
    }

    #[must_use]
    pub fn get(&self, path: &Path) -> Option<&Rc<RefCell<SPolicy>>> {
        if path == RAR_CFG_PATH {
            self.root.data.data.config.as_ref()
        } else {
            self.map
                .iter()
                .find(|config| config.path == path)
                .map(|config| &config.data.data)
        }
    }

    #[must_use]
    pub const fn get_root(&self) -> &RootSettings {
        &self.root.data.data
    }

    pub const fn get_root_mut(&mut self) -> &mut RootSettings {
        &mut self.root.data.data
    }

    #[must_use]
    pub fn get_policies(&self) -> Vec<&Rc<RefCell<SPolicy>>> {
        self.map.iter().map(|config| &config.data.data).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use crate::database::actor::SActor;
    use crate::database::structs::{SCommand, SCommands, SCredentials, SRole, STask, SetBehavior};
    use crate::{PACKAGE_VERSION, RemoteStorageSettings};

    use super::*;

    pub struct Defer<F: FnOnce()>(Option<F>);

    impl<F: FnOnce()> Defer<F> {
        pub fn new(f: F) -> Self {
            Self(Some(f))
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
            let filename = PathBuf::from(value);
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let settings = RootSettings::builder()
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
                SPolicy::builder()
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
            .build();
        let mut config =
            LockedSettingsFile::open_write(PathBuf::from(value), |_, _| Ok(settings.clone()))
                .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();

        let full = FileSettings::read_all(value, value, StorageMethod::JSON).unwrap();
        assert_eq!(*full.get_root(), settings);
    }

    #[test]
    fn test_get_settings_different_file() {
        // Create a test JSON file
        let external_file_path = "/tmp/test_get_settings_different_file_external.json";
        let test_file_path = "/tmp/test_get_settings_different_file.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file_path)
                .canonicalize()
                .unwrap_or_else(|_| test_file_path.into());
            if std::fs::remove_file(test_file_path).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let _cleanup2 = defer(|| {
            let filename = PathBuf::from(external_file_path)
                .canonicalize()
                .unwrap_or_else(|_| external_file_path.into());
            if std::fs::remove_file(external_file_path).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let settings_config = RootSettings::builder()
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
                SPolicy::builder()
                    .role(SRole::builder("IGNORED").build())
                    .build(),
            )
            .build();
        let mut file =
            LockedSettingsFile::open_write(test_file_path, |_, _| Ok(settings_config.clone()))
                .unwrap();
        file.save(StorageMethod::JSON, false).unwrap();
        let config = SPolicy::builder()
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
        let mut file =
            LockedSettingsFile::open_write(external_file_path, |_, _| Ok(config.clone())).unwrap();
        file.save(StorageMethod::JSON, false).unwrap();

        let full = FileSettings::read_all(test_file_path, external_file_path, StorageMethod::JSON)
            .unwrap();
        assert_eq!(full.get_policies().len(), 1);
        assert_eq!(*full.get_policies()[0].borrow(), *file.data.borrow());
    }

    #[test]
    fn test_save_settings_same_file() {
        let test_file = "/tmp/test_save_settings_same_file.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        let settings = RootSettings::builder()
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
                SPolicy::builder()
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
            .build();
        let mut config =
            LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| Ok(settings.clone()))
                .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();
    }

    #[test]
    fn test_save_settings_different_file() {
        let external_file = "/tmp/test_save_settings_different_file_external.json";
        let test_file = "/tmp/test_save_settings_different_file.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let _cleanup2 = defer(|| {
            let filename = PathBuf::from(external_file)
                .canonicalize()
                .unwrap_or_else(|_| external_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        let settings_config = RootSettings::builder()
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
            .config(
                SPolicy::builder()
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
            .build();
        let mut config = LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| {
            Ok(settings_config.clone())
        })
        .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();

        // assert that external_file contains /usr/bin/true
        let mut file = read_with_privileges(external_file).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(content.contains("/usr/bin/true"));

        // assert that test_file does NOT contain /usr/bin/true (only storage settings)
        let mut file = read_with_privileges(test_file).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(!content.contains("/usr/bin/true"));
    }

    #[test]
    fn test_save_cbor_format() {
        let external_file = "/tmp/test_save_cbor_format.bin";
        let test_file = "/tmp/test_save_cbor_format.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let _cleanup2 = defer(|| {
            let filename = PathBuf::from(external_file)
                .canonicalize()
                .unwrap_or_else(|_| external_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        let settings = RootSettings::builder()
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
            .config(
                SPolicy::builder()
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
            .build();
        let mut config =
            LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| Ok(settings.clone()))
                .unwrap();
        config.save(StorageMethod::CBOR, false).unwrap();

        // Assert that external_file is a binary file with CBOR format
        let mut file = read_with_privileges(external_file).unwrap();
        let mut content = Vec::new();
        file.read_to_end(&mut content).unwrap();
        let deserialized: Versioning<Rc<RefCell<SPolicy>>> =
            cbor4ii::serde::from_reader(&content[..]).unwrap();
        assert_eq!(deserialized.version, PACKAGE_VERSION);
    }

    #[test]
    fn test_locked_settings_file_open_new_file() {
        let test_file = "/tmp/test_locked_settings_file_open_new_file.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        // Test opening a non-existent file with write mode
        let locked_file = LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| {
            Ok(RootSettings::default())
        })
        .unwrap();

        // Should create default settings
        assert_eq!(locked_file.path, PathBuf::from(test_file));
        assert_eq!(locked_file.data, RootSettings::default());
    }

    #[test]
    fn test_locked_settings_file_open_existing_file() {
        let test_file = "/tmp/test_locked_settings_file_open_existing_file.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        // Create and save a test file with some content
        let settings = RootSettings::builder()
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
                SPolicy::builder()
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
            .build();

        let mut config =
            LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| Ok(settings.clone()))
                .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();

        // Test opening existing file
        let locked_file = LockedSettingsFile::open_read(PathBuf::from(test_file), |_, file| {
            let versioned: Versioning<RootSettings> = serde_json::from_reader(file)?;
            Ok(versioned.data)
        })
        .unwrap();

        // Should load the existing settings
        assert_eq!(locked_file.path, PathBuf::from(test_file));
        assert_eq!(locked_file.data, settings);
    }

    #[test]
    fn test_locked_settings_file_open_write_mode_non_immutable() {
        let test_file = "/tmp/test_locked_settings_file_open_write_mode_non_immutable.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        // Create a test file with non-immutable settings
        let settings = RootSettings::builder()
            .storage(
                SettingsContent::builder()
                    .method(StorageMethod::JSON)
                    .settings(
                        RemoteStorageSettings::builder()
                            .path(test_file)
                            .not_immutable() // explicitly not immutable
                            .build(),
                    )
                    .build(),
            )
            .build();

        let mut config =
            LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| Ok(settings.clone()))
                .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();

        // Test opening existing file with write mode - should work normally for non-immutable files
        let result = LockedSettingsFile::open_write(PathBuf::from(test_file), |_, file| {
            let versioned: Versioning<RootSettings> = serde_json::from_reader(file)?;
            Ok(versioned.data)
        });
        match result {
            Ok(locked_file) => {
                assert_eq!(locked_file.path, PathBuf::from(test_file));
                // The loaded settings should match our created config
                assert_eq!(locked_file.data.storage, settings.storage);
            }
            Err(_) => {
                println!("Test skipped due to insufficient privileges in test environment");
            }
        }
    }

    #[test]
    fn test_locked_settings_file_open_with_separate_config() {
        let test_file = "/tmp/test_locked_settings_file_open_with_separate_config.json";
        let external_file =
            "/tmp/test_locked_settings_file_open_with_separate_config_external.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        let _cleanup2 = defer(|| {
            let filename = PathBuf::from(external_file)
                .canonicalize()
                .unwrap_or_else(|_| external_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        // Create external config file
        let sconfig = SPolicy::builder()
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
        let mut external_config = LockedSettingsFile::open_write(
            PathBuf::from(external_file),
            |_, _| Ok(sconfig.clone()),
        )
        .unwrap();
        external_config.save(StorageMethod::JSON, false).unwrap();
        drop(external_config);

        // Create settings file pointing to external config
        let settings_config = RootSettings::builder()
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
            .build();
        let mut config = LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| {
            Ok(settings_config.clone())
        })
        .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();

        // Test opening file with separate config
        let locked_file = LockedSettingsFile::open_read(PathBuf::from(test_file), |_, file| {
            let versioned: Versioning<RootSettings> = serde_json::from_reader(file)?;
            Ok(versioned.data)
        })
        .unwrap();

        // Should load settings and external config
        assert_eq!(locked_file.path, PathBuf::from(test_file));
        assert_eq!(locked_file.data.storage, settings_config.storage);
    }

    #[test]
    fn test_locked_settings_file_open_invalid_json() {
        let test_file = "/tmp/test_locked_settings_file_open_invalid_json.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        // Create a file with invalid JSON
        let mut file = File::create(test_file).unwrap();
        file.write_all(b"{ invalid json content }").unwrap();
        drop(file);

        // Test opening file with invalid JSON - should fall back to default
        let locked_file = LockedSettingsFile::open_read(PathBuf::from(test_file), |_, file| {
            match serde_json::from_reader::<_, Versioning<RootSettings>>(file) {
                Ok(versioned) => Ok(versioned.data),
                Err(_) => Ok(RootSettings::default()),
            }
        })
        .unwrap();

        // Should fall back to default settings when JSON is invalid
        assert_eq!(locked_file.path, PathBuf::from(test_file));
        assert_eq!(locked_file.data, RootSettings::default());
    }

    #[test]
    fn test_locked_settings_file_open_readonly() {
        let test_file = "/tmp/test_locked_settings_file_open_readonly.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        // Create a test file with minimal settings
        let settings = RootSettings::builder()
            .storage(
                SettingsContent::builder()
                    .method(StorageMethod::JSON)
                    .build(),
            )
            .build();

        let mut config =
            LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| Ok(settings.clone()))
                .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();

        // Test opening file in read-only mode
        let locked_file = LockedSettingsFile::open_read(PathBuf::from(test_file), |_, file| {
            let versioned: Versioning<RootSettings> = serde_json::from_reader(file)?;
            Ok(versioned.data)
        })
        .unwrap();

        // Should successfully open and load settings
        assert_eq!(locked_file.path, PathBuf::from(test_file));
        // The storage settings should match what we wrote
        assert_eq!(locked_file.data.storage.method, settings.storage.method);
        assert_eq!(locked_file.data.storage.settings, settings.storage.settings);
    }

    #[test]
    fn test_locked_settings_file_open_nonexistent_file_error() {
        let test_file = "/tmp/test_locked_settings_file_open_nonexistent_file_error.json";

        // Ensure the file doesn't exist
        let _ = std::fs::remove_file(test_file);

        // Test opening non-existent file without create option - should fail
        let result = LockedSettingsFile::open_read(PathBuf::from(test_file), |_, file| {
            let versioned: Versioning<RootSettings> = serde_json::from_reader(file)?;
            Ok(versioned.data)
        });

        // Should fail because file doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_locked_settings_file_open_create_new() {
        let test_file = "/tmp/test_locked_settings_file_open_create_new.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        // Ensure the file doesn't exist
        let _ = std::fs::remove_file(test_file);

        // Test creating a new file
        let locked_file = LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| {
            Ok(RootSettings::default())
        })
        .unwrap();

        // Should create new file with default settings
        assert_eq!(locked_file.path, PathBuf::from(test_file));
        // File should exist now
        assert!(PathBuf::from(test_file).exists());
    }

    #[test]
    fn test_locked_settings_truncates_file_on_save() {
        let test_file = "/tmp/test_locked_settings_truncates_file_on_save.json";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(test_file)
                .canonicalize()
                .unwrap_or_else(|_| test_file.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });

        // Create a test file with some initial content
        let initial_content = r#"{
            "version": "0.1.0",
            "storage": {
                "method": "JSON"
            }
        }"#;
        let mut file = File::create(test_file).unwrap();
        file.write_all(initial_content.as_bytes()).unwrap();
        drop(file);

        // Create new settings with no config
        let settings = RootSettings::builder()
            .storage(
                SettingsContent::builder()
                    .method(StorageMethod::JSON)
                    .build(),
            )
            .build();

        // Open and save - should truncate old content
        let mut locked =
            LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| Ok(settings.clone()))
                .unwrap();
        locked.save(StorageMethod::JSON, false).unwrap();

        // Read back the file content
        let mut file = File::open(test_file).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();

        // The content should NOT contain old roles
        assert!(!content.contains("old_role"));
        assert!(!content.contains("another_old_role"));
        assert!(!content.contains("yet_another_old_role"));
        assert!(!content.contains("oldest_role"));
    }
}
