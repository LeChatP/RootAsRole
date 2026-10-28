use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    error::Error,
    fmt::Debug,
    fs::{File, OpenOptions},
    io::{self, BufReader, Seek},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    rc::Rc,
};

use bon::Builder;
use capctl::Cap;
use log::{debug, error, warn};
use nix::fcntl::Flock;
use semver::Version;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    PACKAGE_VERSION, SettingsContent,
    database::{
        migration::{Migration, MigrationError},
        migrations::{DocumentMigration, migrate_document, migrate_document_to, writable_version},
        structs::SPolicy,
        versionning::Versioning,
    },
    util::{
        RAR_CFG_IMMUTABLE, RAR_CFG_PATH, RAR_CFG_TYPE, StorageMethod, has_privileges, is_immutable,
        open_lock_with_privileges, read_with_privileges, with_mutable_config, write_config,
    },
};

pub const ROOT_MIGRATIONS: &[Migration<RootSettings>] = &[];

/// Read a policy document without interpreting it, so that it can be migrated first.
fn read_document(method: StorageMethod, file: &File) -> io::Result<serde_json::Value> {
    match method {
        StorageMethod::JSON => serde_json::from_reader(file).map_err(|e| {
            debug!("Failed to read the document: {e}");
            io::Error::new(io::ErrorKind::InvalidData, e)
        }),
        StorageMethod::CBOR => cbor4ii::serde::from_reader(BufReader::new(file)).map_err(|e| {
            debug!("Failed to read the document: {e}");
            io::Error::new(io::ErrorKind::InvalidData, e)
        }),
    }
}
pub const POLICY_MIGRATIONS: &[Migration<Rc<RefCell<SPolicy>>>] = &[];

#[derive(Debug)]
pub struct LockedSettingsFile<T: Serialize + DeserializeOwned + Debug + Default> {
    path: PathBuf,
    fd: Flock<File>, // file descriptor to the opened file, to keep the lock
    pub data: T,
    /// The migration applied to the document when it was loaded, until it is saved.
    migration: Option<DocumentMigration>,
    /// The data as loaded, or as last saved: a file whose data is the same is not written
    /// again. `None` when the data did not come from the file.
    saved: Option<serde_json::Value>,
}

/// How a policy file is opened to be written. A new file is only readable and writable by its
/// owner (the umask can only remove more), like the files of the installers: the policy must not
/// be readable, nor writable, by other users (see `check_others_permissions`). An existing file
/// keeps its owner and mode, since saving rewrites it in place.
fn write_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).mode(0o600);
    options
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
        Self::open(path, &write_options(), true, data_loader)
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

            let data = data_loader(&path, &file)?;
            Ok(Self {
                path: path.as_ref().to_path_buf(),
                saved: serde_json::to_value(&data).ok(),
                data,
                fd: file,
                migration: None,
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

    /// Whether the data differs from what the file holds: changed since it was loaded or saved,
    /// or not loaded from the file.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.saved.is_none() || self.saved != serde_json::to_value(&self.data).ok()
    }

    /// # Errors
    /// Returns an error if the file cannot be written
    /// due to a lock, permission error or writing error
    pub fn save(&mut self, method: StorageMethod, immutable: bool) -> Result<(), Box<dyn Error>> {
        write_locked(&mut self.fd, &self.data, method, immutable)?;
        self.migration = None;
        self.saved = serde_json::to_value(&self.data).ok();

        Ok(())
    }

    /// The document of the data, as the file holds it in the format `method`: with the short keys
    /// and the compact values of CBOR, which the migrations read like in a loaded file.
    fn document(&self, method: StorageMethod) -> Result<serde_json::Value, Box<dyn Error>> {
        Ok(match method {
            StorageMethod::JSON => serde_json::to_value(&self.data)?,
            StorageMethod::CBOR => {
                cbor4ii::serde::from_slice(&cbor4ii::serde::to_vec(Vec::new(), &self.data)?)?
            }
        })
    }

    /// Write `document` in the file instead of the data: the file then holds another version than
    /// the data, which the next save writes again.
    fn save_document(
        &mut self,
        document: &serde_json::Value,
        method: StorageMethod,
        immutable: bool,
    ) -> Result<(), Box<dyn Error>> {
        write_locked(&mut self.fd, document, method, immutable)?;
        self.migration = None;
        self.saved = None;
        Ok(())
    }
}

/// Replace the content of the locked file `fd` by `data`, in the format `method`.
fn write_locked(
    fd: &mut Flock<File>,
    data: &impl Serialize,
    method: StorageMethod,
    immutable: bool,
) -> Result<(), Box<dyn Error>> {
    let immuable = immutable && has_privileges(&[Cap::LINUX_IMMUTABLE])?;
    debug!("Settings file immutable: {immuable}");
    if immuable {
        debug!("Toggling immutable off for config file");
        with_mutable_config(fd, |file| {
            debug!("Toggled immutable off for config file");
            file.rewind()?;
            file.set_len(0)?;
            write_config(data, file, method)
        })
        .map_err(|e| format!("Failed to write config file: {e}"))?;
    } else {
        let file = &mut **fd;
        debug!("Writing config file");
        file.rewind()?;
        debug!("Rewound config file for writing");
        file.set_len(0)?;
        debug!("Truncated config file");
        write_config(data, file, method)?;
        debug!("Wrote config file");
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, Builder, PartialEq, Eq)]
pub struct RootSettings {
    pub storage: SettingsContent,
    #[serde(flatten)]
    #[builder(default)]
    pub config: Rc<RefCell<SPolicy>>,
}

/// A loaded file written for an older version by [`FileSettings::write_for`].
#[derive(Debug)]
pub struct FileDowngrade {
    pub path: PathBuf,
    /// What changes from the loaded version, or why the file cannot be written for that version.
    pub result: Result<DocumentMigration, String>,
}

/// The version of a loaded file.
#[derive(Debug)]
pub struct FileVersion<'a> {
    pub path: &'a Path,
    /// The version of the loaded content, the current one once migrated.
    pub version: &'a Version,
    /// The migration applied when the file was loaded, if it was not saved since.
    pub migration: Option<&'a DocumentMigration>,
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
        let mut root = LockedSettingsFile::open_write(path, |_, _| {
            let versioned: Versioning<RootSettings> = Versioning::new(config.clone());
            Ok(versioned)
        })?;
        // made from these settings, not read from the file: it is written by the next save
        root.saved = None;
        Ok(root)
    })]
    root: LockedRootSettings,
    /// Policy files of a directory that could not be loaded, with the reason.
    #[builder(skip)]
    ignored: Vec<(PathBuf, String)>,
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
            &write_options(),
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
        Self::load_policy_file(cfg_type, &write_options(), true, cfg_path)
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
        let root = Self::load_root_file(rar_cfg_path.as_ref(), rar_cfg_type, options, write)?;
        let mut map = ConfigMap::new();
        let mut ignored = Vec::new();

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
            if !root.data.data.config.as_ref().borrow().is_empty() {
                warn!(
                    "A policy has been detected in {}, but a different path is specified. 
                    Ignoring the policy and keeping only the ones in the specified path: {}",
                    rar_cfg_path.as_ref().display(),
                    path.display()
                );
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
                            Err(e) => {
                                debug!(
                                    "Failed to load settings from file {}: {}",
                                    path.display(),
                                    e
                                );
                                ignored.push((path, e.to_string()));
                            }
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

        Ok(Self { map, root, ignored })
    }

    /// # Errors
    /// Returns an error if the file cannot be opened or deserialized
    fn load_root_file(
        path: &Path,
        file_type: StorageMethod,
        options: &OpenOptions,
        write: bool,
    ) -> std::io::Result<LockedRootSettings> {
        let migration = Cell::new(None);
        let mut root = LockedSettingsFile::open(path, options, write, |path, file| {
            debug!("Loading root settings from {}", path.display());
            let mut document = read_document(file_type, file)?;
            let mut no_path = None;
            match migrate_document(&mut document) {
                Ok(applied) => migration.set(applied),
                Err(e @ MigrationError::NoMigrationPath(..)) => {
                    debug!("\x1b[31m{e}\x1b[0m");
                    no_path = Some(e);
                }
                Err(MigrationError::MigrationFailed(e)) => return Err(io::Error::other(e)),
            }
            let mut settings: Versioning<RootSettings> =
                serde_json::from_value(document).map_err(|e| {
                    debug!("Failed to deserialize root settings: {e}");
                    io::Error::new(io::ErrorKind::InvalidData, e)
                })?;
            // the storage settings are read at any version, a policy only at a version that
            // this version knows the meaning of, like in a policy file: an older version, or a
            // newer one, may mean something else with the same words
            if let Some(e) = no_path
                && !settings.data.config.as_ref().borrow().is_empty()
            {
                return Err(io::Error::other(e.to_string()));
            }
            Self::make_weak_config(&settings.data.config);
            settings
                .upgrade_version(ROOT_MIGRATIONS)
                .or_else(|e| match e {
                    MigrationError::NoMigrationPath(from, to) => {
                        debug!("\x1b[31mNo migration path found from {from} to {to}\x1b[0m");
                        Ok(false)
                    }
                    MigrationError::MigrationFailed(e) => Err(io::Error::other(e)),
                })?;
            debug!("Loaded root settings from {}", path.display());
            Ok(settings)
        })?;
        root.migration = migration.take();
        Ok(root)
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
        let migration = Cell::new(None);
        let mut policyfile: LockedPolicy =
            LockedSettingsFile::open(path, options, write, |_, file| {
                let mut document = read_document(file_type, file)?;
                migration.set(
                    migrate_document(&mut document).map_err(|e| io::Error::other(e.to_string()))?,
                );
                serde_json::from_value(document)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            })?;
        policyfile.migration = migration.take();
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

    fn immutable(&self) -> bool {
        self.root
            .data
            .data
            .storage
            .settings
            .as_ref()
            .and_then(|s| s.immutable)
            .unwrap_or(RAR_CFG_IMMUTABLE)
    }

    /// # Errors
    /// Returns an error if any of the files cannot be written
    pub fn save_all(&mut self) -> Result<(), Box<dyn Error>> {
        let immutable = self.immutable();

        // the root settings stay in their own file, which dosr reads, and the policy that they
        // name in its own files below: the root settings used to be moved into a separate policy
        // file, and waited forever for the lock that the loaded policy file holds
        //
        // only the files that changed: the others are not rewritten (in the typed form of the
        // actors, without their immutable flag for a while...)
        let mut has_errors = if !self.root.changed() {
            false
        } else if let Err(e) = self.root.save(RAR_CFG_TYPE, immutable) {
            error!("Failed to save root settings: {e}");
            true
        } else {
            debug!("Saved root settings");
            false
        };

        for config in self.map.iter_mut().filter(|config| config.changed()) {
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

    /// Save only the files that were migrated when they were loaded.
    /// # Errors
    /// Returns an error if one of these files cannot be written
    pub fn save_migrated(&mut self) -> Result<(), Box<dyn Error>> {
        let immutable = self.immutable();
        let method = self.root.data.data.storage.method;
        if self.root.migration.is_some() {
            self.root
                .save(RAR_CFG_TYPE, immutable)
                .map_err(|e| format!("Failed to save {}: {e}", self.root.path.display()))?;
        }
        for config in self.map.iter_mut().filter(|c| c.migration.is_some()) {
            config
                .save(method, immutable)
                .map_err(|e| format!("Failed to save {}: {e}", config.path.display()))?;
        }
        Ok(())
    }

    /// Write every loaded file for the older version `to`, root file first, before that version
    /// is installed, or with `check` only tell what would change. Each file is written whatever
    /// happens to the others, and is then loaded again with the current version: the data is
    /// not saved again, a later `save_all` would write it for the current version.
    /// # Errors
    /// Returns an error if the policy cannot be written for `to` (see `writable_version`), or if
    /// `to` is the current version: `save_migrated` writes the policy for it.
    pub fn write_for(&mut self, to: &str, check: bool) -> Result<Vec<FileDowngrade>, String> {
        let to = writable_version(to)?;
        if to == PACKAGE_VERSION {
            return Err(format!("{to} is the current version"));
        }
        let immutable = self.immutable();
        let method = self.root.data.data.storage.method;
        let mut files = vec![Self::write_file_for(
            &mut self.root,
            &to,
            RAR_CFG_TYPE,
            immutable,
            check,
        )];
        for config in &mut self.map {
            files.push(Self::write_file_for(config, &to, method, immutable, check));
        }
        Ok(files)
    }

    fn write_file_for<T: Serialize + DeserializeOwned + Debug + Default>(
        file: &mut LockedSettingsFile<T>,
        to: &Version,
        method: StorageMethod,
        immutable: bool,
        check: bool,
    ) -> FileDowngrade {
        let mut write = || -> Result<DocumentMigration, Box<dyn Error>> {
            let mut document = file.document(method)?;
            let Some(migration) = migrate_document_to(&mut document, to)? else {
                return Err(format!("its version is not known, or is already {to}").into());
            };
            if !check {
                file.save_document(&document, method, immutable)?;
            }
            Ok(migration)
        };
        let result = write().map_err(|e| e.to_string());
        FileDowngrade {
            path: file.path.clone(),
            result,
        }
    }

    /// The version of each loaded file, root settings first.
    #[must_use]
    pub fn get_versions(&self) -> Vec<FileVersion<'_>> {
        let root = FileVersion {
            path: &self.root.path,
            version: &self.root.data.version,
            migration: self.root.migration.as_ref(),
        };
        std::iter::once(root)
            .chain(self.map.iter().map(|config| FileVersion {
                path: &config.path,
                version: &config.data.version,
                migration: config.migration.as_ref(),
            }))
            .collect()
    }

    /// Policy files of a directory that could not be loaded, and were ignored.
    #[must_use]
    pub fn get_ignored(&self) -> &[(PathBuf, String)] {
        &self.ignored
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
            Some(&self.root.data.data.config)
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

    /// The path of the root file.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root.path
    }

    /// The policy files apart from the root file (those of a policy directory, or the one file
    /// that the root file names), with their path.
    pub fn policy_files(&self) -> impl Iterator<Item = (&Path, &Rc<RefCell<SPolicy>>)> {
        self.map
            .iter()
            .map(|config| (config.path.as_path(), &config.data.data))
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
    fn test_read_policy_migrates_older_versions() {
        let path =
            std::env::temp_dir().join(format!("rar_migrate_policy_{}.json", std::process::id()));
        // saved by 4.0.2, with a regex that is not valid anymore
        std::fs::write(
            &path,
            r#"{"version":"4.0.2","options":{"env":{"check":["LC_.*"]}},"roles":[]}"#,
        )
        .unwrap();
        let policy = FileSettings::read_policy(&path, StorageMethod::JSON).unwrap();
        assert_eq!(policy.data.version, PACKAGE_VERSION);
        let options = policy.data.data.as_ref().borrow().options.clone().unwrap();
        let check = options
            .as_ref()
            .borrow()
            .env
            .clone()
            .unwrap()
            .check
            .unwrap();
        assert_eq!(
            check.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["LC_*"]
        );
        std::fs::remove_file(&path).unwrap();
    }

    // a root file at a version without a migration path, older or newer: its storage settings
    // are read, a policy that it holds is refused, like the same policy in a policy file (it was
    // edited, and saved with that version, as if this version knew what it means)
    #[test]
    fn test_root_file_without_a_migration_path() {
        let dir = std::env::temp_dir().join(format!("rar-root-no-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _cleanup = defer(|| {
            let _ = std::fs::remove_dir_all(
                std::env::temp_dir().join(format!("rar-root-no-path-{}", std::process::id())),
            );
        });
        let root = dir.join("rootasrole.json");
        let data = dir.join("policy.json");
        let policy = serde_json::json!({"version": PACKAGE_VERSION.to_string(), "roles": []});
        std::fs::write(&data, policy.to_string()).unwrap();
        for version in ["3.0.0", "99.0.0"] {
            let storage = serde_json::json!({"method": "json", "settings": {"path": data, "immutable": false}});
            std::fs::write(
                &root,
                serde_json::json!({"version": version, "storage": storage}).to_string(),
            )
            .unwrap();
            let settings = FileSettings::read_all(&root, &root, StorageMethod::JSON).unwrap();
            assert_eq!(settings.get_versions()[0].version.to_string(), version);
            assert_eq!(settings.policy_files().count(), 1);
            drop(settings);

            let storage = serde_json::json!({"method": "json", "settings": {"path": root, "immutable": false}});
            for policy in [
                serde_json::json!({"roles": [{"name": "r", "actors": []}]}),
                serde_json::json!({"options": {"bounding": "ignore"}}),
            ] {
                let mut document = serde_json::json!({"version": version, "storage": storage});
                document
                    .as_object_mut()
                    .unwrap()
                    .extend(policy.as_object().unwrap().clone());
                std::fs::write(&root, document.to_string()).unwrap();
                let error = FileSettings::write_all(&root, &root, StorageMethod::JSON)
                    .err()
                    .unwrap_or_else(|| panic!("{document} is refused"));
                assert_eq!(
                    error.to_string(),
                    format!("No migration path found from {version} to {PACKAGE_VERSION}")
                );
                // nothing is written
                assert_eq!(
                    std::fs::read_to_string(&root).unwrap(),
                    document.to_string()
                );
            }
        }
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
        let mut config = LockedSettingsFile::open_write(PathBuf::from(value), |_, _| {
            Ok(Versioning::new(settings.clone()))
        })
        .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();
        drop(config); // yes, it is ugly.
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
        let mut file = LockedSettingsFile::open_write(test_file_path, |_, _| {
            Ok(Versioning::new(settings_config.clone()))
        })
        .unwrap();
        file.save(StorageMethod::JSON, false).unwrap();
        drop(file); // yes, it is ugly.
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
        let mut file = LockedSettingsFile::open_write(external_file_path, |_, _| {
            Ok(Versioning::new(config.clone()))
        })
        .unwrap();
        file.save(StorageMethod::JSON, false).unwrap();
        let data = file.data.clone();
        drop(file); // yes, it is ugly.

        let full = FileSettings::read_all(test_file_path, external_file_path, StorageMethod::JSON)
            .unwrap();
        assert_eq!(full.get_policies().len(), 1);
        assert_eq!(
            *full.get_policies()[0].borrow(),
            *data.data.as_ref().borrow()
        );
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
            .build();
        let mut config = LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| {
            Ok(settings_config.clone())
        })
        .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();
        drop(config); // yes, it is ugly.
        let policy = SPolicy::builder()
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
        let mut config = LockedSettingsFile::open_write(PathBuf::from(external_file), |_, _| {
            Ok(Versioning::new(policy.clone()))
        })
        .unwrap();
        config.save(StorageMethod::JSON, false).unwrap();
        drop(config); // yes, it is ugly.
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

    // a root file that names a separate policy file: saving an edit of the policy writes it in
    // that file, keeps the root file as it is, and does not wait for the lock of the loaded file
    #[test]
    fn test_save_all_with_a_separate_policy_file() {
        use std::os::unix::fs::PermissionsExt;
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let dir = std::env::temp_dir().join(format!("rar-separate-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let root = dir.join("rootasrole.json");
            let data = dir.join("policy.json");
            let version = crate::PACKAGE_VERSION.to_string();
            std::fs::write(
                &root,
                serde_json::json!({"version": version, "storage": {"method": "json", "settings": {"path": data, "immutable": false}}}).to_string(),
            )
            .unwrap();
            std::fs::write(
                &data,
                serde_json::json!({"version": version, "roles": [{"name": "r0", "actors": []}]})
                    .to_string(),
            )
            .unwrap();
            for file in [&root, &data] {
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            let root_before = std::fs::read_to_string(&root).unwrap();
            let mut settings =
                FileSettings::write_all(root.clone(), root.clone(), StorageMethod::JSON).unwrap();
            settings.get_policies()[0]
                .borrow_mut()
                .roles
                .push(SRole::builder("r1").build());
            settings.save_all().unwrap();
            drop(settings);
            let data_after = std::fs::read_to_string(&data).unwrap();
            let root_after = std::fs::read_to_string(&root).unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
            done.send((root_before, root_after, data_after)).unwrap();
        });
        let (root_before, root_after, data_after) = finished
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("save_all finishes, without waiting for a lock that this process holds");
        assert_eq!(root_after, root_before);
        assert!(data_after.contains("r1"), "{data_after}");
        assert!(!data_after.contains("storage"), "{data_after}");
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

        let settings = Versioning::new(
            RootSettings::builder()
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
                .build(),
        );
        let mut config =
            LockedSettingsFile::open_write(PathBuf::from(test_file), |_, _| Ok(settings.clone()))
                .unwrap();
        config.save(StorageMethod::CBOR, false).unwrap();
        drop(config); // yes, it is ugly.
        let policy = Versioning::new(
            SPolicy::builder()
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
                .build(),
        );
        let mut config =
            LockedSettingsFile::open_write(PathBuf::from(external_file), |_, _| Ok(policy.clone()))
                .unwrap();
        config.save(StorageMethod::CBOR, false).unwrap();
        drop(config); // yes, it is ugly.
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
        drop(config); // yes, it is ugly.
        // Test opening existing file
        let locked_file = LockedSettingsFile::open_read(PathBuf::from(test_file), |_, file| {
            let versioned: RootSettings = serde_json::from_reader(file)?;
            Ok(versioned)
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
        drop(config); // yes, it is ugly.
        // Test opening existing file with write mode - should work normally for non-immutable files
        let result = LockedSettingsFile::open_write(PathBuf::from(test_file), |_, file| {
            let versioned: RootSettings = serde_json::from_reader(file)?;
            Ok(versioned)
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
        drop(config); // yes, it is ugly.
        // Test opening file with separate config
        let locked_file = LockedSettingsFile::open_read(PathBuf::from(test_file), |_, file| {
            let versioned: RootSettings = serde_json::from_reader(file)?;
            Ok(versioned)
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
            serde_json::from_reader::<_, RootSettings>(file)
                .map_or_else(|_| Ok(RootSettings::default()), Ok)
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
        drop(config); // yes, it is ugly.
        // Test opening file in read-only mode
        let locked_file = LockedSettingsFile::open_read(PathBuf::from(test_file), |_, file| {
            let versioned: RootSettings = serde_json::from_reader(file)?;
            Ok(versioned)
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
        drop(locked); // yes, it is ugly.

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

    /// A path in the temporary directory that does not exist yet, removed when dropped.
    fn new_temp_path(name: &str) -> (PathBuf, impl Drop) {
        let path = std::env::temp_dir().join(format!("{name}_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cleanup = path.clone();
        (
            path,
            defer(move || {
                let _ = std::fs::remove_file(&cleanup);
            }),
        )
    }

    #[test]
    fn test_new_policy_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (root_file, _cleanup_root) = new_temp_path("rar_new_root_file");
        let mut locked =
            LockedSettingsFile::open_write(&root_file, |_, _| Ok(RootSettings::default())).unwrap();
        locked.save(StorageMethod::JSON, false).unwrap();
        drop(locked);
        let (policy_file, _cleanup_policy) = new_temp_path("rar_new_policy_file");
        // the new file is empty, so reading it fails, but the file is created
        assert!(FileSettings::write_policy(&policy_file, StorageMethod::JSON).is_err());
        for path in [&root_file, &policy_file] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            // never more than 0600, whatever the umask
            assert_eq!(mode & 0o077, 0, "{}: {mode:o}", path.display());
        }
    }

    #[test]
    fn test_saving_keeps_the_owner_and_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (path, _cleanup) = new_temp_path("rar_saved_root_file");
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let mut locked =
            LockedSettingsFile::open_write(&path, |_, _| Ok(RootSettings::default())).unwrap();
        locked.save(StorageMethod::JSON, false).unwrap();
        drop(locked);
        let after = std::fs::metadata(&path).unwrap();
        // rewritten in place: the same file, with its owner and mode
        assert_eq!(after.ino(), before.ino());
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(after.permissions().mode() & 0o7777, 0o640);
        assert!(after.len() > 2);
    }

    #[test]
    fn test_save_all_with_directory_storage() {
        let test_file = "/tmp/test_save_all_with_directory_storage.json";
        let policy_dir = "/tmp/test_save_all_with_directory_storage.d";
        let _cleanup = defer(|| {
            let _ = std::fs::remove_file(test_file);
            let _ = std::fs::remove_dir_all(policy_dir);
        });

        std::fs::create_dir_all(policy_dir).unwrap();
        let settings = RootSettings::builder()
            .storage(
                SettingsContent::builder()
                    .method(StorageMethod::JSON)
                    .settings(
                        RemoteStorageSettings::builder()
                            .path(policy_dir)
                            .not_immutable()
                            .build(),
                    )
                    .build(),
            )
            .build();
        let mut root =
            LockedSettingsFile::open_write(test_file, |_, _| Ok(Versioning::new(settings.clone())))
                .unwrap();
        root.save(StorageMethod::JSON, false).unwrap();
        drop(root);

        let mut file_settings =
            FileSettings::write_all(test_file, policy_dir, StorageMethod::JSON).unwrap();
        file_settings.save_all().unwrap();
        assert_eq!(file_settings.root.path, PathBuf::from(test_file));
    }
}
