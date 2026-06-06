#[derive(Debug, Builder)]
#[allow(clippy::missing_errors_doc)]
pub struct Cred {
    #[builder(with = || -> Result<_,IoError> {
        let uid = Uid::current();
        User::from_uid(uid)?.ok_or_else(|| IoError::other("User not found"))})
    ]
    pub user: User,
    #[builder(with = || -> Result<_,IoError> {
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
    strum::EnumIs,
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

type ConfigMap = BTreeMap<PathBuf, SConfig>;

pub struct LockedSettingsFile {
    path: PathBuf,
    fd: Flock<File>, // file descriptor to the opened file, to keep the lock
    pub data: Rc<RefCell<dyn Serialize + DeserializeOwned>>,
}

pub struct RootSettings {
    pub storage: SettingsContent,
    pub config: Rc<RefCell<SConfig>>,
    pub nested: Rc<RefCell<ConfigMap>>,
}

type ConfigMap = BTreeMap<PathBuf, SPolicy>;

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
    #[builder(default = Rc::new(RefCell::new(BTreeMap::new())))]
    pub config: Rc<RefCell<ConfigMap>>,
}

impl Serialize for FullSettings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
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

                // If we have multi-file configs, deserialize them
                let config = if let Some(configs_json) = configs_value {
                    let mut config_map: BTreeMap<PathBuf, SPolicy> = BTreeMap::new();
                    if let serde_json::Value::Object(configs_obj) = configs_json {
                        for (path_str, config_value) in configs_obj {
                            let path = PathBuf::from(path_str);
                            let config_sconfig = SPolicy::deserialize(config_value)
                                .map_err(serde::de::Error::custom)?;
                            config_map.insert(path, config_sconfig);
                        }
                    }
                    Rc::new(RefCell::new(config_map))
                } else if !config_fields.is_empty() {
                    // Single config file embedded in settings
                    let config_value =
                        serde_json::Value::Object(config_fields.into_iter().collect());
                    let single_config =
                        SPolicy::deserialize(config_value).map_err(serde::de::Error::custom)?;
                    let mut config_map = BTreeMap::new();
                    config_map.insert(PathBuf::new(), single_config);
                    Rc::new(RefCell::new(config_map))
                } else {
                    // Empty config map
                    Rc::new(RefCell::new(BTreeMap::new()))
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

#[builder]
fn write_storage_settings<P>(
    path: P,
    fd: &mut File,
    method: StorageMethod,
    config: &Versioning<Rc<RefCell<SPolicy>>>,
    #[builder(default = false)] set_read_only: bool,
    #[builder(default = false)] set_root_owner: bool,
) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    debug!(
        "Saving in {} : {}",
        path.as_ref().display(),
        serde_json::to_string_pretty(&config)
            .unwrap_or_else(|_| "Failed to serialize config".to_string())
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

fn write_sconfig_to_file<P>(
    path: P,
    fd: &mut File,
    method: StorageMethod,
    config: &Versioning<SPolicy>,
    set_read_only: bool,
    set_root_owner: bool,
) -> std::io::Result<()>
where
    P: AsRef<Path>,
{
    debug!(
        "Saving in {} : {}",
        path.as_ref().display(),
        serde_json::to_string_pretty(&config)
            .unwrap_or_else(|_| "Failed to serialize config".to_string())
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

/// # Errors
/// Returns an error if the file cannot be opened or deserialized
pub fn read_full_settings<S>(path: &S) -> Result<Rc<RefCell<FullSettings>>, Box<dyn Error>>
where
    S: AsRef<Path>,
{
    // if user does not have read permission, try to enable privilege
    let file = read_with_privileges(path.as_ref())?;
    load_full_settings(path, &file)
}

/// # Errors
/// Returns an error if the directory cannot be read or config files cannot be deserialized
fn load_config_from_folder(
    folder_path: &Path,
    storage_method: StorageMethod,
) -> Result<Rc<RefCell<ConfigMap>>, Box<dyn Error>> {
    let mut config_map = BTreeMap::new();

    if !folder_path.is_dir() {
        return Err(format!("Path is not a directory: {}", folder_path.display()).into());
    }

    // Iterate over files in the folder
    for entry in std::fs::read_dir(folder_path)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        // Load the config file
        match load_config_file(&path, storage_method) {
            Ok(config) => {
                debug!("Loaded config from: {}", path.display());
                config_map.insert(path, config);
            }
            Err(e) => {
                warn!("Failed to load config from {}: {}", path.display(), e);
                // Continue loading other files instead of failing completely
            }
        }
    }

    Ok(Rc::new(RefCell::new(config_map)))
}

/// # Errors
/// Returns an error if the file cannot be read or deserialized
fn load_config_file(
    file_path: &Path,
    storage_method: StorageMethod,
) -> Result<SPolicy, Box<dyn Error>> {
    let file = read_with_privileges(file_path)?;
    let value: Versioning<SPolicy> = match storage_method {
        StorageMethod::JSON => serde_json::from_reader(file)?,
        StorageMethod::CBOR => cbor4ii::serde::from_reader(BufReader::new(file))?,
    };
    debug!(
        "Loaded config file: {}",
        serde_json::to_string_pretty(&value)?
    );
    Ok(value.data)
}

/// # Errors
/// Returns an error if the file cannot be opened or deserialized
fn load_full_settings<S: AsRef<Path>>(
    path: &S,
    file: &File,
) -> Result<Rc<RefCell<FullSettings>>, Box<dyn Error>> {
    let value: Versioning<FullSettings> = serde_json::from_reader(file).inspect_err(|e| {
        debug!("Error reading file: {e}");
    })?;
    let settingsfile = rc_refcell!(value.data);
    debug!("settingsfile: {settingsfile:?}");
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
            // Check if path is a directory (multi-file config) or a file (single file config)
            if data_path.is_dir() {
                binding.config = load_config_from_folder(data_path, binding.storage.method)?;
            } else {
                // Load single file config
                let single_config = retrieve_sconfig(&binding.storage.method, data_path)?;

                // Create a BTreeMap with a single entry
                let mut config_map = BTreeMap::new();
                let config_clone = single_config.borrow().clone();
                config_map.insert(data_path.to_path_buf(), config_clone);
                binding.config = Rc::new(RefCell::new(config_map));

                // Make weak references for roles in the single config
                make_weak_config(&single_config);
            }
        } else {
            // Config is embedded in the settings file
            // The config map should already be populated from deserialization
        }
    }
    Ok(settingsfile)
}

/// # Errors
/// Returns an error if the migration fails
pub fn migrate_settings(settings: &mut FullSettings) -> Result<(), Box<dyn Error>> {
    Migration::migrate(&PACKAGE_VERSION, settings, SETTINGS_MIGRATIONS)?;
    Ok(())
}

/// # Errors
/// Returns an error if the file cannot be opened
pub fn get_settings<S>(path: &S) -> Result<Settings, Box<dyn Error>>
where
    S: AsRef<Path>,
{
    // if user does not have read permission, try to enable privilege
    let file = read_with_privileges(path.as_ref())?;
    let value: Versioning<Settings> = serde_json::from_reader(file)
        .inspect_err(|e| {
            debug!("Error reading file: {e}");
        })
        .unwrap_or_else(|_| {
            warn!("Using default settings file!!");
            Versioning::default()
        });
    //read_effective(false).or(dac_override_effective(false))?;
    debug!("{}", serde_json::to_string_pretty(&value)?);
    Ok(value.data)
}
