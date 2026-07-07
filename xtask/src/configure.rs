use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use capctl::Cap;
use log::{info, warn};
use nix::unistd::{getresuid, getuid};
use serde_json::Value;

// (Assuming your crate imports remain the same)
use crate::util::{
    ENV_CHECK_LIST, ENV_DEFAULT_BEHAVIOR, ENV_DELETE_LIST, ENV_KEEP_LIST, ENV_OVERRIDE_BEHAVIOR,
    ENV_PATH_ADD_LIST_SLICE, ENV_PATH_BEHAVIOR, ENV_PATH_REMOVE_LIST_SLICE, ENV_SET_LIST, INFO,
    ImmutableLock, Opt, OsTarget, PACKAGE_VERSION, PAM_CONFIG_SERVICE, Policy, RAR_AUTHENTICATION,
    RAR_BOUNDING, RAR_CFG_DATA_PATH, RAR_CFG_IMMUTABLE, RAR_CFG_PATH, RAR_CFG_TYPE,
    RAR_USER_CONSIDERED, RootSettings, SEnvOptions, SPathOptions, STimeout, SWorkdirSet,
    TIMEOUT_DURATION, TIMEOUT_MAX_USAGE, TIMEOUT_TYPE, UMASK, WORKDIR_ADD_LIST_SLICE,
    WORKDIR_BEHAVIOR, WORKDIR_FALLBACK, WORKDIR_REMOVE_LIST_SLICE, cap_effective,
    toggle_lock_config,
};

#[derive(Debug)]
pub enum ConfigState {
    Unchanged,
    Modified,
}

impl ConfigState {
    #[must_use]
    pub const fn is_modified(&self) -> bool {
        matches!(self, Self::Modified)
    }
    #[must_use]
    pub const fn is_unchanged(&self) -> bool {
        matches!(self, Self::Unchanged)
    }
}

pub fn deploy_config_file() -> Result<ConfigState, anyhow::Error> {
    let cfg_path = Path::new(RAR_CFG_PATH);
    let data_path = Path::new(RAR_CFG_DATA_PATH);

    // 1. Simple existence check to prevent overwriting
    if cfg_path.exists() || (RAR_CFG_PATH != RAR_CFG_DATA_PATH && data_path.exists()) {
        info!("Config file(s) already exist, skipping default deployment.");
        return Ok(ConfigState::Modified);
    }

    info!("Config files do not exist, deploying default configuration...");

    cap_effective(Cap::DAC_OVERRIDE, true).context("Failed to raise DAC_OVERRIDE")?;

    // 2. Wrap the deployment to ensure we drop capabilities even if it fails
    let deploy_result = deploy_default_config();

    cap_effective(Cap::DAC_OVERRIDE, false).context("Failed to lower DAC_OVERRIDE")?;

    deploy_result?;

    Ok(ConfigState::Unchanged)
}

fn set_immutable(config: &mut RootSettings, value: bool) {
    if let Some(settings) = config.storage.settings.as_mut()
        && let Some(mut _immutable) = settings.immutable
    {
        _immutable = value;
    }

    if !value {
        let roles = config
            .policy
            .extra_fields
            .as_object_mut()
            .expect("Config extra fields should be a JSON object")
            .get_mut("roles")
            .expect("Config should have roles field")
            .as_array_mut()
            .expect("Roles field should be an array");
        for role in roles {
            let tasks = role
                .as_object_mut()
                .expect("Role should be a JSON object")
                .get_mut("tasks");
            if let Some(tasks) = tasks {
                for task in tasks
                    .as_array_mut()
                    .expect("Tasks field should be an array")
                {
                    let cred = task
                        .as_object_mut()
                        .expect("Task shoudl be a JSON object")
                        .get_mut("cred")
                        .expect("Task should have cred field")
                        .as_object_mut()
                        .expect("Cred field should be a JSON object");
                    let caps = cred
                        .get_mut("capabilities")
                        .expect("Cred should have capabilities field");

                    if let Some(caps_obj) = caps.as_object_mut() {
                        if let Some(add) = caps_obj.get_mut("add") {
                            add.as_array_mut()
                                .expect("Add field should be an array")
                                .retain(|x| x != "CAP_LINUX_IMMUTABLE");
                        }
                        if let Some(sub) = caps_obj.get_mut("sub") {
                            sub.as_array_mut()
                                .expect("Sub field should be an array")
                                .retain(|x| x != "CAP_LINUX_IMMUTABLE");
                        }
                    } else if let Some(caps_arr) = caps.as_array_mut() {
                        caps_arr.retain(|x| x != "CAP_LINUX_IMMUTABLE");
                    } else {
                        warn!(
                            "Unsupported capabilities format in config, expected object or array"
                        );
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn set_options(content: &mut RootSettings) {
    content.storage.method = RAR_CFG_TYPE;
    if let Some(settings) = &mut content.storage.settings {
        if let Some(path) = &mut settings.path {
            *path = RAR_CFG_DATA_PATH.to_string();
        }
        if let Some(immutable) = &mut settings.immutable {
            *immutable = RAR_CFG_IMMUTABLE;
        }
    }
    content.policy.options = Some(Opt {
        timeout: Some(STimeout {
            type_field: Some(TIMEOUT_TYPE),
            duration: Some(TIMEOUT_DURATION),
            max_usage: TIMEOUT_MAX_USAGE,
            extra_fields: Value::Null,
        }),
        path: Some(SPathOptions {
            default_behavior: ENV_PATH_BEHAVIOR,
            add: Some(
                ENV_PATH_ADD_LIST_SLICE
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            sub: if ENV_PATH_REMOVE_LIST_SLICE.len() == 1
                && ENV_PATH_REMOVE_LIST_SLICE[0].is_empty()
            {
                None
            } else {
                Some(
                    ENV_PATH_REMOVE_LIST_SLICE
                        .iter()
                        .copied()
                        .map(std::string::ToString::to_string)
                        .collect(),
                )
            },
            extra_fields: Value::Null,
        }),
        env: Some(SEnvOptions {
            default_behavior: ENV_DEFAULT_BEHAVIOR,
            override_behavior: if ENV_OVERRIDE_BEHAVIOR {
                Some(ENV_OVERRIDE_BEHAVIOR)
            } else {
                None
            },
            keep: Some(
                ENV_KEEP_LIST
                    .iter()
                    .copied()
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            check: Some(
                ENV_CHECK_LIST
                    .iter()
                    .copied()
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            delete: Some(
                ENV_DELETE_LIST
                    .iter()
                    .copied()
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            set: if ENV_SET_LIST.is_empty() {
                HashMap::new()
            } else {
                ENV_SET_LIST
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                    .collect()
            },
            extra_fields: Value::Null,
        }),
        workdir: Some(SWorkdirSet {
            default_behavior: WORKDIR_BEHAVIOR,
            add: Some(
                WORKDIR_ADD_LIST_SLICE
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            sub: if WORKDIR_REMOVE_LIST_SLICE.len() == 1 && WORKDIR_REMOVE_LIST_SLICE[0].is_empty()
            {
                None
            } else {
                Some(
                    WORKDIR_REMOVE_LIST_SLICE
                        .iter()
                        .copied()
                        .map(std::string::ToString::to_string)
                        .collect(),
                )
            },
            fallback: WORKDIR_FALLBACK
                .as_ref()
                .map(std::string::ToString::to_string),
        }),
        execinfo: Some(INFO),
        umask: Some(UMASK),
        root: Some(RAR_USER_CONSIDERED),
        bounding: Some(RAR_BOUNDING),
        authentication: Some(RAR_AUTHENTICATION),
        extra_fields: Value::Null,
    });
}

fn deploy_default_config() -> Result<(), anyhow::Error> {
    let user = retrieve_real_user()?;
    let template_content = fs::read_to_string("resources/rootasrole.json")
        .context("Failed to open the template config file")?;

    let template_str = if let Some(user) = user {
        template_content.replace("\"ROOTADMINISTRATOR\"", &format!("\"{}\"", user.name))
    } else {
        warn!("Failed to get the current user from passwd file, using UID instead");
        template_content.replace("\"ROOTADMINISTRATOR\"", &format!("{}", getuid().as_raw()))
    };

    let mut settings = serde_json::from_str::<RootSettings>(&template_str)
        .context("Failed to parse the template config file")?;

    set_options(&mut settings);

    // 3. Handle Immutability
    let is_immutable = if RAR_CFG_IMMUTABLE {
        get_filesystem_type(RAR_CFG_PATH)?.map_or_else(
            || {
                info!("Failed to get filesystem type, removing immutable flag");
                false
            },
            |fs_type| match fs_type.as_str() {
                "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "ocfs2" | "jfs" | "reiserfs" => {
                    info!("{fs_type} is compatible for immutability, setting immutable flag");
                    true
                }
                _ => {
                    info!("{fs_type} is not compatible for immutability, removing immutable flag");
                    false
                }
            },
        )
    } else {
        false
    };

    set_immutable(&mut settings, is_immutable);

    // 4. Split policy if paths differ
    if RAR_CFG_PATH != RAR_CFG_DATA_PATH {
        settings.policy.version = Some(PACKAGE_VERSION);
        let policy_path = resolve_policy_path(Path::new(RAR_CFG_DATA_PATH));

        if let Some(parent) = policy_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(
            &policy_path,
            serde_json::to_string_pretty(&settings.policy)?,
        )
        .context("Failed to write policy config file")?;

        settings.policy = Policy::default(); // Clear it from main config so it doesn't duplicate
    }

    // 5. Write main settings
    if let Some(parent) = Path::new(RAR_CFG_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(RAR_CFG_PATH, serde_json::to_string_pretty(&settings)?)
        .context("Failed to write main config file")?;

    if is_immutable {
        toggle_lock_config(&RAR_CFG_PATH.to_string(), &ImmutableLock::Set)?;
        if RAR_CFG_PATH != RAR_CFG_DATA_PATH {
            let policy_path = resolve_policy_path(Path::new(RAR_CFG_DATA_PATH));
            toggle_lock_config(
                &policy_path.to_string_lossy().to_string(),
                &ImmutableLock::Set,
            )?;
        }
    }

    Ok(())
}

fn resolve_policy_path(base_path: &Path) -> PathBuf {
    if base_path.extension().is_some_and(|ext| ext == "d") {
        base_path.join("policy.json")
    } else {
        base_path.to_path_buf()
    }
}
pub fn pam_config(os: &OsTarget) -> std::io::Result<String> {
    match os {
        OsTarget::Debian | OsTarget::Ubuntu => {
            std::fs::read_to_string("../../resources/debian/deb_sr_pam.conf")
        }
        OsTarget::RedHat | OsTarget::Fedora => {
            std::fs::read_to_string("../../resources/rh/rh_sr_pam.conf")
        }
        OsTarget::OpenSUSE => std::fs::read_to_string("../../resources/opensuse/opensuse.conf"),
        OsTarget::ArchLinux => std::fs::read_to_string("../../resources/arch/arch_sr_pam.conf"),
    }
}

fn deploy_pam_config(os: &OsTarget) -> io::Result<u64> {
    if fs::metadata(Path::new("/etc/pam.d").join(PAM_CONFIG_SERVICE)).is_err() {
        info!("Deploying PAM configuration file");
        let mut pam_conf = File::create(Path::new("/etc/pam.d").join(PAM_CONFIG_SERVICE))?;
        pam_conf.write_all(pam_config(os)?.as_bytes())?;
        pam_conf.sync_all()?;
    }
    Ok(0)
}

fn get_filesystem_type<P: AsRef<Path>>(path: P) -> io::Result<Option<String>> {
    let path = path.as_ref();
    let mounts_file = File::open("/proc/mounts")?;
    let reader = BufReader::new(mounts_file);
    let mut longest_mount_point = String::new();
    let mut filesystem_type = None;

    for line_result in reader.lines() {
        let line = line_result?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() > 2 {
            let mount_point = fields[1];
            let fs_type = fields[2];
            if path.starts_with(mount_point) && mount_point.len() > longest_mount_point.len() {
                longest_mount_point = mount_point.to_string();
                filesystem_type = Some(fs_type.to_string());
            }
        }
    }

    Ok(filesystem_type)
}

fn retrieve_real_user() -> Result<Option<nix::unistd::User>, anyhow::Error> {
    // if sudo_user is not set, get the real user
    if let Ok(sudo_user) = env::var("SUDO_USER") {
        let user =
            nix::unistd::User::from_name(&sudo_user).context("Failed to get the sudo user")?;
        Ok(user)
    } else {
        let ruid = getresuid()?.real;
        let user = nix::unistd::User::from_uid(ruid).context("Failed to get the real user")?;
        Ok(user)
    }
}

pub fn configure(os: Option<OsTarget>) -> Result<(), anyhow::Error> {
    let os = if let Some(os) = os {
        os
    } else {
        OsTarget::detect()
            .map(|t| {
                info!("Detected OS is : {t}");
                t
            })
            .context("Failed to detect the OS")?
    };
    deploy_pam_config(&os).context("Failed to deploy the PAM configuration file")?;

    deploy_config_file()?;
    Ok(())
}
