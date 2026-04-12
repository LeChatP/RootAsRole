use std::collections::HashMap;
use std::env::{self};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use anyhow::Context;
use capctl::Cap;
use log::{info, warn};
use nix::unistd::{getresuid, getuid};
use serde_json::Value;
use strum::EnumIs;

use crate::util::{
    ImmutableLock, Opt, OsTarget, ROOTASROLE, SEnvOptions, SPathOptions, STimeout, SettingsFile,
    cap_effective, convert_string_to_duration, files_are_equal, toggle_lock_config,
};

const TEMPLATE: &str = include_str!("../../resources/rootasrole.json");
pub const PAM_CONFIG_SERVICE: &str = env!("RAR_PAM_SERVICE");

fn is_running_in_container() -> bool {
    // Check for environment files that might indicate a container
    let container_env_files = ["/run/.containerenv", "/.dockerenv", "/run/container_type"];
    for file in container_env_files.iter().as_slice() {
        if fs::metadata(file).is_ok() {
            return true;
        }
    }

    // Check for the "container" environment variable
    if let Ok(val) = env::var("container")
        && (val == "docker" || val == "lxc")
    {
        return true;
    }

    // Check cgroups for container-specific patterns
    if let Ok(file) = File::open("/proc/1/cgroup") {
        let reader = io::BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            if line.contains("docker")
                || line.contains("kubepods")
                || line.contains("lxc")
                || line.contains("containerd")
            {
                return true;
            }
        }
    }

    false
}

pub fn check_filesystem() -> io::Result<()> {
    let config = BufReader::new(File::open(ROOTASROLE)?);
    let mut config: SettingsFile = serde_json::from_reader(config)?;

    if env!("RAR_CFG_IMMUTABLE") == "true" {
        // Get the filesystem type
        if let Some(fs_type) = get_filesystem_type(ROOTASROLE)? {
            match fs_type.as_str() {
                "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "ocfs2" | "jfs" | "reiserfs" => {
                    info!("{fs_type} is compatble for immutability, setting immutable flag");
                    set_immutable(&mut config, true);
                    toggle_lock_config(&ROOTASROLE.to_string(), &ImmutableLock::Set)?;
                    return Ok(());
                }
                _ => info!("{fs_type} is not compatible for immutability, removing immutable flag"),
            }
        } else {
            info!("Failed to get filesystem type, removing immutable flag");
        }
    }

    set_immutable(&mut config, false);
    File::create(ROOTASROLE)?.write_all(serde_json::to_string_pretty(&config)?.as_bytes())?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn set_options(content: &mut String) -> io::Result<()> {
    let mut config: SettingsFile = serde_json::from_str(content)?;
    config.storage.method = env!("RAR_CFG_TYPE")
        .parse()
        .expect("Check RAR_CFG_TYPE in .cargo/config.toml");
    if let Some(settings) = &mut config.storage.settings {
        if let Some(path) = &mut settings.path {
            *path = env!("RAR_CFG_DATA_PATH").to_string();
        }
        if let Some(immutable) = &mut settings.immutable {
            *immutable = env!("RAR_CFG_IMMUTABLE")
                .parse()
                .expect("Check RAR_CFG_IMMUTABLE in .cargo/config.toml");
        }
    }
    config.storage.options = Some(Opt {
        timeout: Some(STimeout {
            type_field: Some(
                env!("RAR_TIMEOUT_TYPE")
                    .parse()
                    .expect("Check RAR_TIMEOUT_TYPE in .cargo/config.toml"),
            ),
            duration: convert_string_to_duration(env!("RAR_TIMEOUT_DURATION"))
                .expect("Check RAR_TIMEOUT_DURATION in .cargo/config.toml"),
            max_usage: if env!("RAR_TIMEOUT_MAX_USAGE").is_empty() {
                None
            } else {
                Some(
                    env!("RAR_TIMEOUT_MAX_USAGE")
                        .parse()
                        .expect("Check RAR_TIMEOUT_MAX_USAGE in .cargo/config.toml"),
                )
            },
            extra_fields: Value::Null,
        }),
        path: Some(SPathOptions {
            default_behavior: env!("RAR_PATH_DEFAULT")
                .parse()
                .expect("Check RAR_PATH_DEFAULT in .cargo/config.toml"),
            add: Some(
                env!("RAR_PATH_ADD_LIST")
                    .split(':')
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            sub: if env!("RAR_PATH_REMOVE_LIST").is_empty() {
                None
            } else {
                Some(
                    env!("RAR_PATH_REMOVE_LIST")
                        .split(':')
                        .map(std::string::ToString::to_string)
                        .collect(),
                )
            },
            extra_fields: Value::Null,
        }),
        env: Some(SEnvOptions {
            default_behavior: env!("RAR_ENV_DEFAULT")
                .parse()
                .expect("Check RAR_ENV_DEFAULT in .cargo/config.toml"),
            override_behavior: if env!("RAR_ENV_OVERRIDE_BEHAVIOR")
                .parse()
                .expect("Check RAR_ENV_OVERRIDE_BEHAVIOR in .cargo/config.toml")
            {
                Some(
                    env!("RAR_ENV_OVERRIDE_BEHAVIOR")
                        .parse()
                        .expect("Check RAR_ENV_OVERRIDE_BEHAVIOR in .cargo/config.toml"),
                )
            } else {
                None
            },
            keep: Some(
                env!("RAR_ENV_KEEP_LIST")
                    .split(',')
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            check: Some(
                env!("RAR_ENV_CHECK_LIST")
                    .split(',')
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            delete: Some(
                env!("RAR_ENV_DELETE_LIST")
                    .split(',')
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            set: if env!("RAR_ENV_SET_LIST").is_empty() {
                HashMap::new()
            } else {
                serde_json::from_str(env!("RAR_ENV_SET_LIST"))
                    .expect("Check RAR_ENV_SET_LIST in .cargo/config.toml")
            },
            extra_fields: Value::Null,
        }),
        root: Some(
            env!("RAR_USER_CONSIDERED")
                .parse()
                .expect("Check RAR_USER_CONSIDERED in .cargo/config.toml"),
        ),
        bounding: Some(
            env!("RAR_BOUNDING")
                .parse()
                .expect("Check RAR_BOUNDING in .cargo/config.toml"),
        ),
        authentication: Some(
            env!("RAR_AUTHENTICATION")
                .parse()
                .expect("Check RAR_AUTHENTICATION in .cargo/config.toml"),
        ),
        extra_fields: Value::Null,
    });
    *content = serde_json::to_string_pretty(&config)?;
    Ok(())
}

fn set_immutable(config: &mut SettingsFile, value: bool) {
    if let Some(settings) = config.storage.settings.as_mut()
        && let Some(mut _immutable) = settings.immutable
    {
        _immutable = value;
    }

    if !value {
        let roles = config
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

#[derive(Debug, EnumIs)]
pub enum ConfigState {
    Unchanged,
    Modified,
}

fn deploy_config_file() -> Result<ConfigState, anyhow::Error> {
    let status = if Path::new(ROOTASROLE).exists() {
        config_state()?
    } else {
        info!("Config file {ROOTASROLE} does not exist, deploying default file");
        // If the target file does not exist, copy the default file
        cap_effective(Cap::DAC_OVERRIDE, true).context("Failed to raise DAC_OVERRIDE")?;
        deploy_config(ROOTASROLE)?;
        cap_effective(Cap::DAC_OVERRIDE, false).context("Failed to raise DAC_OVERRIDE")?;
        ConfigState::Unchanged
    };

    match status {
        ConfigState::Unchanged => {
            info!("Config file newly created or has not been modified.");
            info!("Checking if filesystem allows immutability.");
            let res = check_filesystem().context("Failed to configure the filesystem parameter");
            if res.is_err() {
                // If the filesystem check fails, ignore the error if running in a container as it may not have immutable access
                if is_running_in_container() {
                    return Ok(status);
                }
                res?;
            }
        }
        ConfigState::Modified => {
            info!("Config file has been modified by the user, skipping immutable configuration");
        }
    }
    Ok(status)
}

pub fn config_state() -> Result<ConfigState, anyhow::Error> {
    let temporary_config_file = "/tmp/rar.json";
    deploy_config(temporary_config_file)?;
    let status = if files_are_equal(temporary_config_file, ROOTASROLE)? {
        ConfigState::Unchanged
    } else {
        ConfigState::Modified
    };
    fs::remove_file(temporary_config_file)?;
    Ok(status)
}

fn deploy_config<P: AsRef<Path>>(config_path: P) -> Result<(), anyhow::Error> {
    let user = retrieve_real_user()?;
    let mut content = if let Some(user) = user {
        TEMPLATE.replace("\"ROOTADMINISTRATOR\"", &format!("\"{}\"", user.name))
    } else {
        warn!("Failed to get the current user from passwd file, using UID instead");
        TEMPLATE.replace("\"ROOTADMINISTRATOR\"", &format!("{}", getuid().as_raw()))
    };
    // deploy execution options on the config file defined in the compilation environment variables
    set_options(&mut content)?;
    // Write the config file
    let mut config = File::create(config_path)?;
    config.write_all(content.as_bytes())?;
    config.sync_all()?;
    Ok(())
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

pub const fn pam_config(os: &OsTarget) -> &'static str {
    match os {
        OsTarget::Debian | OsTarget::Ubuntu => {
            include_str!("../../resources/debian/deb_sr_pam.conf")
        }
        OsTarget::RedHat | OsTarget::Fedora | OsTarget::OpenSUSE => {
            include_str!("../../resources/rh/rh_sr_pam.conf")
        }
        OsTarget::ArchLinux => include_str!("../../resources/arch/arch_sr_pam.conf"),
    }
}

fn deploy_pam_config(os: &OsTarget) -> io::Result<u64> {
    if fs::metadata(Path::new("/etc/pam.d").join(PAM_CONFIG_SERVICE)).is_err() {
        info!("Deploying PAM configuration file");
        let mut pam_conf = File::create(Path::new("/etc/pam.d").join(PAM_CONFIG_SERVICE))?;
        pam_conf.write_all(pam_config(os).as_bytes())?;
        pam_conf.sync_all()?;
    }
    Ok(0)
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
