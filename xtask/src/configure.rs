use std::collections::HashMap;
use std::env::{self};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use anyhow::Context;
use log::{info, warn};
use nix::unistd::{getresuid, getuid};
use serde_json::Value;
use strum::EnumIs;

use crate::util::{
    convert_string_to_duration, files_are_equal, toggle_lock_config, ImmutableLock, Opt, OsTarget, SEnvOptions, SPathOptions, STimeout, SettingsFile, ROOTASROLE
};

const TEMPLATE: &str = include_str!("../../resources/rootasrole.json");
pub const PAM_CONFIG_PATH: &str = "/etc/pam.d/sr";

fn is_running_in_container() -> bool {
    // Check for environment files that might indicate a container
    let container_env_files = ["/run/.containerenv", "/.dockerenv", "/run/container_type"];
    for file in container_env_files.iter() {
        if fs::metadata(file).is_ok() {
            return true;
        }
    }

    // Check for the "container" environment variable
    if let Ok(val) = env::var("container") {
        if val == "docker" || val == "lxc" {
            return true;
        }
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
                    info!(
                        "{} is compatble for immutability, setting immutable flag",
                        fs_type
                    );
                    set_immutable(&mut config, true);
                    toggle_lock_config(&ROOTASROLE.to_string(), ImmutableLock::Set)?;
                    return Ok(());
                }
                _ => info!(
                    "{} is not compatible for immutability, removing immutable flag",
                    fs_type
                ),
            }
        } else {
            info!("Failed to get filesystem type, removing immutable flag");
        }
    }
    
    set_immutable(&mut config, false);
    File::create(ROOTASROLE)?.write_all(serde_json::to_string_pretty(&config)?.as_bytes())?;
    Ok(())
}

fn set_options(content : &mut String) -> io::Result<()> {
    let mut config: SettingsFile = serde_json::from_str(content)?;
    if let Some(settings) = &mut config.storage.settings {
        if let Some(path) = &mut settings.path {
            *path = env!("RAR_PATH_DEFAULT").to_string();
        }
    }
    config.storage.options = Some(Opt {
        timeout: Some(STimeout {
            type_field: Some(env!("RAR_TIMEOUT_TYPE").parse().unwrap()),
            duration: convert_string_to_duration(&env!("RAR_TIMEOUT_DURATION").to_string()).unwrap(),
            max_usage: if env!("RAR_TIMEOUT_MAX_USAGE").len() > 0 {
                Some(env!("RAR_TIMEOUT_MAX_USAGE").parse().unwrap())
            } else {
                None
            },
            _extra_fields: Value::Null,
        }),
        path: Some(SPathOptions {
            default_behavior: env!("RAR_PATH_DEFAULT").parse().unwrap(),
            add: Some(env!("RAR_PATH_ADD_LIST").split(":").map(|s| s.to_string()).collect()),
            sub: if env!("RAR_PATH_REMOVE_LIST").len() > 0 { Some(env!("RAR_PATH_REMOVE_LIST").split(":").map(|s| s.to_string()).collect()) } else { None },
            _extra_fields: Value::Null,
        }),
        env: Some(SEnvOptions {
            default_behavior: env!("RAR_ENV_DEFAULT").parse().unwrap(),
            override_behavior: if env!("RAR_ENV_OVERRIDE_BEHAVIOR").parse().unwrap() { Some(env!("RAR_ENV_OVERRIDE_BEHAVIOR").parse().unwrap()) } else { None },
            keep: Some(env!("RAR_ENV_KEEP_LIST").split(",").map(|s| s.to_string()).collect()),
            check: Some(env!("RAR_ENV_CHECK_LIST").split(",").map(|s| s.to_string()).collect()),
            delete: Some(env!("RAR_ENV_DELETE_LIST").split(",").map(|s| s.to_string()).collect()),
            set: if env!("RAR_ENV_SET_LIST").len() > 0 && env!("RAR_ENV_SET_LIST") != "{}" { serde_json::from_str(env!("RAR_ENV_SET_LIST")).unwrap()} else { HashMap::new() },
            _extra_fields: Value::Null,
        }),
        root: Some(env!("RAR_USER_CONSIDERED").parse().unwrap()),
        bounding: Some(env!("RAR_BOUNDING").parse().unwrap()),
        wildcard_denied: Some(env!("RAR_WILDCARD_DENIED").to_string()),
        authentication: Some(env!("RAR_AUTHENTICATION").parse().unwrap()),
        _extra_fields: Value::Null,
    });
    *content = serde_json::to_string_pretty(&config)?;
    Ok(())
}

fn set_immutable(config: &mut SettingsFile, value: bool) {
    if let Some(settings) = config.storage.settings.as_mut() {
        if let Some(mut _immutable) = settings.immutable {
            _immutable = value;
        }
    }

    if !value {
        let roles = config
            ._extra_fields
            .as_object_mut()
            .unwrap()
            .get_mut("roles")
            .unwrap()
            .as_array_mut()
            .unwrap();
        for role in roles {
            let tasks = role.as_object_mut().unwrap().get_mut("tasks");
            if let Some(tasks) = tasks {
                for task in tasks.as_array_mut().unwrap() {
                    let cred = task
                        .as_object_mut()
                        .unwrap()
                        .get_mut("cred")
                        .unwrap()
                        .as_object_mut()
                        .unwrap();
                    let caps = cred
                        .get_mut("capabilities")
                        .unwrap()
                        .as_object_mut()
                        .unwrap();
                    if let Some(add) = caps.get_mut("add") {
                        add.as_array_mut()
                            .unwrap()
                            .retain(|x| x.as_str().unwrap() != "CAP_LINUX_IMMUTABLE");
                    }
                    if let Some(sub) = caps.get_mut("sub") {
                        sub.as_array_mut()
                            .unwrap()
                            .retain(|x| x.as_str().unwrap() != "CAP_LINUX_IMMUTABLE");
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
        if let Ok(line_result) = line_result {
            let fields: Vec<&str> = line_result.split_whitespace().collect();
            if fields.len() > 2 {
                let mount_point = fields[1];
                let fs_type = fields[2];
                if path.starts_with(mount_point) && mount_point.len() > longest_mount_point.len() {
                    longest_mount_point = mount_point.to_string();
                    filesystem_type = Some(fs_type.to_string());
                }
            }
        } else {
            return Err(line_result.unwrap_err());
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
    let mut status = ConfigState::Unchanged;
    // Check if the target file exists
    if !Path::new(ROOTASROLE).exists() {
        info!("Config file {} does not exist, deploying default file", ROOTASROLE);
        // If the target file does not exist, copy the default file
        deploy_config(ROOTASROLE)?;
    } else {
        status = config_state()?;
    }

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
    let mut content = TEMPLATE.to_string();

    let user = retrieve_real_user()?;
    // Replace the placeholder with the current user, which will act as the main administrator
    match user {
        Some(user) => {
            content = content.replace("\"ROOTADMINISTRATOR\"", &format!("\"{}\"", user.name));
        }
        None => {
            warn!("Failed to get the current user from passwd file, using UID instead");
            content = content.replace("\"ROOTADMINISTRATOR\"", &format!("{}", getuid().as_raw()));
        }
    }
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

pub fn pam_config(os: &OsTarget) -> &'static str {
    match os {
        OsTarget::Debian | OsTarget::Ubuntu => {
            include_str!("../../resources/debian/deb_sr_pam.conf")
        }
        OsTarget::RedHat | OsTarget::Fedora => include_str!("../../resources/rh/rh_sr_pam.conf"),
        OsTarget::ArchLinux => include_str!("../../resources/arch/arch_sr_pam.conf"),
    }
}

fn deploy_pam_config(os: &OsTarget) -> io::Result<u64> {
    if fs::metadata(PAM_CONFIG_PATH).is_err() {
        info!("Deploying PAM configuration file");
        let mut pam_conf = File::create(PAM_CONFIG_PATH)?;
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
                info!("Detected OS is : {}", t);
                t
            })
            .context("Failed to detect the OS")?
    };
    deploy_pam_config(&os).context("Failed to deploy the PAM configuration file")?;

    deploy_config_file()?;
    Ok(())
}
