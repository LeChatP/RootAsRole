use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

use anyhow::Context;
use nix::unistd::{getresuid, getuid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::EnumIs;

use super::util::files_are_equal;
use super::OsTarget;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SettingsFile {
    pub storage: Settings,
    #[serde(default)]
    #[serde(flatten, skip)]
    pub _extra_fields: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Settings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<RemoteStorageSettings>,
    #[serde(default)]
    #[serde(flatten)]
    pub _extra_fields: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoteStorageSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immutable: Option<bool>,
    #[serde(default)]
    #[serde(flatten)]
    pub _extra_fields: Value,
}

pub const CONFIG_FILE: &str = "/etc/security/rootasrole.json";
const DEFAULT_PATH: &str = "resources/rootasrole.json";
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
        for line in reader.lines() {
            if let Ok(line) = line {
                if line.contains("docker") || line.contains("kubepods") || line.contains("lxc") || line.contains("containerd") {
                    return true;
                }
            }
        }
    }

    false
}

fn check_filesystem() -> io::Result<()> {
    let config = BufReader::new(File::open(CONFIG_FILE)?);
    let mut config: SettingsFile = serde_json::from_reader(config)?;
    // Get the filesystem type
    if let Some(fs_type) = get_filesystem_type(CONFIG_FILE)? {
        match fs_type.as_str() {
            "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "ocfs2" | "jfs" | "reiserfs" => {
                set_immutable(&mut config, true);
            }
            _ => {
                set_immutable(&mut config, false);
            }
        }
    } else {
        set_immutable(&mut config, false);
    }
    Ok(())
}

fn set_immutable(config: &mut SettingsFile, value: bool) {
    if let Some(settings) = config.storage.settings.as_mut() {
        if let Some(mut _immutable) = settings.immutable {
            _immutable = value;
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
    if !Path::new(CONFIG_FILE).exists() {
        // If the target file does not exist, copy the default file
        deploy_config(CONFIG_FILE)?;
    } else {
        status = config_state()?;
    }
    Ok(status)
}

pub fn config_state() -> Result<ConfigState, anyhow::Error> {
    let temporary_config_file = "/tmp/rar.json";
    deploy_config(temporary_config_file)?;
    let status = if files_are_equal(temporary_config_file, CONFIG_FILE)? {
        ConfigState::Unchanged
    } else {
        ConfigState::Modified
    };
    fs::remove_file(temporary_config_file)?;
    Ok(status)
}

fn deploy_config<P:AsRef<Path>>(config_path: P) -> Result<(), anyhow::Error> {
    let config = File::open(DEFAULT_PATH)?;
    let mut buf = BufReader::new(config);
    let mut content = String::new();
    // Read the default config file
    buf.read_to_string(&mut content)?;
    // Get the real user
    
    let user = retrieve_real_user()?;
    // Replace the placeholder with the current user, which will act as the main administrator
    match user {
        Some(user) => {
            content = content.replace(
                "\"ROOTADMINISTRATOR\"",
                &format!("\"{}\"", user.name),
            );
        }
        None => {
            eprintln!("Failed to get the current user from passwd file, using UID instead");
            content = content.replace("\"ROOTADMINISTRATOR\"", &format!("{}", getuid().as_raw()));
        }
    }
    // Write the config file
    let mut config = File::create(config_path)?;
    config.write_all(content.as_bytes())?;
    config.sync_all()?;
    Ok(())
}

fn retrieve_real_user() -> Result<Option<nix::unistd::User>, anyhow::Error> {
    // if sudo_user is not set, get the real user
    if let Ok(sudo_user) = env::var("SUDO_USER") {
        let user = nix::unistd::User::from_name(&sudo_user)
            .context("Failed to get the sudo user")?;
        return Ok(user);
    } else {
        let ruid = getresuid()?.real;
        let user = nix::unistd::User::from_uid(ruid)
        .context("Failed to get the real user")?;
        Ok(user)
    }

}

pub fn default_pam_path(os : &OsTarget) -> &'static str {
    match os {
        OsTarget::Debian | OsTarget::Ubuntu => "resources/debian/deb_sr_pam.conf",
        OsTarget::RedHat | OsTarget::CentOS | OsTarget::Fedora => "resources/redhat/rh_sr_pam.conf",
        OsTarget::ArchLinux => "resources/arch/arch_sr_pam.conf",
    }
}

fn deploy_pam_config(os: &OsTarget) -> io::Result<u64> {
    if fs::metadata(PAM_CONFIG_PATH).is_err() {
        return fs::copy(default_pam_path(os), PAM_CONFIG_PATH);
    }
    Ok(0)
}

pub fn configure(os: &Option<OsTarget>) -> Result<(), anyhow::Error> {
    let os = if let Some(os) = os {
        os
    } else {
        &OsTarget::detect().context("Failed to detect the OS")?
    };
    deploy_pam_config(os).context("Failed to deploy the PAM configuration file")?;

    deploy_config_file()
        .context("Failed to configure the config file")
        .and_then(|state| match state {
            ConfigState::Unchanged => {
                let res = check_filesystem().context("Failed to configure the filesystem parameter");
                if res.is_err() {
                    // If the filesystem check fails, ignore the error if running in a container as it may not have immutable access
                    if is_running_in_container() {
                        return Ok(());
                    }
                }
                res
            }
            ConfigState::Modified => Ok(()),
        })

    
}
