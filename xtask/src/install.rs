use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;


pub fn post_install() -> Result<(), anyhow::Error> {
    check_config_file()?;
    check_filesystem()?;
    

    Ok(())
}

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

const CONFIG_FILE: &str = "/etc/security/rootasrole.json";

fn check_filesystem() -> io::Result<()> {
    let config = BufReader::new(File::open(CONFIG_FILE)?);
    let mut config: SettingsFile = serde_json::from_reader(config)?;
    // Get the filesystem type
    if let Some(fs_type) = get_filesystem_type(CONFIG_FILE)? {
        match fs_type.as_str() {
            "ext2"|"ext3"|"ext4"|"xfs"|"btrfs"|"ocfs2"|"jfs"|"reiserfs" => {
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
        if let Some(mut immutable) = settings.immutable {
            immutable = value;
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

fn check_config_file() -> io::Result<()> {
    let default_path = "/usr/share/rootasrole/default.json";

    // Check if the target file exists
    if !Path::new(CONFIG_FILE).exists() {
        // If the target file does not exist, copy the default file
        if let Err(e) = fs::copy(default_path, CONFIG_FILE) {
            eprintln!("Failed to copy the default configuration file to {}: {}", CONFIG_FILE, e);
            std::process::exit(1);
        }
    } else {
        // If the target file exists, compare it with the default file
        if !files_are_equal(default_path, CONFIG_FILE)? {
            std::process::exit(0);
        }
    }

    Ok(())
}

fn files_are_equal(path1: &str, path2: &str) -> io::Result<bool> {
    let file1_content = fs::read(path1)?;
    let file2_content = fs::read(path2)?;

    Ok(file1_content == file2_content)
}