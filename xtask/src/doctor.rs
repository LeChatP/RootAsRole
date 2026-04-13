use std::{
    env, fs,
    path::{Path, PathBuf},
};

use clap::Parser;
use log::{info, warn};

use crate::util::{ROOTASROLE, detect_priv_bin, get_os};

#[derive(Debug, Parser)]
pub struct DoctorOptions {
    /// Also check optional packaging/build tools
    #[clap(long)]
    pub full: bool,
}

fn command_exists(command: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };

    for dir in env::split_paths(&path) {
        let candidate: PathBuf = dir.join(command);
        if is_executable(&candidate) {
            return true;
        }
    }

    false
}

fn is_executable(path: &Path) -> bool {
    if let Ok(metadata) = fs::metadata(path) {
        if !metadata.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            return metadata.permissions().mode() & 0o111 != 0;
        }
        #[cfg(not(unix))]
        {
            return true;
        }
    }
    false
}

pub fn doctor(opts: &DoctorOptions) -> Result<(), anyhow::Error> {
    let os = get_os(None)?;
    info!("Detected target OS: {os}");

    if let Some(priv_bin) = detect_priv_bin() {
        info!("Privilege escalator: {}", priv_bin.display());
    } else {
        warn!("No privilege escalator detected (dosr/sudo/doas)");
    }

    for command in ["cargo", "git"] {
        if command_exists(command) {
            info!("Found required command: {command}");
        } else {
            warn!("Missing required command: {command}");
        }
    }

    if opts.full {
        for command in ["pandoc", "gzip", "upx"] {
            if command_exists(command) {
                info!("Found optional command: {command}");
            } else {
                warn!("Missing optional command: {command}");
            }
        }
    }

    if fs::metadata(ROOTASROLE).is_ok() {
        info!("Configuration file exists: {ROOTASROLE}");
    } else {
        warn!("Configuration file does not exist yet: {ROOTASROLE}");
    }

    Ok(())
}
