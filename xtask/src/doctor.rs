use std::fs;

use clap::Parser;
use log::{info, warn};

use crate::{
    installer::dependencies,
    util::{RAR_CFG_PATH, command_exists, detect_priv_bin, get_os},
};

#[derive(Debug, Parser)]
pub struct DoctorOptions {
    /// Also check optional packaging/build tools
    #[clap(long)]
    pub full: bool,
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

    for (build, what) in [(false, "run"), (true, "build")] {
        match dependencies::missing_packages(&os, build) {
            Ok(missing) if missing.is_empty() => info!("Found the packages to {what} RootAsRole"),
            Ok(missing) => warn!("{}", dependencies::missing_message(&os, build, &missing)?),
            Err(e) => warn!("The packages to {what} RootAsRole cannot be checked: {e:#}"),
        }
    }
    match dependencies::missing_optional(&os) {
        Ok(missing) => {
            for (package, purpose) in missing {
                warn!(
                    "{}",
                    dependencies::optional_message(&os, &package, &purpose)?
                );
            }
        }
        Err(e) => warn!("The optional packages cannot be checked: {e:#}"),
    }

    if opts.full {
        for command in ["gzip", "upx"] {
            if command_exists(command) {
                info!("Found optional command: {command}");
            } else {
                warn!("Missing optional command: {command}");
            }
        }
    }

    if fs::metadata(RAR_CFG_PATH).is_ok() {
        info!("Configuration file exists: {RAR_CFG_PATH}");
    } else {
        warn!("Configuration file does not exist yet: {RAR_CFG_PATH}");
    }

    Ok(())
}
