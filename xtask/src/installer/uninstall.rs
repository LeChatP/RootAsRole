use anyhow::Context;
use log::warn;
use std::fs;

use crate::{
    configure::PAM_CONFIGS,
    util::{
        ImmutableLock, PAM_CONFIG_SERVICE, RAR_CFG_DATA_PATH, RAR_CFG_PATH, toggle_lock_config,
    },
};

use super::{CHSR_DEST, SR_DEST, UninstallOptions};

// a Result like every command of xtask, for the dispatch in main
#[allow(clippy::unnecessary_wraps)]
pub fn uninstall(opts: &UninstallOptions) -> Result<(), anyhow::Error> {
    let mut errors = vec![];
    if opts.kind.is_all() || opts.kind.is_sr() {
        let pam_config_path = format!("/etc/pam.d/{PAM_CONFIG_SERVICE}");
        errors.push(fs::remove_file(SR_DEST).context(SR_DEST));
        errors.push(fs::remove_file(CHSR_DEST).context(CHSR_DEST));
        // the PAM service is removed if it is one that the installer deployed
        let deployed = fs::read_to_string(&pam_config_path)
            .is_ok_and(|content| PAM_CONFIGS.contains(&content.as_str()));
        if opts.clean_config || deployed {
            errors.push(fs::remove_file(&pam_config_path).context(pam_config_path));
        }
        if opts.clean_config {
            errors.push(
                toggle_lock_config(&RAR_CFG_PATH.to_string(), &ImmutableLock::Unset)
                    .context("Error while removing lock from config file"),
            );
            errors.push(
                toggle_lock_config(&RAR_CFG_DATA_PATH.to_string(), &ImmutableLock::Unset)
                    .context("Error while removing lock from config file"),
            );
            errors.push(fs::remove_file(RAR_CFG_PATH).context(RAR_CFG_PATH));
        }
    }
    for error in errors {
        if let Err(e) = error {
            warn!("{}: {}", e, e.source().expect("Error should have a source"));
        }
    }
    Ok(())
}
