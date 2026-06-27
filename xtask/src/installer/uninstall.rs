use anyhow::Context;
use log::warn;
use std::fs;

use crate::util::{
    ImmutableLock, RAR_CFG_DATA_PATH, RAR_CFG_PATH, files_are_equal, toggle_lock_config,
};

use super::{CHSR_DEST, SR_DEST, UninstallOptions};

pub fn uninstall(opts: &UninstallOptions) -> Result<(), anyhow::Error> {
    let mut errors = vec![];
    if opts.kind.is_all() || opts.kind.is_sr() {
        const PAM_CONFIG_PATH: &str = concat!("/etc/pam.d/", env!("RAR_PAM_SERVICE"));
        errors.push(fs::remove_file(SR_DEST).context(SR_DEST));
        errors.push(fs::remove_file(CHSR_DEST).context(CHSR_DEST));
        if opts.clean_config
            || files_are_equal("resources/debian/deb_sr_pam.conf", PAM_CONFIG_PATH)?
            || files_are_equal("resources/rh/rh_sr_pam.conf", PAM_CONFIG_PATH)?
            || files_are_equal("resources/arch/arch_sr_pam.conf", PAM_CONFIG_PATH)?
        {
            errors.push(fs::remove_file(PAM_CONFIG_PATH).context(PAM_CONFIG_PATH));
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
