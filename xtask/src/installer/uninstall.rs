use anyhow::Context;
use log::warn;
use std::fs;

use crate::util::{files_are_equal, toggle_lock_config, ImmutableLock, ROOTASROLE};

use super::{
    configure::{config_state, PAM_CONFIG_PATH},
    UninstallOptions, CHSR_DEST, SR_DEST,
};

pub fn uninstall(opts: &UninstallOptions) -> Result<(), anyhow::Error> {
    let mut errors = vec![];
    if opts.kind.is_all() || opts.kind.is_sr() {
        errors.push(fs::remove_file(SR_DEST).context(SR_DEST));
        errors.push(fs::remove_file(CHSR_DEST).context(CHSR_DEST));
        if opts.clean_config
            || files_are_equal("resources/debian/deb_sr_pam.conf", PAM_CONFIG_PATH)?
            || files_are_equal("resources/rh/rh_sr_pam.conf", PAM_CONFIG_PATH)?
            || files_are_equal("resources/arch/arch_sr_pam.conf", PAM_CONFIG_PATH)?
        {
            errors.push(fs::remove_file(PAM_CONFIG_PATH).context(PAM_CONFIG_PATH));
        }
        if opts.clean_config || config_state()?.is_unchanged() {
            errors.push(
                toggle_lock_config(&ROOTASROLE.to_string(), ImmutableLock::Unset)
                    .context("Error while removing lock from config file"),
            );
            errors.push(fs::remove_file(ROOTASROLE).context(ROOTASROLE));
        }
    }
    for error in errors {
        if let Err(e) = error {
            warn!("{}: {}", e.to_string(), e.source().unwrap().to_string());
        }
    }
    Ok(())
}
