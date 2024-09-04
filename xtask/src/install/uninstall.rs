use anyhow::Context;
use rar_common::util::toggle_lock_config;
use std::fs;

use super::{
    configure::{config_state, CONFIG_FILE, PAM_CONFIG_PATH},
    util::files_are_equal,
    UninstallOptions, CAPABLE_DEST, CHSR_DEST, SR_DEST,
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
                toggle_lock_config(
                    &CONFIG_FILE.to_string(),
                    rar_common::util::ImmutableLock::Unset,
                )
                .context("Error while removing lock from config file"),
            );
            errors.push(fs::remove_file(CONFIG_FILE).context(CONFIG_FILE));
        }
    }
    if opts.kind.is_all() || opts.kind.is_capable() {
        errors.push(fs::remove_file(CAPABLE_DEST).context(CAPABLE_DEST));
    }
    for error in errors {
        if let Err(e) = error {
            eprintln!("{}: {}", e.to_string(), e.source().unwrap().to_string());
        }
    }
    Ok(())
}
