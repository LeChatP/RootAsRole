use std::fs;
use super::{configure::{config_state, CONFIG_FILE, PAM_CONFIG_PATH}, util::files_are_equal, UninstallOptions, CAPABLE_DEST, CHSR_DEST, SR_DEST};


pub fn uninstall(opts : &UninstallOptions) -> Result<(), anyhow::Error> {
    fs::remove_file(SR_DEST)?;
    fs::remove_file(CHSR_DEST)?;
    if fs::metadata(CAPABLE_DEST).is_ok() {
        fs::remove_file(CAPABLE_DEST)?;
    }
    if opts.clean_config || files_are_equal("resources/debian/deb_sr_pam.conf", PAM_CONFIG_PATH)?
            || files_are_equal("resources/rh/rh_sr_pam.conf", PAM_CONFIG_PATH)?
            || files_are_equal("resources/arch/arch_sr_pam.conf", PAM_CONFIG_PATH)?
    {
        fs::remove_file(PAM_CONFIG_PATH)?;
    }
    if opts.clean_config || config_state()?.is_unchanged()  {
        fs::remove_file(CONFIG_FILE)?;
    }
    Ok(())
    
}
