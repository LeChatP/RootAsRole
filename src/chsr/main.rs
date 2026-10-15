//extern crate sudoers_reader;

mod cli;
#[cfg(not(tarpaulin_include))]
mod security;
mod util;

#[cfg(not(tarpaulin_include))]
fn main() -> Result<std::process::ExitCode, Box<dyn std::error::Error>> {
    use std::{env::temp_dir, process::ExitCode};

    use crate::{
        cli::editor::defer,
        util::{RAR_CFG_DATA_PATH, RAR_CFG_PATH},
    };
    use ::landlock::{RestrictionStatus, RulesetStatus};
    use capctl::Cap;
    use log::{debug, error, warn};
    use rootasrole_core::{
        file::FileSettings,
        log::subsribe,
        util::{RAR_CFG_TYPE, definitive_drop},
    };

    use crate::security::full_program_lock;

    subsribe("chsr")?;
    // Drop privileges we don't need
    definitive_drop(&[
        Cap::DAC_OVERRIDE,
        Cap::DAC_READ_SEARCH,
        Cap::FOWNER,
        Cap::CHOWN,
        Cap::LINUX_IMMUTABLE,
    ])?;

    let folder = nix::unistd::mkdtemp(&temp_dir().join("chsr_XXXXXX"))
        .expect("Failed to create temporary folder");
    let _cleanup = defer(|| {
        let _ = std::fs::remove_dir_all(&folder);
    });

    let mut settings = FileSettings::write_all(RAR_CFG_PATH, RAR_CFG_DATA_PATH, RAR_CFG_TYPE)
        .expect("Error on config read");

    // Apply Landlock restrictions
    let ruleset_status = match full_program_lock(
        &folder,
        settings
            .get_root()
            .storage
            .settings
            .as_ref()
            .and_then(|s| s.path.as_ref())
            .and_then(|p| p.to_str())
            .unwrap_or(RAR_CFG_DATA_PATH),
    ) {
        Ok(RestrictionStatus { ruleset, .. }) => ruleset,
        Err(e) => {
            warn!("Failed to apply landlock policy: {e:#}");
            RulesetStatus::NotEnforced
        }
    };

    match cli::main(&mut settings, std::env::args().skip(1))
        .ruleset(&ruleset_status)
        .folder(&folder)
        .call()
    {
        Ok(true) => {
            debug!("Saving configuration");
            settings.save_all()?;
            Ok(ExitCode::SUCCESS)
        }
        Ok(false) => Ok(ExitCode::SUCCESS),
        Err(e) => {
            error!("Unable to edit policy : {e}");
            Ok(ExitCode::FAILURE)
        }
    }
}
