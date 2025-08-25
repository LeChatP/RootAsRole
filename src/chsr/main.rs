//extern crate sudoers_reader;

use rar_common::util::subsribe;

mod cli;
#[cfg(not(tarpaulin_include))]
mod security;
mod util;

#[cfg(not(test))]
const ROOTASROLE: &str = env!("RAR_CFG_PATH");
#[cfg(test)]
const ROOTASROLE: &str = "target/rootasrole.json";

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{env::temp_dir, fs::OpenOptions};

    use crate::cli::editor::defer;
    use ::landlock::{RestrictionStatus, RulesetStatus};
    use capctl::Cap;
    use log::{error, warn};
    use rar_common::{util::definitive_drop, LockedSettingsFile};

    use crate::security::{full_program_lock, seccomp_lock};

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

    // Apply Landlock restrictions
    let ruleset_status = match full_program_lock(&folder) {
        Ok(RestrictionStatus { ruleset, .. }) => ruleset,
        Err(e) => {
            warn!("Failed to apply landlock policy: {:#}", e);
            RulesetStatus::NotEnforced
        }
    };

    // Then apply seccomp restrictions
    seccomp_lock()?;

    let mut settings = LockedSettingsFile::open(
        &ROOTASROLE.to_string(),
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .to_owned(),
        true,
    )
    .expect("Error on config read");

    if cli::main(settings.data.clone(), std::env::args().skip(1))
        .ruleset(ruleset_status)
        .folder(&folder)
        .call()
        .map_err(|e| error!("Unable to edit policy : {}", e))
        .is_ok_and(|b| b)
    {
        settings.save()
    } else {
        Ok(())
    }
}
