//extern crate sudoers_reader;

// `println!` and the like panic when the output is a closed pipe (`EPIPE`, since Rust ignores
// `SIGPIPE`): outside the tests, the `*_ignore_io_error` macros of rootasrole-core are used.
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! println {
    ($($tt:tt)*) => {
        compile_error!("println! panics on EPIPE, use println_ignore_io_error!")
    };
}
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! print {
    ($($tt:tt)*) => {
        compile_error!("print! panics on EPIPE, use print_ignore_io_error!")
    };
}
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! eprintln {
    ($($tt:tt)*) => {
        compile_error!("eprintln! panics on EPIPE, use eprintln_ignore_io_error!")
    };
}
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! eprint {
    ($($tt:tt)*) => {
        compile_error!("eprint! panics on EPIPE, use eprintln_ignore_io_error!")
    };
}

mod cli;
#[cfg(not(tarpaulin_include))]
mod security;
mod util;

/// Report an error that stops chsr, on stderr and in the log.
#[cfg(not(tarpaulin_include))]
fn failure(message: &str) -> std::process::ExitCode {
    log::error!("{message}");
    rootasrole_core::eprintln_ignore_io_error!("chsr: {message}");
    std::process::ExitCode::FAILURE
}

#[cfg(not(tarpaulin_include))]
fn main() -> Result<std::process::ExitCode, Box<dyn std::error::Error>> {
    use std::{path::Path, process::ExitCode};

    use crate::{
        cli::editor::defer,
        util::{RAR_CFG_DATA_PATH, RAR_CFG_PATH},
    };
    use ::landlock::{RestrictionStatus, RulesetStatus};
    use capctl::Cap;
    use log::{debug, error, warn};
    use rootasrole_core::{
        file::FileSettings,
        log::subscribe,
        util::{RAR_CFG_TYPE, definitive_drop},
    };

    use crate::security::full_program_lock;

    subscribe("chsr")?;
    // Drop privileges we don't need
    definitive_drop(&[
        Cap::DAC_OVERRIDE,
        Cap::DAC_READ_SEARCH,
        Cap::FOWNER,
        Cap::CHOWN,
        Cap::LINUX_IMMUTABLE,
    ])?;

    // argv is untrusted: a non-UTF-8 argument is refused, std::env::args() would panic
    let Ok(args) = std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<String>, _>>()
    else {
        return Ok(failure("an argument is not valid UTF-8"));
    };
    // --help and a usage error need neither the policy nor the temporary folder
    if let Some(result) = cli::usage_without_policy(&args) {
        return Ok(if result.is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        });
    }

    // not in TMPDIR, which the user chooses when the policy keeps it: a folder in a directory
    // that the user owns can be renamed and replaced; /tmp is sticky
    let folder = match nix::unistd::mkdtemp(&Path::new("/tmp").join("chsr_XXXXXX")) {
        Ok(folder) => folder,
        Err(e) => return Ok(failure(&format!("cannot create a temporary folder: {e}"))),
    };
    let _cleanup = defer(|| {
        let _ = std::fs::remove_dir_all(&folder);
    });

    let mut settings = match FileSettings::write_all(RAR_CFG_PATH, RAR_CFG_DATA_PATH, RAR_CFG_TYPE)
    {
        Ok(settings) => settings,
        Err(e) => return Ok(failure(&format!("cannot read the policy: {e}"))),
    };

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

    match cli::main(&mut settings, &args)
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
