mod configure;
mod doctor;
mod installer;
pub mod util;

use Command::{Build, Configure, Dependencies, Doctor, Install, Uninstall};

use std::process::exit;

use clap::Parser;
use log::{debug, error, info};
use util::OsTarget;

#[derive(Debug, Parser)]
pub struct Options {
    /// Print planned actions without executing mutating steps
    #[clap(long, global = true)]
    dry_run: bool,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    #[cfg(feature = "cli")]
    Dependencies(installer::InstallDependenciesOptions),
    #[cfg(feature = "cli")]
    Build(installer::BuildOptions),
    #[cfg(feature = "cli")]
    Install(installer::InstallOptions),

    Configure {
        /// The OS target
        #[clap(long)]
        os: Option<OsTarget>,
    },
    Uninstall(installer::UninstallOptions),
    Doctor(doctor::DoctorOptions),
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_module_path(false)
        .format_file(false)
        .format_source_path(false)
        .format_target(false)
        .init();
    debug!(
        "Starting xtask with arguments: {:?}",
        std::env::args().collect::<Vec<_>>()
    );
    if std::env::var_os("ROOTASROLE_INSTALLER_NESTED").is_some() {
        info!("nested install is enabled");
    }
    if let Err(e) = run(Options::parse()) {
        error!("{e:#}");
        exit(1);
    }
}

/// Run the command of `opts`. `--dry-run` was parsed but never applied: a dry run of install
/// elevated through the real privilege escalator.
fn run(opts: Options) -> Result<(), anyhow::Error> {
    util::set_dry_run(opts.dry_run);
    match opts.command {
        Dependencies(opts) => installer::dependencies(&opts),
        Build(opts) => installer::build(&opts),
        Install(opts) => installer::install(&opts),
        Configure { os } => installer::configure(os),
        Uninstall(opts) => installer::uninstall(&opts),
        Doctor(opts) => doctor::doctor(&opts),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };

    use super::*;

    /// A program that leaves a mark when it runs, given as the privilege escalation of the
    /// tests: even a dry run that went wrong would run it, never sudo nor dosr.
    fn marker_program(dir: &Path) -> (PathBuf, PathBuf) {
        let program = dir.join("escalate");
        fs::write(&program, "#!/bin/sh\ntouch \"$0.ran\"\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        (program, dir.join("escalate.ran"))
    }

    #[test]
    fn test_dry_run_runs_no_command() {
        let _guard = util::DRY_RUN_TEST_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("xtask_dry_run_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (program, mark) = marker_program(&dir);
        let program_arg = program.to_str().unwrap();
        for args in [
            vec!["xtask", "--dry-run", "install", "-p", program_arg],
            vec!["xtask", "install", "--dry-run", "-bi", "-p", program_arg],
            vec![
                "xtask",
                "--dry-run",
                "dependencies",
                "-i",
                "-p",
                program_arg,
            ],
            vec!["xtask", "--dry-run", "configure"],
        ] {
            run(Options::parse_from(&args)).unwrap();
            assert!(!mark.exists(), "{args:?} ran the privilege escalation");
        }
        // the program does leave its mark when it is run: the check above can fail
        util::set_dry_run(false);
        util::run_checked(&mut std::process::Command::new(&program), "leave a mark").unwrap();
        assert!(mark.exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
