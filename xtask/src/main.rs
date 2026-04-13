mod configure;
mod deploy;
mod doctor;
mod installer;
pub mod util;

use Command::{Build, Configure, Dependencies, Deploy, Doctor, Install, Uninstall};
use std::process::exit;

use clap::Parser;
use log::{debug, error};
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
    #[cfg(feature = "deploy")]
    Deploy(deploy::MakeOptions),
    Doctor(doctor::DoctorOptions),
}

fn main() {
    env_logger::builder()
        .default_format()
        .format_module_path(true)
        .init();
    debug!("Starting xtask with arguments: {:?}", std::env::args().collect::<Vec<_>>());
    if std::env::var_os("ROOTASROLE_INSTALLER_NESTED").is_some() {
        println!("nested install is enabled");
    }
    let opts = Options::parse();
    util::set_dry_run(opts.dry_run);
    let ret = match opts.command {
        Dependencies(opts) => installer::dependencies(&opts),
        Build(opts) => installer::build(&opts),
        Install(opts) => installer::install(&opts),
        Configure { os } => installer::configure(os),
        Uninstall(opts) => installer::uninstall(&opts),
        Deploy(opts) => deploy::deploy(&opts),
        Doctor(opts) => doctor::doctor(&opts),
    };

    if let Err(e) = ret {
        error!("{e:#}");
        exit(1);
    }
}
