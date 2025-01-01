mod configure;
mod deploy;
mod installer;
pub mod util;

use std::process::exit;

use clap::Parser;
use log::error;
use util::OsTarget;

#[derive(Debug, Parser)]
pub struct Options {
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
}

fn main() {
    env_logger::builder()
        .default_format()
        .format_module_path(true)
        .init();
    let opts = Options::parse();
    use Command::*;
    let ret = match opts.command {
        Dependencies(opts) => installer::dependencies(opts),
        Build(opts) => installer::build(&opts),
        Install(opts) => installer::install(&opts),
        Configure { os } => installer::configure(os),
        Uninstall(opts) => installer::uninstall(&opts),
        Deploy(opts) => deploy::deploy(&opts),
    };

    if let Err(e) = ret {
        error!("{e:#}");
        exit(1);
    }
}
