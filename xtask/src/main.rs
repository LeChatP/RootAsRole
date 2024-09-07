mod install;
mod configure;
mod deploy;
pub mod util;

use std::process::exit;

use clap::Parser;
use util::OsTarget;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    #[cfg(feature = "cli")]
    Dependencies(install::InstallDependenciesOptions),
    #[cfg(feature = "cli")]
    Build(install::BuildOptions),
    #[cfg(feature = "cli")]
    Install(install::InstallOptions),

    Configure {
        /// The OS target
        #[clap(long)]
        os: Option<OsTarget>,
    },
    Uninstall(install::UninstallOptions),
    #[cfg(feature = "deploy")]
    Deploy(deploy::MakeOptions),

}

fn main() {
    let opts = Options::parse();
    use Command::*;
    let ret = match opts.command {
        Dependencies(opts) => install::dependencies(opts),
        Build(opts)=> install::build(&opts),
        Install(opts) => install::install(&opts),
        Configure{ os} => install::configure(os),
        Uninstall(opts) => install::uninstall(&opts),
        Deploy(opts) => deploy::deploy(&opts),

    };
    

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
