mod configure;
mod deploy;
mod install;
pub mod util;

use std::process::exit;

use clap::Parser;
use tracing::{error, Level};
use tracing_subscriber::util::SubscriberInitExt;
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
fn subsribe() {
    use std::io;
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_file(true)
        .with_line_number(true)
        .with_writer(io::stdout)
        .finish()
        .init();
}

fn main() {
    subsribe();
    let opts = Options::parse();
    use Command::*;
    let ret = match opts.command {
        Dependencies(opts) => install::dependencies(opts),
        Build(opts) => install::build(&opts),
        Install(opts) => install::install(&opts),
        Configure { os } => install::configure(os),
        Uninstall(opts) => install::uninstall(&opts),
        Deploy(opts) => deploy::deploy(&opts),
    };

    if let Err(e) = ret {
        error!("{e:#}");
        exit(1);
    }
}
