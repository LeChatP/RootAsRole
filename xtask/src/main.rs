mod ebpf;
mod install;

use std::process::exit;

use clap::Parser;
use install::OsTarget;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(install::BuildOptions),
    RunEbpf(ebpf::run::RunOptions),
    Build(install::BuildOptions),
    Install(install::InstallOptions),
    Configure {
        /// The OS target
        #[clap(long)]
        os: Option<OsTarget>,
    },
    Uninstall(install::UninstallOptions),
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => ebpf::build_all(&opts),
        RunEbpf(opts) => ebpf::run(&opts),
        Build(opts) => install::build(&opts),
        Install(opts) => install::install(&opts),
        Configure{ os } => install::configure(os),
        Uninstall(opts) => install::uninstall(&opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
