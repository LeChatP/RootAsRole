use std::collections::HashSet;

use clap::Parser;

use crate::{install::Profile, util::OsTarget};

mod debian;
mod arch;
mod redhat;

#[derive(Debug, Parser)]
pub struct MakeOptions {
    /// Build the target with debug profile (default is release)
    #[clap(short = 'd', long = "debug", default_value_t = Profile::Release, default_missing_value = "debug", num_args = 0)]
    pub profile: Profile,

    /// The current OS where the binary is running
    #[clap(long, short)]
    pub os: Option<OsTarget>,

    /// The OS target for package generation
    pub target: Vec<OsTarget>,
}

fn all() -> HashSet<OsTarget> {
    vec![OsTarget::Debian, OsTarget::ArchLinux, OsTarget::RedHat].into_iter().collect()
}

pub fn deploy(opts: &MakeOptions) -> Result<(), anyhow::Error> {
    let targets = if opts.target.is_empty() {
        all()
    } else {
        opts.target.iter().cloned().collect::<HashSet<OsTarget>>()
    };

    for target in targets {
        match target {
            OsTarget::Debian => {
                debian::dependencies()?;
                debian::make_deb(opts.profile)?;
                
            },
            OsTarget::ArchLinux => arch::make_pkg(opts.profile)?,
            OsTarget::RedHat => redhat::make_rpm(opts.profile)?,
            _ => anyhow::bail!("Unsupported OS target"),
        }
    }

    Ok(())
}
