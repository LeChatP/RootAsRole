use std::{collections::HashSet, process::Command};

use clap::Parser;

use crate::{install::Profile, util::OsTarget};

mod debian;
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

    /// The binary to elevate privileges
    #[clap(long, short = 'p')]
    pub priv_bin: Option<String>,
}

fn all() -> HashSet<OsTarget> {
    vec![OsTarget::Debian, OsTarget::ArchLinux, OsTarget::RedHat]
        .into_iter()
        .collect()
}

pub fn deploy(opts: &MakeOptions) -> Result<(), anyhow::Error> {
    let targets = if opts.target.is_empty() {
        all()
    } else {
        opts.target.iter().cloned().collect::<HashSet<OsTarget>>()
    };

    for target in targets {
        match target {
            OsTarget::Debian => debian::make_deb(opts.os.clone(), opts.profile, &opts.priv_bin)?,
            OsTarget::RedHat => redhat::make_rpm(opts.os.clone(), opts.profile, &opts.priv_bin)?,
            _ => anyhow::bail!("Unsupported OS target"),
        }
    }

    Ok(())
}

pub fn setup_maint_scripts() -> Result<(), anyhow::Error> {
    Command::new("cargo")
        .arg("build")
        .arg("--package")
        .arg("xtask")
        .arg("--no-default-features")
        .arg("--release")
        .arg("--bin")
        .arg("postinst")
        .arg("--bin")
        .arg("prerm")
        .status()?;
    compress("target/release/postinst")?;
    compress("target/release/prerm")
}

fn compress(script: &str) -> Result<(), anyhow::Error> {
    Command::new("upx")
        .arg("--best")
        .arg("--lzma")
        .arg(script)
        .status()?;
    Ok(())
}
