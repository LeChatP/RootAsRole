use std::{collections::HashSet, path::PathBuf, process::Command};

use clap::Parser;

use crate::util::{is_dry_run, run_checked};
use crate::{installer::Profile, util::OsTarget};

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
    #[clap(long, short = 'p', visible_alias = "privbin")]
    pub priv_bin: Option<PathBuf>,
}

fn all() -> HashSet<OsTarget> {
    vec![OsTarget::Debian, OsTarget::ArchLinux, OsTarget::RedHat]
        .into_iter()
        .collect()
}

pub fn deploy(opts: &MakeOptions) -> Result<(), anyhow::Error> {
    if is_dry_run() {
        log::debug!("Dry-run mode: skipping deploy changes");
        return Ok(());
    }

    let targets = if opts.target.is_empty() {
        all()
    } else {
        opts.target.iter().cloned().collect::<HashSet<OsTarget>>()
    };

    for target in targets {
        match target {
            OsTarget::Debian => {
                debian::make_deb(opts.os.as_ref(), opts.profile, opts.priv_bin.as_deref())?;
            }
            OsTarget::RedHat => {
                redhat::make_rpm(opts.os.as_ref(), opts.profile, opts.priv_bin.as_deref())?;
            }
            _ => anyhow::bail!("Unsupported OS target"),
        }
    }

    Ok(())
}

pub fn setup_maint_scripts() -> Result<(), anyhow::Error> {
    run_checked(
        Command::new("cargo")
            .arg("build")
            .arg("--package")
            .arg("xtask")
            .arg("--no-default-features")
            .arg("--release")
            .arg("--bin")
            .arg("postinst")
            .arg("--bin")
            .arg("prerm"),
        "build maintenance scripts",
    )?;
    compress("target/release/postinst")?;
    compress("target/release/prerm")
}

fn compress(script: &str) -> Result<(), anyhow::Error> {
    run_checked(
        Command::new("upx").arg("--best").arg("--lzma").arg(script),
        &format!("compress script {script}"),
    )?;
    Ok(())
}
