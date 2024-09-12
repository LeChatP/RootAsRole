use std::process::{Command, ExitStatus};

use anyhow::Context;

use crate::{
    installer::{self, dependencies::install_dependencies, InstallDependenciesOptions, Profile},
    util::{detect_priv_bin, get_os, OsTarget},
};

use super::setup_maint_scripts;

fn dependencies(os: &OsTarget, priv_bin: Option<String>) -> Result<ExitStatus, anyhow::Error> {
    install_dependencies(os, &["upx"], priv_bin).context("failed to install packaging dependencies")?;
    Command::new("cargo")
        .arg("install")
        .arg("cargo-deb")
        .status()
        .context("failed to install cargo-deb")
}

pub fn make_deb(
    os: Option<OsTarget>,
    profile: Profile,
    priv_bin: &Option<String>,
) -> Result<(), anyhow::Error> {
    let os = get_os(os)?;
    let priv_bin = priv_bin.clone().or(detect_priv_bin());
    dependencies(&os, priv_bin.clone())?;

    installer::dependencies(InstallDependenciesOptions {
        os: Some(os),
        install_dependencies: true,
        dev: true,
        priv_bin: priv_bin.clone(),
    })?;
    installer::build(&installer::BuildOptions {
        profile,
        toolchain: installer::Toolchain::default(),
        clean_before: false,
        privbin: priv_bin,
    })?;
    setup_maint_scripts()?;

    Command::new("cargo")
        .arg("deb")
        .arg("--no-build")
        .status()?;
    Ok(())
}
