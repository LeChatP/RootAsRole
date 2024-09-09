use std::process::{Command, ExitStatus, Stdio};

use anyhow::Context;

use crate::{
    install::{self, dependencies::install_dependencies, InstallDependenciesOptions, Profile},
    util::{get_os, OsTarget},
};

use super::setup_maint_scripts;

fn dependencies(os: &OsTarget, priv_bin: Option<String>) -> Result<ExitStatus, anyhow::Error> {
    install_dependencies(os, &["upx", "dpkg"], priv_bin)
        .context("failed to install packaging dependencies")
}

pub fn make_deb(
    os: Option<OsTarget>,
    profile: Profile,
    priv_bin: &Option<String>,
) -> Result<(), anyhow::Error> {
    let os = get_os(os)?;

    dependencies(&os, priv_bin.clone())?;

    install::dependencies(InstallDependenciesOptions {
        os: Some(os),
        install_dependencies: true,
        dev: true,
        priv_bin: priv_bin.clone(),
    })?;
    install::build(&install::BuildOptions {
        profile,
        toolchain: install::Toolchain::default(),
        clean_before: false,
        privbin: Some("sudo".to_string()),
    })?;
    setup_maint_scripts()?;

    Command::new("cargo")
        .arg("deb")
        .arg("--no-build")
        .status()?;
    Ok(())
}
