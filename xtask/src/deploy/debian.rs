use std::process::{Command, ExitStatus, Stdio};

use anyhow::Context;

use crate::{install::{self, dependencies::install_dependencies, InstallDependenciesOptions, Profile}, util::OsTarget};

use super::setup_maint_scripts;

pub fn dependencies() -> Result<ExitStatus, anyhow::Error> {
    install_dependencies(&OsTarget::detect()?, &["upx", "dpkg"]).context("failed to install packaging dependencies")
}

pub fn make_deb(profile: Profile) -> Result<(), anyhow::Error> {
    dependencies()?;
    
    install::dependencies(InstallDependenciesOptions {
        os: None,
        install_dependencies: true,
        dev: true,
    })?;
    install::build(&install::BuildOptions {
        profile,
        toolchain: install::Toolchain::default(),
        clean_before: true,
    })?;
    setup_maint_scripts()?;

    Command::new("cargo")
        .arg("deb")
        .arg("--no-build")
        .status()?;
    Ok(())
}

