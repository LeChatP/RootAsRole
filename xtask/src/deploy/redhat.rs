use std::process::Command;

use crate::install::{self, InstallDependenciesOptions, Profile};

use super::setup_maint_scripts;


pub fn make_rpm(profile: Profile) -> Result<(), anyhow::Error> {
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

    Command::new("cargo")
        .arg("generate-rpm")
        .status()?;
    Ok(())
}