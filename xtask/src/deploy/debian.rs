use std::process::{Command, ExitStatus, Stdio};

use anyhow::Context;

use crate::{install::{self, dependencies::install_dependencies, InstallDependenciesOptions, Profile}, util::OsTarget};

pub fn dependencies() -> Result<ExitStatus, anyhow::Error> {
    install_dependencies(&OsTarget::detect()?, &["upx", "dpkg"]).context("failed to install packaging dependencies")
}

pub fn make_deb(profile: Profile) -> Result<(), anyhow::Error> {
    
    
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

fn setup_maint_scripts() -> Result<(), anyhow::Error> {
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