use std::process::Command;

use crate::{
    installer::{self, InstallDependenciesOptions, Profile},
    util::{detect_priv_bin, get_os, OsTarget},
};

fn install_dependencies() -> Result<(), anyhow::Error> {
    Command::new("cargo")
        .arg("install")
        .arg("cargo-generate-rpm")
        .status()?;
    Ok(())
}

pub fn make_rpm(
    os: Option<OsTarget>,
    profile: Profile,
    exe: &Option<String>,
) -> Result<(), anyhow::Error> {
    install_dependencies()?;
    let os = get_os(os)?;
    let exe: Option<String> = exe.clone().or(detect_priv_bin());

    installer::dependencies(InstallDependenciesOptions {
        os: Some(os),
        install_dependencies: true,
        dev: true,
        priv_bin: exe.clone(),
    })?;
    installer::build(&installer::BuildOptions {
        profile,
        toolchain: installer::Toolchain::default(),
        clean_before: false,
        privbin: exe.clone(),
    })?;

    Command::new("cargo").arg("generate-rpm").status()?;
    Ok(())
}
