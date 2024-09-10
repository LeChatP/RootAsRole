use std::process::Command;

use crate::{
    install::{self, InstallDependenciesOptions, Profile},
    util::{get_os, OsTarget},
};

pub fn make_rpm(
    os: Option<OsTarget>,
    profile: Profile,
    exe: &Option<String>,
) -> Result<(), anyhow::Error> {
    let os = get_os(os)?;
    install::dependencies(InstallDependenciesOptions {
        os: Some(os),
        install_dependencies: true,
        dev: true,
        priv_bin: exe.clone(),
    })?;
    install::build(&install::BuildOptions {
        profile,
        toolchain: install::Toolchain::default(),
        clean_before: false,
        privbin: Some("sudo".to_string()),
    })?;

    Command::new("cargo").arg("generate-rpm").status()?;
    Ok(())
}
