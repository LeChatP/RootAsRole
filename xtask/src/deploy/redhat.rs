use std::process::Command;
use std::path::Path;

use crate::{
    installer::{self, InstallDependenciesOptions, Profile},
    util::{OsTarget, detect_priv_bin, get_os, run_checked},
};

fn install_dependencies() -> Result<(), anyhow::Error> {
    run_checked(
        Command::new("cargo")
            .arg("install")
            .arg("cargo-generate-rpm"),
        "install cargo-generate-rpm",
    )?;
    Ok(())
}

pub fn make_rpm(
    os: Option<&OsTarget>,
    profile: Profile,
    exe: Option<&Path>,
) -> Result<(), anyhow::Error> {
    install_dependencies()?;
    let os = get_os(os)?;
    let exe = exe.map(Path::to_path_buf).or_else(detect_priv_bin);

    installer::dependencies(&InstallDependenciesOptions {
        os: Some(os),
        install_dependencies: true,
        dev: true,
        priv_bin: exe.clone(),
    })?;
    installer::build(&installer::BuildOptions {
        profile,
        toolchain: installer::Toolchain::default(),
        clean_before: false,
        priv_bin: exe,
    })?;

    run_checked(
        Command::new("cargo").arg("generate-rpm"),
        "generate rpm package",
    )?;
    Ok(())
}
