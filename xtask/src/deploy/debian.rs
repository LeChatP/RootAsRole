use std::{
    fs::File,
    io::{BufRead, Write},
    process::{Command, ExitStatus},
};

use anyhow::Context;
use tracing::debug;

use crate::{
    installer::{self, dependencies::install_dependencies, InstallDependenciesOptions, Profile},
    util::{detect_priv_bin, get_os, OsTarget},
};

use super::setup_maint_scripts;

fn dependencies(os: &OsTarget, priv_bin: Option<String>) -> Result<ExitStatus, anyhow::Error> {
    install_dependencies(os, &["upx"], priv_bin)
        .context("failed to install packaging dependencies")?;
    Command::new("cargo")
        .arg("install")
        .arg("cargo-deb")
        .status()
        .context("failed to install cargo-deb")
}

fn generate_changelog() -> Result<(), anyhow::Error> {
    let binding = Command::new("git")
        .args(["tag", "--sort=-creatordate"])
        .output()?;
    let mut ordered_tags = binding.stdout.lines();

    let from = ordered_tags
        .next()
        .expect("Are you in the git repository ?")?;

    let to = ordered_tags
        .next()
        .expect("Are you in the git repository ?")?;

    debug!("Generating changelog from {} to {}", from, to);

    let changes = Command::new("git")
        .args([
            "log",
            "--pretty=format:  * %s",
            &format!("{}..{}", to, from),
        ])
        .output()?;
    debug!(
        "Changes: {}",
        String::from_utf8(changes.stdout.clone()).unwrap()
    );
    let changelog = format!(
        r#"rootasrole ({version}) {dist}; urgency={urgency}

{changes}

-- Eddie Billoir <lechatp@outlook.fr>  {date}"#,
        version = env!("CARGO_PKG_VERSION"),
        dist = "unstable",
        urgency = "low",
        changes = String::from_utf8(changes.stdout).unwrap(),
        date = chrono::Local::now().format("%a, %d %b %Y %T %z")
    );
    File::create("target/debian/changelog")?.write_all(changelog.as_bytes())?;

    Ok(())
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
    generate_changelog()?;

    Command::new("cargo")
        .arg("deb")
        .arg("--no-build")
        .status()?;
    Ok(())
}
