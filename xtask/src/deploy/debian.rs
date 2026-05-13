use std::{
    fs::File,
    io::{BufRead, Write},
    path::Path,
    process::Command,
};

use anyhow::{Context, anyhow};
use log::debug;

use crate::{
    installer::{self, InstallDependenciesOptions, Profile, dependencies::install_dependencies},
    util::{OsTarget, detect_priv_bin, get_os, output_checked, run_checked},
};

use super::setup_maint_scripts;

fn dependencies(os: &OsTarget, priv_bin: Option<&Path>) -> Result<(), anyhow::Error> {
    install_dependencies(os, &["upx"], priv_bin)
        .context("failed to install packaging dependencies")?;
    run_checked(
        Command::new("cargo").arg("install").arg("cargo-deb"),
        "install cargo-deb",
    )
    .context("failed to install cargo-deb")
}

fn generate_changelog() -> Result<(), anyhow::Error> {
    let changelog_path = "target/debian/changelog";
    if std::path::Path::new(changelog_path).exists() {
        return Ok(());
    }
    let binding = output_checked(
        Command::new("git").args(["tag", "--sort=-creatordate"]),
        "list git tags",
    )?;
    let mut ordered_tags = binding.stdout.lines();

    let from = ordered_tags
        .next()
        .ok_or_else(|| anyhow!("No git tag found for changelog generation"))??;

    let to = ordered_tags
        .next()
        .ok_or_else(|| anyhow!("At least two git tags are required for changelog generation"))??;

    debug!("Generating changelog from {from} to {to}");

    let changes = output_checked(
        Command::new("git").args(["log", "--pretty=format:  %s", &format!("{to}..{from}")]),
        "collect changelog entries",
    )?;
    debug!(
        "Changes: {}",
        String::from_utf8(changes.stdout.clone())
            .expect("Failed to convert git log output to string")
    );
    let changelog = format!(
        r"rootasrole ({version}) {dist}; urgency={urgency}
{changes}

 -- Eddie Billoir <lechatp@outlook.fr>  {date}
",
        version = env!("CARGO_PKG_VERSION"),
        dist = "unstable",
        urgency = "low",
        changes =
            String::from_utf8(changes.stdout).expect("Failed to convert git log output to string"),
        date = chrono::Local::now().format("%a, %d %b %Y %T %z")
    );
    File::create(changelog_path)?.write_all(changelog.as_bytes())?;

    Ok(())
}

pub fn make_deb(
    os: Option<&OsTarget>,
    profile: Profile,
    priv_bin: Option<&Path>,
) -> Result<(), anyhow::Error> {
    let os = get_os(os)?;
    let priv_bin = priv_bin.map(Path::to_path_buf).or_else(detect_priv_bin);
    dependencies(&os, priv_bin.as_deref())?;

    installer::dependencies(&InstallDependenciesOptions {
        os: Some(os),
        install_dependencies: true,
        dev: true,
        priv_bin: priv_bin.clone(),
    })?;
    installer::build(&installer::BuildOptions {
        profile,
        toolchain: installer::Toolchain::default(),
        clean_before: false,
        priv_bin,
    })?;
    setup_maint_scripts()?;
    generate_changelog()?;

    run_checked(
        Command::new("cargo").arg("deb").arg("--no-build"),
        "generate deb package",
    )?;
    Ok(())
}
