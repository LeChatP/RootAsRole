use std::{fs, os::unix, process::Command};

use anyhow::Context;
use log::debug;

use crate::{installer::Toolchain, util::change_dir_to_git_root};

use super::BuildOptions;

fn build_binary(
    name: &str,
    options: &BuildOptions,
    additionnal_args: Vec<&str>,
) -> Result<(), anyhow::Error> {
    let toolchain = format!("+{}", options.toolchain);
    let mut args = if options.toolchain == Toolchain::default() {
        vec!["build", "--bin", name]
    } else {
        vec![&toolchain, "build", "--bin", name]
    };
    if options.profile.is_release() {
        args.push("--release");
    }
    args.extend(additionnal_args);
    debug!("Building {} binary with args: {:?}", name, args);
    Command::new("cargo").args(args).status()?;
    Ok(())
}

pub fn build(options: &BuildOptions) -> Result<(), anyhow::Error> {
    change_dir_to_git_root()?;
    if options.clean_before {
        Command::new("cargo")
            .arg("clean")
            .status()
            .expect("failed to clean");
    }
    build_binary("dosr", options, vec![])?;
    build_binary("chsr", options, vec!["--no-default-features"])?;

    build_manpages()?;

    Ok(())
}

fn build_manpages() -> Result<(), anyhow::Error> {
    debug!("Building manpages");
    let _ = fs::remove_dir_all("target/man/");
    fs::create_dir_all("target/man/")?;
    Command::new("pandoc")
        .args([
            "-s",
            "-t",
            "man",
            "resources/man/en_US.md",
            "-o",
            "target/man/dosr.8",
        ])
        .status()?;
    fs::create_dir_all("target/man/fr")?;
    Command::new("pandoc")
        .args([
            "-s",
            "-t",
            "man",
            "resources/man/fr_FR.md",
            "-o",
            "target/man/fr/dosr.8",
        ])
        .status()?;
    debug!("Compressing manpages");
    Command::new("gzip")
        .args(["target/man/dosr.8", "target/man/fr/dosr.8"])
        .status()?;
    debug!("Making symlinks");
    unix::fs::symlink("dosr.8.gz", "target/man/chsr.8.gz").context("Failed to create symlink")?;
    unix::fs::symlink("dosr.8.gz", "target/man/fr/chsr.8.gz")
        .context("Failed to create symlink")?;

    debug!("Manpages built");
    Ok(())
}
