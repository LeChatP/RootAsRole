use std::{fs, process::Command};

use log::{debug, warn};

use crate::{
    installer::Toolchain,
    util::{change_dir_to_project_root, command_exists, run_checked},
};

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
    debug!("Building {name} binary with args: {args:?}");
    run_checked(
        Command::new("cargo").args(args),
        &format!("build {name} binary"),
    )?;
    Ok(())
}

pub fn build(options: &BuildOptions) -> Result<(), anyhow::Error> {
    change_dir_to_project_root()?;
    if options.clean_before {
        run_checked(Command::new("cargo").arg("clean"), "clean build artifacts")?;
    }
    build_binary("dosr", options, vec!["--features", "finder"])?;
    build_binary("chsr", options, vec!["--features", "editor"])?;

    build_manpages()?;

    Ok(())
}

/// The manual pages need pandoc and gzip: without them, they are left out, and the installation
/// installs none.
fn build_manpages() -> Result<(), anyhow::Error> {
    debug!("Building manpages");
    // the pages of a former build are never installed instead of these ones
    let _ = fs::remove_dir_all("target/man/");
    if let Some(command) = ["pandoc", "gzip"]
        .into_iter()
        .find(|command| !command_exists(command))
    {
        warn!("{command} is not installed: the manual pages are not built");
        return Ok(());
    }
    fs::create_dir_all("target/man/")?;
    run_checked(
        Command::new("pandoc").args([
            "-s",
            "-t",
            "man",
            "resources/man/en_US.md",
            "-o",
            "target/man/dosr.8",
        ]),
        "generate English manpage",
    )?;
    fs::create_dir_all("target/man/fr")?;
    run_checked(
        Command::new("pandoc").args([
            "-s",
            "-t",
            "man",
            "resources/man/fr_FR.md",
            "-o",
            "target/man/fr/dosr.8",
        ]),
        "generate French manpage",
    )?;
    debug!("Compressing manpages");
    run_checked(
        Command::new("gzip").args(["target/man/dosr.8", "target/man/fr/dosr.8"]),
        "compress manpages",
    )?;
    debug!("Manpages built");
    Ok(())
}
