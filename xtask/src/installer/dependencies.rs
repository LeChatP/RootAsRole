use std::{borrow::Cow, collections::HashMap, process::ExitStatus, sync::OnceLock};

use anyhow::Context;
use capctl::CapState;
use log::info;
use nix::unistd::geteuid;
use serde::Deserialize;

use crate::{
    installer::OsTarget,
    util::{get_os, run_checked, status_checked},
};

use super::InstallDependenciesOptions;

#[derive(Debug, Deserialize)]
struct DependenciesManifest<'a> {
    targets: HashMap<Cow<'a, str>, TargetDependencies<'a>>,
}

#[derive(Debug, Deserialize)]
struct TargetDependencies<'a> {
    #[serde(default)]
    aliases: Vec<Cow<'a, str>>,
    package_manager: PackageManager<'a>,
    runtime: Vec<Cow<'a, str>>,
    development: Vec<Cow<'a, str>>,
}

#[derive(Debug, Deserialize)]
struct PackageManager<'a> {
    refresh: Vec<Cow<'a, str>>,
    install: Vec<Cow<'a, str>>,
}

fn dependencies_manifest() -> Result<&'static DependenciesManifest<'static>, anyhow::Error> {
    static MANIFEST: OnceLock<Result<DependenciesManifest<'static>, String>> = OnceLock::new();
    let manifest = MANIFEST.get_or_init(|| {
        serde_json::from_str(include_str!("deps.json"))
            .context("Failed to parse installer dependency manifest")
            .map_err(|e| e.to_string())
    });
    match manifest {
        Ok(manifest) => Ok(manifest),
        Err(e) => Err(anyhow::anyhow!(e.clone())),
    }
}

const fn os_key(os: &OsTarget) -> &'static str {
    match os {
        OsTarget::Debian => "debian",
        OsTarget::Ubuntu => "ubuntu",
        OsTarget::RedHat => "redhat",
        OsTarget::Fedora => "fedora",
        OsTarget::OpenSUSE => "opensuse",
        OsTarget::ArchLinux => "archlinux",
    }
}

fn os_from_key(key: &str) -> Option<OsTarget> {
    match key {
        "debian" => Some(OsTarget::Debian),
        "ubuntu" => Some(OsTarget::Ubuntu),
        "redhat" => Some(OsTarget::RedHat),
        "fedora" => Some(OsTarget::Fedora),
        "opensuse" => Some(OsTarget::OpenSUSE),
        "archlinux" => Some(OsTarget::ArchLinux),
        _ => None,
    }
}

fn os_from_identifier(
    manifest: &DependenciesManifest<'_>,
    identifier: &str,
) -> Option<OsTarget> {
    let identifier = identifier.trim().to_ascii_lowercase();
    if let Some(target) = os_from_key(&identifier)
        && manifest.targets.contains_key(identifier.as_str())
    {
        return Some(target);
    }

    manifest.targets.iter().find_map(|(key, target)| {
        if target
            .aliases
            .iter()
            .any(|alias| alias.as_ref() == identifier.as_str())
        {
            os_from_key(key.as_ref())
        } else {
            None
        }
    })
}

pub fn os_target_from_identifiers<'a, I>(identifiers: I) -> Result<Option<OsTarget>, anyhow::Error>
where
    I: IntoIterator<Item = &'a str>,
{
    let manifest = dependencies_manifest()?;
    for id in identifiers {
        if let Some(target) = os_from_identifier(manifest, id) {
            return Ok(Some(target));
        }
    }
    Ok(None)
}

fn resolve_target<'a>(
    manifest: &'a DependenciesManifest<'a>,
    os: &OsTarget,
) -> Result<&'a TargetDependencies<'a>, anyhow::Error> {
    let key = os_key(os);
    if let Some(target) = manifest.targets.get(key) {
        return Ok(target);
    }

    manifest
        .targets
        .values()
        .find(|target| target.aliases.iter().any(|alias| alias.as_ref() == key))
        .ok_or_else(|| anyhow::anyhow!("Unsupported OS target in deps.json: {key}"))
}

fn compose_command(
    priv_bin: Option<&String>,
    base: &[Cow<'_, str>],
) -> Result<Vec<String>, anyhow::Error> {
    if base.is_empty() {
        return Err(anyhow::anyhow!("Invalid package-manager command in deps.json"));
    }

    let mut command = Vec::new();
    if is_priv_bin_necessary()? {
        if let Some(priv_bin) = priv_bin {
            if is_su_command(priv_bin) {
                let shell_command = base
                    .iter()
                    .map(|arg| shell_quote(arg.as_ref()))
                    .collect::<Vec<String>>()
                    .join(" ");
                command.push(priv_bin.clone());
                command.push("-c".to_string());
                command.push(shell_command);
                return Ok(command);
            }
            command.push(priv_bin.clone());
        } else {
            return Err(anyhow::anyhow!("Privileged binary is required"));
        }
    }
    command.extend(base.iter().map(|s| s.as_ref().to_string()));
    Ok(command)
}

fn is_su_command(priv_bin: &str) -> bool {
    std::path::Path::new(priv_bin)
        .file_name()
        .is_some_and(|name| name == "su")
}

fn shell_quote(arg: &str) -> String {
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "@%_+=:,./-".contains(c))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

fn update_package_manager(os: &OsTarget, priv_bin: Option<&String>) -> Result<(), anyhow::Error> {
    let manifest = dependencies_manifest()?;
    let target = resolve_target(manifest, os)?;
    let command = compose_command(priv_bin, target.package_manager.refresh.as_slice())?;
    log::info!("Updating package manager with command: {}", command.join(" "));
    run_checked(
        std::process::Command::new(&command[0]).args(&command[1..]),
        "update package manager",
    )
    .context("Failed to update package manager")?;

    Ok(())
}

fn get_dependencies<'a>(
    manifest: &'a DependenciesManifest<'a>,
    os: &OsTarget,
    dev: bool,
) -> Result<&'a [Cow<'a, str>], anyhow::Error> {
    let target = resolve_target(manifest, os)?;
    if dev {
        Ok(target.development.as_slice())
    } else {
        Ok(target.runtime.as_slice())
    }
}

fn is_priv_bin_necessary() -> Result<bool, anyhow::Error> {
    if geteuid().is_root() { // as long root own files/folders, it should not need capabilities.
        return Ok(false);
    }
    let mut state = CapState::get_current()?;
    if state.permitted.has(capctl::Cap::DAC_OVERRIDE)
        && !state.effective.has(capctl::Cap::DAC_OVERRIDE)
    {
        state.effective.add(capctl::Cap::DAC_OVERRIDE);
        state.set_current()?;
        Ok(false)
    } else {
        Ok(true)
    }
}

pub fn install_dependencies(
    os: &OsTarget,
    deps: &[&str],
    priv_bin: Option<&String>,
) -> Result<ExitStatus, anyhow::Error> {
    let manifest = dependencies_manifest()?;
    let target = resolve_target(manifest, os)?;

    let mut command = compose_command(priv_bin, target.package_manager.install.as_slice())?;
    command.extend(deps.iter().map(std::string::ToString::to_string));

    status_checked(
        std::process::Command::new(&command[0]).args(&command[1..]),
        "install required packages",
    )
}

pub fn install(opts: &InstallDependenciesOptions) -> Result<(), anyhow::Error> {
    let os = get_os(opts.os.as_ref())?;
    update_package_manager(&os, opts.priv_bin.as_ref())?;
    // dependencies are : libpam and libpcre2
    info!("Installing dependencies: libpam.so and libpcre2.so for running the application");

    let manifest = dependencies_manifest()?;
    let deps = get_dependencies(manifest, &os, opts.dev)?;
    let deps: Vec<&str> = deps.iter().map(std::convert::AsRef::as_ref).collect();
    install_dependencies(&os, &deps, opts.priv_bin.as_ref())?;

    info!("Dependencies installed successfully");
    Ok(())
}
