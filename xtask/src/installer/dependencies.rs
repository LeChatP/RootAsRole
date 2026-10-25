//! The packages that `RootAsRole` needs to build and to run. xtask checks them and prints the
//! command that installs the missing ones, it does not install them: like Rust, they are left
//! to the administrator.

use std::{borrow::Cow, collections::HashMap, io, process::Command, sync::OnceLock};

use anyhow::{Context, anyhow};
use log::warn;
use serde::Deserialize;

use crate::{installer::OsTarget, util};

#[derive(Debug, Deserialize)]
struct DependenciesManifest<'a> {
    targets: HashMap<Cow<'a, str>, TargetDependencies<'a>>,
}

#[derive(Debug, Deserialize)]
struct TargetDependencies<'a> {
    #[serde(default)]
    aliases: Vec<Cow<'a, str>>,
    /// How the installed packages are found
    query: PackageQuery,
    /// The command that installs packages, printed for the administrator, never run
    install: Vec<Cow<'a, str>>,
    runtime: Vec<Cow<'a, str>>,
    development: Vec<Cow<'a, str>>,
}

/// How a distribution tells whether a package is installed. The queries change nothing.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum PackageQuery {
    Dpkg,
    Rpm,
    Pacman,
}

impl PackageQuery {
    fn is_installed(self, package: &str) -> io::Result<bool> {
        let output = match self {
            // one line for each architecture of a multiarch package
            Self::Dpkg => Command::new("dpkg-query")
                .args(["-W", "-f=${db:Status-Status}\\n", package])
                .output()?,
            // a capability as well as a package name: pkgconf-pkg-config provides pkgconfig
            Self::Rpm => Command::new("rpm")
                .args(["-q", "--quiet", "--whatprovides", package])
                .output()?,
            // a package that another one provides is satisfied too: pkgconf provides pkg-config
            Self::Pacman => Command::new("pacman").args(["-T", package]).output()?,
        };
        // a removed package keeps its configuration files: dpkg-query finds it, not installed
        Ok(output.status.success()
            && (self != Self::Dpkg
                || output
                    .stdout
                    .split(|&byte| byte == b'\n')
                    .any(|line| line == b"installed")))
    }
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

fn os_from_identifier(manifest: &DependenciesManifest<'_>, identifier: &str) -> Option<OsTarget> {
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

/// The packages that `os` needs to build `RootAsRole` (`build`), or to run it, and that are not
/// installed.
///
/// # Errors
/// When the OS is not in the manifest, or its package database cannot be queried.
pub fn missing_packages(os: &OsTarget, build: bool) -> Result<Vec<String>, anyhow::Error> {
    let target = resolve_target(dependencies_manifest()?, os)?;
    let packages = if build {
        &target.development
    } else {
        &target.runtime
    };
    let mut missing = Vec::new();
    for package in packages {
        if !target
            .query
            .is_installed(package)
            .with_context(|| format!("Cannot query the packages of {os}"))?
        {
            missing.push(package.to_string());
        }
    }
    Ok(missing)
}

/// The command that installs `packages` on `os`, to print for the administrator.
///
/// # Errors
/// When the OS is not in the manifest.
pub fn install_command(os: &OsTarget, packages: &[String]) -> Result<String, anyhow::Error> {
    let target = resolve_target(dependencies_manifest()?, os)?;
    Ok(target
        .install
        .iter()
        .map(AsRef::as_ref)
        .chain(packages.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" "))
}

/// The `missing` packages to build `RootAsRole` (`build`), or to run it, with the command that
/// installs them.
///
/// # Errors
/// When the OS is not in the manifest.
pub fn missing_message(
    os: &OsTarget,
    build: bool,
    missing: &[String],
) -> Result<String, anyhow::Error> {
    Ok(format!(
        "Missing packages to {} RootAsRole on {os}: {}. Install them, as root: {}",
        if build { "build" } else { "run" },
        missing.join(" "),
        install_command(os, missing)?
    ))
}

/// What to do with the `missing` packages: stop with the command that installs them, or only
/// warn in a dry run.
fn report_missing(os: &OsTarget, build: bool, missing: &[String]) -> Result<(), anyhow::Error> {
    if missing.is_empty() {
        return Ok(());
    }
    let message = missing_message(os, build, missing)?;
    if util::is_dry_run() {
        warn!("{message}");
        Ok(())
    } else {
        Err(anyhow!(message))
    }
}

/// Check the packages that `os` needs to build `RootAsRole` (`build`), or to run it. A system
/// whose packages cannot be queried is only warned about: the build tells then.
///
/// # Errors
/// When packages are missing, with the command that installs them.
pub fn check(os: &OsTarget, build: bool) -> Result<(), anyhow::Error> {
    match missing_packages(os, build) {
        Ok(missing) => report_missing(os, build, &missing),
        Err(e) => {
            warn!("The packages of {os} cannot be checked: {e:#}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{DRY_RUN_TEST_LOCK, set_dry_run};

    #[test]
    fn test_every_target_has_its_packages() {
        let manifest = dependencies_manifest().unwrap();
        for os in [
            OsTarget::Debian,
            OsTarget::Ubuntu,
            OsTarget::RedHat,
            OsTarget::Fedora,
            OsTarget::OpenSUSE,
            OsTarget::ArchLinux,
        ] {
            let target = resolve_target(manifest, &os).unwrap();
            assert!(!target.install.is_empty(), "{os}");
            assert!(!target.runtime.is_empty(), "{os}");
            assert!(!target.development.is_empty(), "{os}");
        }
        assert_eq!(
            install_command(&OsTarget::Debian, &["clang".into(), "pandoc".into()]).unwrap(),
            "apt-get install clang pandoc"
        );
    }

    #[test]
    fn test_a_package_that_does_not_exist_is_missing() {
        for query in [PackageQuery::Dpkg, PackageQuery::Rpm, PackageQuery::Pacman] {
            match query.is_installed("rar-no-such-package") {
                Ok(installed) => assert!(!installed, "{query:?}"),
                // not the package manager of this system
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound, "{query:?}"),
            }
        }
    }

    #[test]
    fn test_the_package_manager_of_this_system_is_installed() {
        // the query of another system may be installed as a tool, without a package database
        let Ok(os) = util::get_os(None) else {
            return;
        };
        let target = resolve_target(dependencies_manifest().unwrap(), &os).unwrap();
        let itself = match target.query {
            PackageQuery::Dpkg => "dpkg",
            PackageQuery::Rpm => "rpm",
            PackageQuery::Pacman => "pacman",
        };
        assert!(target.query.is_installed(itself).unwrap(), "{os}");
    }

    #[test]
    fn test_missing_packages_stop_unless_dry_run() {
        let _guard = DRY_RUN_TEST_LOCK.lock().unwrap();
        let missing = ["pandoc".to_string()];
        set_dry_run(false);
        let error = report_missing(&OsTarget::Debian, true, &missing)
            .unwrap_err()
            .to_string();
        assert!(error.contains("apt-get install pandoc"), "{error}");
        assert!(report_missing(&OsTarget::Debian, true, &[]).is_ok());
        set_dry_run(true);
        assert!(report_missing(&OsTarget::Debian, true, &missing).is_ok());
        set_dry_run(false);
    }
}
