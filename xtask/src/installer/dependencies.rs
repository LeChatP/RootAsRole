use std::process::ExitStatus;

use anyhow::Context;
use capctl::CapState;
use log::info;
use nix::unistd::geteuid;

use crate::{
    installer::OsTarget,
    util::{get_os, run_checked, status_checked},
};

use super::InstallDependenciesOptions;

fn update_package_manager(os: &OsTarget, priv_bin: Option<&String>) -> Result<(), anyhow::Error> {
    let mut command = Vec::new();
    if is_priv_bin_necessary(os)? {
        if let Some(priv_bin) = priv_bin {
            command.push(priv_bin.as_str());
        } else {
            return Err(anyhow::anyhow!("Privileged binary is required"));
        }
    }

    match os {
        OsTarget::Debian | OsTarget::Ubuntu => command.extend(&["apt-get", "update"]),
        OsTarget::RedHat => command.extend(&["yum", "update", "-y"]),
        OsTarget::Fedora => {
            command.extend(&["dnf", "update", "-y"]);
        }
        OsTarget::OpenSUSE => command.extend(&["zypper", "refresh"]),
        OsTarget::ArchLinux => command.extend(&["pacman", "-Syu"]),
    }
    run_checked(
        std::process::Command::new(command[0]).args(&command[1..]),
        "update package manager",
    )
    .context("Failed to update package manager")?;

    Ok(())
}

const fn required_dependencies(os: &OsTarget) -> &'static [&'static str] {
    match os {
        OsTarget::Debian | OsTarget::Ubuntu => &["libpam0g", "libpcre2-8-0", "libseccomp-dev"],
        OsTarget::RedHat => &["pcre2", "libseccomp"],
        OsTarget::OpenSUSE | OsTarget::ArchLinux | OsTarget::Fedora => {
            &["pam", "pcre2", "libseccomp"]
        }
    }
}

const fn development_dependencies(os: &OsTarget) -> &'static [&'static str] {
    match os {
        OsTarget::Debian | OsTarget::Ubuntu => &[
            "libpam0g-dev",
            "libpcre2-dev",
            "libclang-dev",
            "pandoc",
            "libseccomp-dev",
        ],
        OsTarget::RedHat | OsTarget::Fedora => &[
            "pcre2-devel",
            "clang-devel",
            "openssl-devel",
            "pam-devel",
            "pandoc",
            "libseccomp-devel",
        ],
        OsTarget::OpenSUSE => &[
            "pcre2-devel",
            "clang-devel",
            "libopenssl-devel",
            "pam-devel",
            "pandoc",
            "libseccomp-devel",
        ],
        OsTarget::ArchLinux => &["clang", "pkg-config", "pandoc", "libseccomp"],
    }
}

const fn get_dependencies(os: &OsTarget, dev: bool) -> &'static [&'static str] {
    if dev {
        development_dependencies(os)
    } else {
        required_dependencies(os)
    }
}

fn is_priv_bin_necessary(os: &OsTarget) -> Result<bool, anyhow::Error> {
    if os == &OsTarget::ArchLinux {
        Ok(!geteuid().is_root())
    } else {
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
}

pub fn install_dependencies(
    os: &OsTarget,
    deps: &[&str],
    priv_bin: Option<&String>,
) -> Result<ExitStatus, anyhow::Error> {
    let mut command = Vec::new();

    if is_priv_bin_necessary(os)? {
        if let Some(priv_bin) = &priv_bin {
            command.push(priv_bin.as_str());
        } else {
            return Err(anyhow::anyhow!("Privileged binary is required"));
        }
    }
    command.extend(match os {
        OsTarget::Debian | OsTarget::Ubuntu => ["apt-get", "install", "-y"],
        OsTarget::RedHat => ["yum", "install", "-y"],
        OsTarget::Fedora => ["dnf", "install", "-y"],
        OsTarget::OpenSUSE => ["zypper", "install", "-y"],
        OsTarget::ArchLinux => ["pacman", "-Syu", "--noconfirm"],
    });
    command.extend(deps);
    status_checked(
        std::process::Command::new(command[0]).args(&command[1..]),
        "install required packages",
    )
}

pub fn install(opts: &InstallDependenciesOptions) -> Result<(), anyhow::Error> {
    let os = get_os(opts.os.as_ref())?;
    update_package_manager(&os, opts.priv_bin.as_ref())?;
    // dependencies are : libpam and libpcre2
    info!("Installing dependencies: libpam.so and libpcre2.so for running the application");

    install_dependencies(&os, get_dependencies(&os, opts.dev), opts.priv_bin.as_ref())?;

    info!("Dependencies installed successfully");
    Ok(())
}
