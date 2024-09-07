use std::process::ExitStatus;

use anyhow::Context;

use crate::install::OsTarget;

use super::InstallDependenciesOptions;

fn update_package_manager() -> Result<(), anyhow::Error> {
    let os = OsTarget::detect()?;

    match os {
        OsTarget::Debian | OsTarget::Ubuntu => {
            let _ = std::process::Command::new("apt-get")
                .arg("update")
                .status()?;
        },
        OsTarget::RedHat | OsTarget::Fedora => {
            let _ = std::process::Command::new("yum")
                .arg("update")
                .arg("-y")
                .status()?;
        },
        OsTarget::ArchLinux => {},
    }

    Ok(())
}

fn required_dependencies(os: &OsTarget) -> &'static [&'static str] {
    match os {
        OsTarget::Debian | OsTarget::Ubuntu => &["libpam0g", "libpcre2-8-0"],
        OsTarget::RedHat => &["pcre2"],
        OsTarget::ArchLinux | OsTarget::Fedora => &["pam", "pcre2"],
    }
}

fn development_dependencies(os: &OsTarget) -> &'static [&'static str] {
    match os {
        OsTarget::Debian | OsTarget::Ubuntu => &["libpam0g-dev", "libpcre2-dev"],
        OsTarget::RedHat => &["pcre2-devel", "clang-devel", "openssl-devel", "pam-devel"],
        OsTarget::Fedora => &["clang-devel", "openssl-devel", "pam-devel"],
        OsTarget::ArchLinux => &["clang", "pkg-config"],
    }
}

fn get_dependencies(os: &OsTarget, dev: &bool) -> &'static [&'static str] {
    if *dev {
        development_dependencies(os)
    } else {
        required_dependencies(os)
    }
}

pub fn install_dependencies(os: &OsTarget, deps:&[&str]) -> Result<ExitStatus,std::io::Error> {
    match os {
        OsTarget::Debian | OsTarget::Ubuntu => {
            std::process::Command::new("apt-get")
                .arg("install")
                .arg("-y")
                .args(deps)
                .status()
        },
        OsTarget::RedHat => {
            std::process::Command::new("yum")
                .arg("install")
                .arg("-y")
                .args(deps)
                .status()
        },
        OsTarget::Fedora => {
            std::process::Command::new("dnf")
                .arg("install")
                .arg("-y")
                .args(deps)
                .status()
        }
        OsTarget::ArchLinux => {
            std::process::Command::new("pacman")
                .arg("-Syu")
                .arg("--noconfirm")
                .args(deps)
                .status()
        },
    }
}

pub fn install(opts: InstallDependenciesOptions) -> Result<(), anyhow::Error> {
    update_package_manager()?;
    // dependencies are : libpam and libpcre2
    println!("Installing dependencies: libpam.so and libpcre2.so for running the application");

    let os = if let Some(os) = opts.os {
        os
    } else {
        OsTarget::detect()
            .and_then(|t| {
                println!("Detected OS is : {}", t);
                Ok(t)
            })
            .context("Failed to detect the OS")?
    };
    install_dependencies(&os, get_dependencies(&os, &opts.dev))?;

    println!("Dependencies installed successfully");
    Ok(())
}