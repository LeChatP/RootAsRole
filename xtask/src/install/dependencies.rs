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
        OsTarget::RedHat | OsTarget::Fedora | OsTarget::CentOS => {
            let _ = std::process::Command::new("yum")
                .arg("update")
                .arg("-y")
                .status()?;
        },
        OsTarget::ArchLinux => {},
    }

    Ok(())
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

    match os {
        OsTarget::Debian | OsTarget::Ubuntu => {
            let _ = std::process::Command::new("apt-get")
                .arg("install")
                .arg("-y")
                .arg("libpam0g")
                .arg("libpcre2-8-0")
                .status()?;
        },
        OsTarget::RedHat => {
            let _ = std::process::Command::new("yum")
                .arg("install")
                .arg("-y")
                .arg("pcre2")
                .status()?;
        },
        OsTarget::CentOS => {
            let _ = std::process::Command::new("yum")
                .arg("install")
                .arg("-y")
                .arg("pam")
                .arg("pcre2")
                .status()?;
        },
        OsTarget::Fedora => {
            let _ = std::process::Command::new("dnf")
                .arg("install")
                .arg("-y")
                .arg("pam")
                .arg("pcre2")
                .status()?;
        }
        OsTarget::ArchLinux => {
            let _ = std::process::Command::new("pacman")
                .arg("-Sy")
                .arg("--noconfirm")
                .arg("pam")
                .arg("pcre2")
                .status()?;
        },
    }

    println!("Dependencies installed successfully");
    Ok(())
}