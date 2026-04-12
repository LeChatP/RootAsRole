mod build;
pub mod dependencies;
pub mod install;
mod uninstall;

use std::fmt::Write;
use std::str::FromStr;
use std::{collections::VecDeque, fmt::Display};

use chrono::{Datelike, NaiveDate, Utc};
use clap::{Parser, ValueEnum};
use semver::Version;
use strum::{Display, EnumIs, EnumString};

use anyhow::anyhow;
use log::debug;

use crate::{
    configure,
    util::{OsTarget, detect_priv_bin, get_os, is_dry_run},
};
pub const RAR_BIN_PATH: &str = env!("RAR_BIN_PATH");
pub const SR_DEST: &str = "dosr";
pub const CHSR_DEST: &str = "chsr";

#[derive(Debug, Parser, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct InstallOptions {
    #[clap(flatten)]
    pub build_opts: BuildOptions,

    /// Hidden flag used internally when install re-executes itself through a privilege escalator
    #[clap(long, hide = true)]
    pub nested_install: bool,

    /// The OS target for PAM configuration and dependencies installation (if -i is set)
    /// By default, it tries to autodetect it
    #[clap(long, short)]
    pub os: Option<OsTarget>,

    /// Build the binaries
    #[clap(long, short = 'b')]
    pub build: bool,

    /// Install dependencies before building
    #[clap(long, short = 'i')]
    pub install_dependencies: bool,

    /// Clean the target directory after installing
    #[clap(long, short = 'a')]
    pub clean_after: bool,
}

#[derive(Debug, Parser)]
pub struct InstallDependenciesOptions {
    /// The OS target for PAM configuration and dependencies installation (if -i is set)
    /// By default, it tries to autodetect it
    #[clap(long, short)]
    pub os: Option<OsTarget>,

    /// Install dependencies before installing
    #[clap(long, short = 'i')]
    pub install_dependencies: bool,

    /// Install development dependencies for compiling
    #[clap(long, short = 'd')]
    pub dev: bool,

    /// The binary to elevate privileges
    #[clap(long, short = 'p', visible_alias = "privbin")]
    pub priv_bin: Option<String>,
}

#[derive(Debug, Parser)]
pub struct UninstallOptions {
    /// Delete all configuration files
    #[clap(long, short = 'c')]
    pub clean_config: bool,

    /// Apply filesystem changes (required)
    #[clap(long)]
    pub apply: bool,

    pub kind: UninstallKind,
}

#[derive(Clone, Debug, ValueEnum, EnumIs, EnumString, Display)]
#[strum(serialize_all = "lowercase")]
pub enum UninstallKind {
    All,
    Sr,
    Capable,
}

#[derive(Debug, Copy, Clone, EnumIs, EnumString, Display)]
#[strum(serialize_all = "lowercase")]
pub enum Profile {
    Release,
    Debug,
}

#[derive(Debug, Parser, Clone)]
pub struct BuildOptions {
    /// The binary to elevate privileges
    #[clap(long, short = 'p', visible_alias = "privbin")]
    pub priv_bin: Option<String>,

    /// Build the target with debug profile (default is release)
    #[clap(short = 'd', long = "debug", default_value_t = Profile::Release, default_missing_value = "debug", num_args = 0)]
    pub profile: Profile,

    /// The toolchain to use for building sr and chsr.
    #[clap(short, long, default_value = "stable")]
    pub toolchain: Toolchain,

    /// Clean the target directory before building
    #[clap(long = "clean")]
    pub clean_before: bool,
}

impl Display for Toolchain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = self.channel.to_string();
        if let Some(ref date) = self.date {
            let _ = write!(
                s,
                "-{:04}-{:02}-{:02}",
                date.year(),
                date.month(),
                date.day()
            );
        }
        if let Some(ref host) = self.host {
            let _ = write!(s, "-{host}");
        }
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain {
    pub channel: Channel,
    pub date: Option<NaiveDate>,
    pub host: Option<String>,
}

impl Default for Toolchain {
    fn default() -> Self {
        Self {
            channel: Channel::Stable,
            date: None,
            host: None,
        }
    }
}

#[derive(Debug, Clone, EnumIs, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Beta,
    Nightly,
    Version(Version),
}

impl Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stable => write!(f, "stable"),
            Self::Beta => write!(f, "beta"),
            Self::Nightly => write!(f, "nightly"),
            Self::Version(v) => write!(f, "{v}"),
        }
    }
}

impl FromStr for Channel {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, anyhow::Error> {
        match s.to_lowercase().as_str() {
            "stable" => Ok(Self::Stable),
            "beta" => Ok(Self::Beta),
            "nightly" => Ok(Self::Nightly),
            version => {
                let version = Version::parse(version)?;
                Ok(Self::Version(version))
            }
        }
    }
}

fn parse_date(y: &str, m: &str, d: &str) -> Result<NaiveDate, anyhow::Error> {
    let y = y.parse::<i32>()?;
    let m = m.parse::<u32>()?;
    let d = d.parse::<u32>()?;
    let date = NaiveDate::from_ymd_opt(y, m, d).ok_or_else(|| anyhow!("Invalid date"))?;
    if date > Utc::now().naive_utc().into() {
        return Err(anyhow!("Invalid date"));
    }
    Ok(date)
}

impl FromStr for Toolchain {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, anyhow::Error> {
        let mut parts: VecDeque<&str> = s.split('-').collect();
        if parts.is_empty() {
            return Ok(Self::default());
        }
        let channel = parts
            .pop_front()
            .expect("Failed to get channel part from toolchain string")
            .to_lowercase()
            .as_str()
            .parse::<Channel>()?;
        let mut date = None;
        if parts.len() >= 3 {
            date = parse_date(parts[0], parts[1], parts[2]).ok();
            if date.is_some() {
                parts.pop_front();
                parts.pop_front();
                parts.pop_front();
            }
        }

        let host = parts
            .iter()
            .fold(String::new(), |acc, x| format!("{acc}-{x}"));
        Ok(Self {
            channel,
            date,
            host: if host.is_empty() { None } else { Some(host) },
        })
    }
}

pub fn configure(os: Option<OsTarget>) -> Result<(), anyhow::Error> {
    if is_dry_run() {
        debug!("Dry-run mode: skipping configure changes");
        return Ok(());
    }
    configure::configure(os)
}

pub fn dependencies(opts: &InstallDependenciesOptions) -> Result<(), anyhow::Error> {
    if is_dry_run() {
        debug!("Dry-run mode: skipping dependencies installation");
        return Ok(());
    }
    dependencies::install(opts)
}

pub fn install(opts: &InstallOptions) -> Result<(), anyhow::Error> {
    if is_dry_run() {
        debug!("Dry-run mode: skipping install changes");
        return Ok(());
    }
    if opts.nested_install {
        unsafe { std::env::set_var("ROOTASROLE_INSTALLER_NESTED", "1") };
    } else {
        unsafe { std::env::remove_var("ROOTASROLE_INSTALLER_NESTED") };
    }
    let os = get_os(opts.os.as_ref())?;
    let priv_bin = opts.build_opts.priv_bin.clone().or_else(detect_priv_bin);
    if opts.install_dependencies {
        debug!("Installing dependencies");
        dependencies(&InstallDependenciesOptions {
            os: Some(os.clone()),
            install_dependencies: true,
            dev: opts.build,
            priv_bin: priv_bin.clone(),
        })?;
    }
    if opts.build {
        debug!("Building sr and chsr");
        build(&opts.build_opts)?;
    }
    if install::install(
        priv_bin.as_ref(),
        opts.build_opts.profile,
        opts.clean_after,
        true,
    )?
    .is_yes()
    {
        Ok(())
    } else {
        configure(Some(os))
    }
}

pub fn build(opts: &BuildOptions) -> Result<(), anyhow::Error> {
    build::build(opts)
}

pub fn uninstall(opts: &UninstallOptions) -> Result<(), anyhow::Error> {
    if is_dry_run() {
        debug!("Dry-run mode: skipping uninstall changes");
        return Ok(());
    }
    uninstall::uninstall(opts)
}
