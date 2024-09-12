mod build;
pub(crate) mod dependencies;
pub(crate) mod install;
mod uninstall;

use std::str::FromStr;
use std::{collections::VecDeque, fmt::Display};

use chrono::{Datelike, NaiveDate, Utc};
use clap::{Parser, ValueEnum};
use semver::Version;
use strum::{Display, EnumIs, EnumString};

use anyhow::anyhow;
use tracing::debug;

use crate::{
    configure,
    util::{detect_priv_bin, get_os, OsTarget},
};

pub const SR_DEST: &str = "/usr/bin/sr";
pub const CHSR_DEST: &str = "/usr/bin/chsr";

#[derive(Debug, Parser, Clone)]
pub struct InstallOptions {
    #[clap(flatten)]
    pub build_opts: BuildOptions,

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

    /// The binary to elevate privileges
    #[clap(long, short = 'p')]
    pub priv_bin: Option<String>,
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
    #[clap(long, short = 'p')]
    pub priv_bin: Option<String>,
}

#[derive(Debug, Parser)]
pub struct UninstallOptions {
    /// Delete all configuration files
    #[clap(long, short = 'c')]
    pub clean_config: bool,

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
    pub privbin: Option<String>,

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
            s.push_str(&format!(
                "-{:04}-{:02}-{:02}",
                date.year(),
                date.month(),
                date.day()
            ));
        }
        if let Some(ref host) = self.host {
            s.push_str(&format!("-{}", host));
        }
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone)]
pub struct Toolchain {
    pub channel: Channel,
    pub date: Option<NaiveDate>,
    pub host: Option<String>,
}

impl Default for Toolchain {
    fn default() -> Self {
        Toolchain {
            channel: Channel::Stable,
            date: None,
            host: None,
        }
    }
}

#[derive(Debug, Clone, EnumIs)]
pub enum Channel {
    Stable,
    Beta,
    Nightly,
    Version(Version),
}

impl Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Channel::Stable => write!(f, "stable"),
            Channel::Beta => write!(f, "beta"),
            Channel::Nightly => write!(f, "nightly"),
            Channel::Version(v) => write!(f, "{}", v),
        }
    }
}

impl FromStr for Channel {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, anyhow::Error> {
        match s.to_lowercase().as_str() {
            "stable" => Ok(Channel::Stable),
            "beta" => Ok(Channel::Beta),
            "nightly" => Ok(Channel::Nightly),
            version => {
                let version = Version::parse(version)?;
                Ok(Channel::Version(version))
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
            return Ok(Toolchain::default());
        }
        let channel = parts
            .pop_front()
            .unwrap()
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
            .fold(String::new(), |acc, x| format!("{}-{}", acc, x));
        Ok(Toolchain {
            channel,
            date,
            host: if host.is_empty() { None } else { Some(host) },
        })
    }
}

pub(crate) fn configure(os: Option<OsTarget>) -> Result<(), anyhow::Error> {
    configure::configure(os)
}

pub(crate) fn dependencies(opts: InstallDependenciesOptions) -> Result<(), anyhow::Error> {
    dependencies::install(opts)
}

pub(crate) fn install(opts: &InstallOptions) -> Result<(), anyhow::Error> {
    let os = get_os(opts.os.clone())?;
    if opts.install_dependencies {
        debug!("Installing dependencies");
        dependencies(InstallDependenciesOptions {
            os: Some(os.clone()),
            install_dependencies: true,
            dev: opts.build,
            priv_bin: opts.build_opts.privbin.clone().or(detect_priv_bin()),
        })?;
    }
    if opts.build {
        debug!("Building sr and chsr");
        build(&opts.build_opts)?;
    }
    if install::install(
        &opts.priv_bin,
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

pub(crate) fn build(opts: &BuildOptions) -> Result<(), anyhow::Error> {
    build::build(opts)
}

pub(crate) fn uninstall(opts: &UninstallOptions) -> Result<(), anyhow::Error> {
    uninstall::uninstall(opts)
}
