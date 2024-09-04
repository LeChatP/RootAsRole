mod install;
mod build;
mod uninstall;
mod configure;
mod util;
mod dependencies;

use std::collections::VecDeque;
use std::str::FromStr;

use chrono::{Datelike, NaiveDate, Utc};
use clap::{Parser, ValueEnum};
use semver::Version;
use strum::{Display, EnumIs, EnumIter, EnumString};

use crate::ebpf::{self, build::EbpfArchitecture};
use anyhow::anyhow;


pub const SR_DEST: &str = "/usr/bin/sr";
pub const CHSR_DEST: &str = "/usr/bin/chsr";
pub const CAPABLE_DEST: &str = "/usr/bin/capable";

/// Options for the install command

/// This command may use multiple toolchains.
/// By default `capable` use the nightly toolchain and `sr` and `chsr` use the stable toolchain.
/// `capable` eBPF requires nightly, but binaries like `sr` and `chsr` can be built at >=version 1.70.0.
/// Nightly toolchain are not recommended for production use, as they are not stable. So `capable` is for testing purposes.
/// Indeed, capable purpose is to obtain a set of Linux capabilities from a generic command, to help people to configure their RootAsRole configuration.
/// But if you don't want several toolchains installed, you can use the nightly toolchain for everything, or just not compile the eBPF program.
#[derive(Debug, Parser, Clone)]
pub struct InstallOptions {

    #[clap(flatten)]
    pub build : BuildOptions,

    /// The OS target for PAM configuration and dependencies installation (if -i is set)
    /// By default, it tries to autodetect it
    #[clap(long, short)]
    pub os: Option<OsTarget>,

    /// Do not build the binaries
    #[clap(long, short = 'n')]
    pub no_build: bool,

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

    /// Install dependencies before building
    #[clap(long, short = 'i')]
    pub install_dependencies: bool,
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
    /// Build the target with debug profile (default is release)
    #[clap(short = 'd', long = "debug", default_value_t = Profile::Release, default_missing_value = "debug", num_args = 0)]
    pub profile: Profile,

    /// The toolchain to use for building sr and chsr.
    #[clap(short, long, default_value = "stable")]
    pub toolchain: Toolchain,

    /// The eBPF architecture to build.
    /// Accepts no value (default is bpfel-unknown-none)
    #[clap(default_missing_value = "bpfel-unknown-none", long, short )]
    pub ebpf: Option<EbpfArchitecture>,

    /// Clean the target directory before building
    #[clap(long = "clean", short = 'b')]
    pub clean_before: bool,

}

#[derive(Debug, Clone, ValueEnum, EnumIs, EnumIter, Display)]
#[clap(rename_all = "lowercase")]
pub enum OsTarget {
    #[clap(alias = "deb")]
    Debian,
    #[clap(alias = "ubu")]
    Ubuntu,
    #[clap(alias = "rh")]
    RedHat,
    #[clap(alias = "fed")]
    Fedora,
    #[clap(alias = "cen")]
    CentOS,
    #[clap(alias = "arch")]
    ArchLinux,
}

impl OsTarget {
    pub fn detect() -> Result<Self, anyhow::Error> {
        for file in glob::glob("/etc/*-release")? {
            let file = file?;
            let os = std::fs::read_to_string(&file)?.to_ascii_lowercase();
            if os.contains("debian") {
                return Ok(OsTarget::Debian);
            } else if os.contains("ubuntu") {
                return Ok(OsTarget::Ubuntu);
            } else if os.contains("redhat") || os.contains("rhel") {
                return Ok(OsTarget::RedHat);
            } else if os.contains("fedora") {
                return Ok(OsTarget::Fedora);
            } else if os.contains("centos") {
                return Ok(OsTarget::CentOS);
            } else if os.contains("arch") {
                return Ok(OsTarget::ArchLinux);
            }
        }
        Err(anyhow!("Unsupported OS"))
    }
}

impl ToString for Toolchain {
    fn to_string(&self) -> String {
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
        s
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

impl ToString for Channel {
    fn to_string(&self) -> String {
        match self {
            Channel::Stable => "stable".to_string(),
            Channel::Beta => "beta".to_string(),
            Channel::Nightly => "nightly".to_string(),
            Channel::Version(version) => version.to_string(),
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
        if parts.len() < 1 {
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
        return Ok(Toolchain {
            channel,
            date,
            host: if host.is_empty() { None } else { Some(host) },
        });
    }
}

pub(crate) fn configure(os: Option<OsTarget>) -> Result<(), anyhow::Error> {
    configure::configure(os)
}

pub(crate) fn dependencies(opts: InstallDependenciesOptions) -> Result<(), anyhow::Error> {
    dependencies::install(opts)
}

pub(crate) fn install(opts: &InstallOptions) -> Result<(), anyhow::Error> {
    if opts.install_dependencies {
        dependencies(InstallDependenciesOptions {
            os: opts.os.clone(),
            install_dependencies: true,
        })?;
    }
    if ! opts.no_build {
        build(&opts.build)?;
    }
    if opts.build.ebpf.is_some() {
        let mut opts = opts.clone();
        opts.build.toolchain.channel = Channel::Nightly;
        ebpf::build_all(&opts.build)?;
    }
    install::install(&opts)?;
    configure(opts.os.clone())
}

pub(crate) fn build(opts: &BuildOptions) -> Result<(), anyhow::Error> {
    build::build(opts)
}

pub(crate) fn uninstall(opts : &UninstallOptions) -> Result<(), anyhow::Error> {
    uninstall::uninstall(opts)
}