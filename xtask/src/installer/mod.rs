mod build;
pub mod dependencies;
pub mod install;
mod uninstall;

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{collections::VecDeque, fmt::Display};

use clap::{Parser, ValueEnum};
use jiff::Zoned;
use jiff::civil::Date;
use semver::Version;

use anyhow::anyhow;
use capctl::{Cap, CapState};
use log::{debug, info};

use crate::util::path_exe_from_env;
use crate::{
    configure,
    util::{
        OsTarget, PAM_CONFIG_SERVICE, RAR_CFG_DATA_PATH, RAR_CFG_PATH, detect_priv_bin, get_os,
        is_dry_run,
    },
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
    pub priv_bin: Option<PathBuf>,
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

#[derive(Clone, Debug, ValueEnum)]
pub enum UninstallKind {
    All,
    Sr,
    Capable,
}

impl UninstallKind {
    #[must_use]
    pub const fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    #[must_use]
    pub const fn is_sr(&self) -> bool {
        matches!(self, Self::Sr)
    }

    #[must_use]
    pub const fn is_capable(&self) -> bool {
        matches!(self, Self::Capable)
    }
}

#[derive(Debug, Copy, Clone, ValueEnum)]
pub enum Profile {
    Release,
    Debug,
}

impl Profile {
    #[must_use]
    pub const fn is_release(self) -> bool {
        matches!(self, Self::Release)
    }

    #[must_use]
    pub const fn is_debug(self) -> bool {
        matches!(self, Self::Debug)
    }
}

impl Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Release => write!(f, "release"),
            Self::Debug => write!(f, "debug"),
        }
    }
}

#[derive(Debug, Parser, Clone)]
pub struct BuildOptions {
    /// The binary to elevate privileges
    #[clap(long, short = 'p', visible_alias = "privbin")]
    pub priv_bin: Option<PathBuf>,

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
    pub date: Option<Date>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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

fn parse_date(y: &str, m: &str, d: &str) -> Result<Date, anyhow::Error> {
    // jiff::civil::Date::new expects (i16, i8, i8)
    let y = y.parse::<i16>()?;
    let m = m.parse::<i8>()?;
    let d = d.parse::<i8>()?;

    let date = Date::new(y, m, d).map_err(|e| anyhow!("Invalid date: {e}"))?;

    // Compare against today's date in UTC (or local using Zoned::now().date())
    let today_utc = Zoned::now().with_time_zone(jiff::tz::TimeZone::UTC).date();
    if date > today_utc {
        return Err(anyhow!("Date cannot be in the future"));
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

/// What `configure` would change, for a dry run.
fn configure_plan() -> Vec<String> {
    vec![
        format!("deploy /etc/pam.d/{PAM_CONFIG_SERVICE} if it is missing or empty"),
        format!(
            "deploy the policy, {RAR_CFG_PATH} and {RAR_CFG_DATA_PATH}, if missing, immutable when the file system allows it, then run chsr upgrade"
        ),
    ]
}

fn print_plan(what: &str, plan: &[String]) {
    info!("Dry run, nothing is changed: {what} would");
    for step in plan {
        info!("  - {step}");
    }
}

pub fn configure(os: Option<OsTarget>) -> Result<(), anyhow::Error> {
    if is_dry_run() {
        print_plan("configure", &configure_plan());
        return Ok(());
    }
    configure::configure(os)
}

/// In a dry run, the commands of the package manager are printed, not run (`run_checked`).
pub fn dependencies(opts: &InstallDependenciesOptions) -> Result<(), anyhow::Error> {
    dependencies::install(opts)
}

/// What the privileged part of `install` would change, for a dry run: these steps change the
/// system without a command that a dry run could print.
fn install_plan(opts: &InstallOptions, priv_bin: Option<&Path>) -> Vec<String> {
    let mut plan = Vec::new();
    let privileged = CapState::get_current().is_ok_and(|state| {
        [Cap::DAC_OVERRIDE, Cap::CHOWN, Cap::SETFCAP]
            .into_iter()
            .all(|cap| state.permitted.has(cap))
    });
    if !privileged {
        let exe = std::env::current_exe()
            .map_or_else(|_| "xtask".into(), |exe| exe.display().to_string());
        plan.push(
            priv_bin
                .map(Path::to_path_buf)
                .or_else(detect_priv_bin)
                .map_or_else(
                    || "stop: no privilege escalation (dosr, sudo, doas, please) was found".into(),
                    |priv_bin| {
                        format!(
                            "run {} {exe} install --nested-install, to do the rest with privileges",
                            priv_bin.display()
                        )
                    },
                ),
        );
    }
    let profile = opts.build_opts.profile;
    plan.push(format!(
        "copy target/{profile}/{SR_DEST} and target/{profile}/{CHSR_DEST} into {RAR_BIN_PATH} as new files of root, mode 0555"
    ));
    plan.push(format!(
        "give {RAR_BIN_PATH}/{SR_DEST} the file capabilities =p"
    ));
    plan.extend(configure_plan());
    if opts.clean_after {
        plan.push("run cargo clean".into());
    }
    plan
}

pub fn install(opts: &InstallOptions) -> Result<(), anyhow::Error> {
    let os = get_os(opts.os.as_ref())?;
    let priv_bin = opts
        .build_opts
        .priv_bin
        .clone()
        .or_else(detect_priv_bin)
        .and_then(|bin| {
            path_exe_from_env(
                &std::env::var_os("PATH")
                    .unwrap_or_default()
                    .to_string_lossy()
                    .split(':')
                    .collect::<Vec<_>>(),
                bin,
            )
        });
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
    if is_dry_run() {
        print_plan("install", &install_plan(opts, priv_bin.as_deref()));
        return Ok(());
    }
    if opts.nested_install {
        unsafe { std::env::set_var("ROOTASROLE_INSTALLER_NESTED", "1") };
    } else {
        unsafe { std::env::remove_var("ROOTASROLE_INSTALLER_NESTED") };
    }
    if install::install(
        priv_bin.as_deref(),
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

/// What `uninstall` would remove, for a dry run or without `--apply`.
fn uninstall_plan(opts: &UninstallOptions) -> Vec<String> {
    let mut plan = Vec::new();
    if opts.kind.is_all() || opts.kind.is_sr() {
        plan.push(format!(
            "remove {RAR_BIN_PATH}/{SR_DEST} and {RAR_BIN_PATH}/{CHSR_DEST}"
        ));
        plan.push(if opts.clean_config {
            format!("remove /etc/pam.d/{PAM_CONFIG_SERVICE}")
        } else {
            format!("remove /etc/pam.d/{PAM_CONFIG_SERVICE} if it is the one that install deploys")
        });
        if opts.clean_config {
            plan.push(format!(
                "remove the immutable flag of {RAR_CFG_PATH} and {RAR_CFG_DATA_PATH}, and remove {RAR_CFG_PATH}"
            ));
        }
    }
    plan
}

/// Whether uninstall changes the system: `--apply` is required, and a dry run never does.
fn uninstall_applies(opts: &UninstallOptions) -> bool {
    opts.apply && !is_dry_run()
}

pub fn uninstall(opts: &UninstallOptions) -> Result<(), anyhow::Error> {
    if !uninstall_applies(opts) {
        print_plan("uninstall", &uninstall_plan(opts));
        if !opts.apply {
            info!("Add --apply to uninstall");
        }
        return Ok(());
    }
    uninstall::uninstall(opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{DRY_RUN_TEST_LOCK, set_dry_run};

    #[test]
    fn test_uninstall_needs_apply_and_no_dry_run() {
        let _guard = DRY_RUN_TEST_LOCK.lock().unwrap();
        let opts = |apply| UninstallOptions {
            clean_config: false,
            apply,
            kind: UninstallKind::All,
        };
        set_dry_run(false);
        assert!(!uninstall_applies(&opts(false)));
        assert!(uninstall_applies(&opts(true)));
        set_dry_run(true);
        assert!(!uninstall_applies(&opts(true)));
        set_dry_run(false);
        let plan = uninstall_plan(&opts(false)).join("\n");
        assert!(
            plan.contains(&format!("{RAR_BIN_PATH}/{SR_DEST}")),
            "{plan}"
        );
        assert!(!plan.contains(RAR_CFG_PATH), "{plan}");
    }
}
