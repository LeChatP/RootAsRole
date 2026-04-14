use std::{
    collections::HashMap,
    error::Error,
    fs::{self, File},
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output},
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, anyhow};
use capctl::Cap;
use capctl::CapState;
use chrono::Duration;
use clap::ValueEnum;
use log::{debug, info};
use nix::libc::{FS_IOC_GETFLAGS, FS_IOC_SETFLAGS};
use serde::{Deserialize, Serialize, de};
use serde_json::Value;
use strum::{Display, EnumIs, EnumIter, EnumString};

#[derive(Debug, Clone, ValueEnum, EnumIs, EnumIter, Display, PartialEq, Eq, Hash)]
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
    #[clap(alias = "suse")]
    OpenSUSE,
    #[clap(alias = "arch")]
    ArchLinux,
}

impl OsTarget {
    fn os_release_identifiers(content: &str) -> Vec<String> {
        content
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter_map(|(key, value)| {
                if key == "ID" || key == "ID_LIKE" {
                    Some(value)
                } else {
                    None
                }
            })
            .flat_map(|value| value.trim_matches('"').split_whitespace())
            .map(str::to_ascii_lowercase)
            .collect()
    }

    /// # Errors
    ///
    /// Will return an error if the OS cannot be detected or is unsupported
    pub fn detect() -> Result<Self, anyhow::Error> {
        if let Ok(os_release) = std::fs::read_to_string("/etc/os-release") {
            let identifiers = Self::os_release_identifiers(&os_release);
            if let Some(target) = crate::installer::dependencies::os_target_from_identifiers(
                identifiers.iter().map(std::string::String::as_str),
            )? {
                return Ok(target);
            }
        }

        for file in glob::glob("/etc/*-release")? {
            let file = file?;
            let os = std::fs::read_to_string(&file)?.to_ascii_lowercase();
            if let Some(target) = crate::installer::dependencies::os_target_from_identifiers(
                os.split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_'),
            )? {
                return Ok(target);
            }
        }
        Err(anyhow!("Unsupported OS"))
    }
}

pub const RST: &str = "\x1B[0m";
pub const BOLD: &str = "\x1B[1m";
pub const UNDERLINE: &str = "\x1B[4m";
pub const RED: &str = "\x1B[31m";
pub const GREEN: &str = "\x1B[32m";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SettingsFile {
    pub storage: Settings,
    #[serde(default)]
    #[serde(flatten)]
    pub extra_fields: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone, EnumString)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
pub enum StorageMethod {
    Json,
    Cbor,
    //    SQLite,
    //    PostgreSQL,
    //    MySQL,
    //    LDAP,
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Settings {
    pub method: StorageMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<RemoteStorageSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Opt>,
    #[serde(default)]
    #[serde(flatten)]
    pub extra_fields: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemoteStorageSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub immutable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    #[serde(flatten)]
    pub extra_fields: Value,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PathBehavior {
    Delete,
    KeepSafe,
    KeepUnsafe,
    #[default]
    Inherit,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone, Copy, Display, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TimestampType {
    #[default]
    Ppid,
    Tty,
    Uid,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
pub struct STimeout {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_field: Option<TimestampType>,
    #[serde(
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration",
        skip_serializing_if = "Option::is_none"
    )]
    pub duration: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_usage: Option<u64>,
    #[serde(default)]
    #[serde(flatten)]
    pub extra_fields: Value,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct SPathOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    pub default_behavior: PathBehavior,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "del")]
    pub sub: Option<Vec<String>>,
    #[serde(default)]
    #[serde(flatten)]
    pub extra_fields: Value,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum EnvBehavior {
    Delete,
    Keep,
    #[default]
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
pub struct SEnvOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    pub default_behavior: EnvBehavior,
    #[serde(alias = "override", default, skip_serializing_if = "Option::is_none")]
    pub override_behavior: Option<bool>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub set: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete: Option<Vec<String>>,
    #[serde(default, flatten)]
    pub extra_fields: Value,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SBounding {
    Strict,
    Ignore,
    #[default]
    Inherit,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SPrivileged {
    Privileged,
    #[default]
    User,
    Inherit,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SAuthentication {
    Skip,
    #[default]
    Perform,
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Opt {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<SPathOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<SEnvOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<SPrivileged>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounding: Option<SBounding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<STimeout>,
    #[serde(default, flatten)]
    pub extra_fields: Value,
}

const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub const ROOTASROLE: &str = env!("RAR_CFG_PATH");
static DRY_RUN: AtomicBool = AtomicBool::new(false);

#[derive(Debug, EnumIs)]
pub enum ImmutableLock {
    Set,
    Unset,
}

pub fn is_default<T: PartialEq + Default>(t: &T) -> bool {
    t == &T::default()
}

#[allow(clippy::ref_option)]
fn serialize_duration<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // hh:mm:ss format
    match value {
        Some(value) => serializer.serialize_str(&format!(
            "{:#02}:{:#02}:{:#02}",
            value.num_hours(),
            value.num_minutes() % 60,
            value.num_seconds() % 60
        )),
        None => serializer.serialize_none(),
    }
}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match convert_string_to_duration(&s) {
        Ok(d) => Ok(d),
        Err(e) => Err(de::Error::custom(e)),
    }
}

/// # Errors
///
/// Will return an error if the duration string is not in the format hh:mm:ss or if the hours, minutes or seconds cannot be parsed as integers
pub fn convert_string_to_duration(s: &str) -> Result<Option<chrono::TimeDelta>, Box<dyn Error>> {
    let mut parts = s.split(':');
    //unwrap or error
    if let (Some(hours), Some(minutes), Some(seconds)) = (parts.next(), parts.next(), parts.next())
    {
        let hours: i64 = hours.parse()?;
        let minutes: i64 = minutes.parse()?;
        let seconds: i64 = seconds.parse()?;
        return Ok(Some(
            Duration::hours(hours) + Duration::minutes(minutes) + Duration::seconds(seconds),
        ));
    }
    Err("Invalid duration format".into())
}

fn immutable_required_privileges(file: &File, effective: bool) -> Result<(), capctl::Error> {
    //get file owner
    let metadata = file.metadata().expect("Failed to get file metadata");
    let uid = metadata.uid();
    let gid = metadata.gid();
    immutable_effective(effective)?;
    // check if the current user is the owner
    if nix::unistd::Uid::effective() != nix::unistd::Uid::from_raw(uid)
        && nix::unistd::Gid::effective() != nix::unistd::Gid::from_raw(gid)
    {
        read_or_dac_override(effective)?;
        fowner_effective(effective)?;
    }
    Ok(())
}

/// # Errors
///
/// Will return an error if capabilities about dac cannot be set due to permissions or system issue
fn read_or_dac_override(effective: bool) -> Result<(), capctl::Error> {
    if effective {
        read_effective(true).or_else(|_| dac_override_effective(true))?;
    } else {
        read_effective(false).and_then(|()| dac_override_effective(false))?;
    }
    Ok(())
}

/// # Errors
///
/// Will return an error if the current directory is not a cargo project or if cargo command fails
pub fn change_dir_to_project_root() -> Result<(), anyhow::Error> {
    // check if current directory is our code repo by looking for the Cargo.toml file
    let output = output_checked(
        Command::new("cargo").args(["locate-project", "--workspace"]),
        "check if current directory is a cargo workspace",
    )?;
    let json = String::from_utf8(output.stdout)?;
    let value: Value = serde_json::from_str(&json)?;
    let manifest_path = Path::new(
        value
            .get("root")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Failed to parse cargo locate-project output"))?,
    );

    std::env::set_current_dir(
        manifest_path
            .parent()
            .ok_or_else(|| anyhow!("Failed to get parent directory of Cargo.toml"))?,
    )?;
    Ok(())
}

pub fn set_dry_run(enabled: bool) {
    DRY_RUN.store(enabled, Ordering::Relaxed);
}

#[must_use]
pub fn is_dry_run() -> bool {
    DRY_RUN.load(Ordering::Relaxed)
}

/// # Errors
///
/// Will return an error if the command fails to execute or exits with a non-zero code
pub fn status_checked(command: &mut Command, action: &str) -> Result<ExitStatus, anyhow::Error> {
    let status = command
        .status()
        .with_context(|| format!("Failed to {action}: {command:?}"))?;
    if !status.success() {
        anyhow::bail!("Failed to {action}: {command:?} exited with status {status}");
    }
    Ok(status)
}

fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        "''".to_string()
    } else if !arg.contains(|c: char| c.is_whitespace() || c == '\'' || c == '"') {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

fn shell_quote_command(command: &Command) -> String {
    format!("{} {}",
        command.get_program().to_string_lossy(),
        command
        .get_args()
        .map(|arg| shell_quote(arg.to_string_lossy().as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
    )
}

/// # Errors
///
/// Will return an error if the command fails to execute or exits with a non-zero code
pub fn run_checked(command: &mut Command, action: &str) -> Result<(), anyhow::Error> {
    log_command_execution(command, action);
    let _ = status_checked(command, action)?;
    Ok(())
}

fn log_command_execution(command: & Command, action: &str) {
    info!("{BOLD}Running:{RED} {}{RST}\n{BOLD}  Objective -->{RST}{GREEN} {}{RST}", shell_quote_command(command), action);
}

/// # Errors
///
/// Will return an error if the command fails to execute or exits with a non-zero code
pub fn output_checked(command: &mut Command, action: &str) -> Result<Output, anyhow::Error> {
    let output = command
        .output()
        .with_context(|| format!("Failed to {action}: {command:?}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "Failed to {action}: {command:?} exited with status {}",
            output.status
        );
    }
    Ok(output)
}

/// Set or unset the immutable flag on a file
/// # Arguments
/// * `file` - The file to set the immutable flag on
/// * `lock` - Whether to set or unset the immutable flag
/// # Errors
/// Will return an error if the file cannot be opened, if the immutable flag cannot be set
pub fn toggle_lock_config<P: AsRef<Path>>(file: &P, lock: &ImmutableLock) -> io::Result<()> {
    let file = open_with_privileges(file)?;
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { nix::libc::ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if lock.is_unset() {
        val &= !(FS_IMMUTABLE_FL);
    } else {
        val |= FS_IMMUTABLE_FL;
    }

    immutable_required_privileges(&file, true)?;
    if unsafe { nix::libc::ioctl(fd, FS_IOC_SETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    immutable_required_privileges(&file, false)?;
    Ok(())
}

/// # Errors
/// Will return an error if the file cannot be opened or if the required capabilities cannot be set
pub fn cap_effective(cap: Cap, enable: bool) -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.set_state(cap, enable);
    current.set_current()
}

/// # Errors
/// Will return an error if the file cannot be opened or if the required capabilities cannot be set
pub fn fowner_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::FOWNER, enable)
}

/// # Errors
/// Will return an error if the file cannot be opened or if the required capabilities cannot be set
pub fn read_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::DAC_READ_SEARCH, enable)
}

/// # Errors
/// Will return an error if the file cannot be opened or if the required capabilities cannot be set
pub fn dac_override_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::DAC_OVERRIDE, enable)
}

/// # Errors
/// Will return an error if the file cannot be opened or if the required capabilities cannot be set
pub fn immutable_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::LINUX_IMMUTABLE, enable)
}

/// # Errors
/// Will return an error if the file cannot be opened or if the required capabilities cannot be set
pub fn open_with_privileges<P: AsRef<Path>>(p: P) -> Result<File, std::io::Error> {
    std::fs::File::open(&p).or_else(|_| {
        read_effective(true).or_else(|_| dac_override_effective(true))?;
        let res = std::fs::File::open(p);
        read_effective(false)?;
        dac_override_effective(false)?;
        res
    })
}

/// # Errors
/// Will return an error if the file cannot be opened
pub fn files_are_equal(path1: &str, path2: &str) -> io::Result<bool> {
    let file1_content = fs::read(path1)?;
    let file2_content = fs::read(path2)?;

    Ok(file1_content == file2_content)
}

/// # Errors
/// Will return an error if the OS cannot be detected
pub fn get_os(os: Option<&OsTarget>) -> Result<OsTarget, anyhow::Error> {
    Ok(if let Some(os) = os {
        os.clone()
    } else {
        OsTarget::detect()
            .map(|t| {
                debug!("Detected OS is : {t}");
                t
            })
            .context("Failed to detect the OS")?
    })
}

#[must_use]
pub fn detect_priv_bin() -> Option<PathBuf> {
    // is /usr/bin/dosr exist ?
    if std::fs::metadata("/usr/bin/dosr").is_ok() {
        Some("/usr/bin/dosr".into())
    } else if std::fs::metadata("/usr/bin/sudo").is_ok() {
        Some("/usr/bin/sudo".into())
    } else if std::fs::metadata("/usr/bin/doas").is_ok() {
        Some("/usr/bin/doas".into())
    } else if std::fs::metadata("/usr/bin/please").is_ok() {
        Some("/usr/bin/please".into())
    } else {
        None
    }
}

/// # Errors
/// Will return an error if the capabilities cannot be altered due to permissions or system issues
pub fn cap_clear(state: &mut capctl::CapState) -> Result<(), anyhow::Error> {
    state.effective.clear();
    state.set_current()?;
    Ok(())
}

#[must_use]
pub fn is_su_command(priv_bin: &Path) -> bool {
    priv_bin.file_name().is_some_and(|name| name == "su")
}

#[must_use]
pub fn is_run0_command(priv_bin: &Path) -> bool {
    priv_bin.file_name().is_some_and(|name| name == "run0")
}

pub fn path_exe_from_env<P: AsRef<Path>>(env_path: &[&str], exe_name: P) -> Option<PathBuf> {
    env_path
        .iter()
        .find_map(|dir| {
            let full_path = Path::new(dir).join(&exe_name);
            debug!("Checking path: {}", full_path.display());
            full_path.is_file().then_some(full_path).and_then(|path| {
                if path.is_symlink() {
                    fs::read_link(path)
                    .ok()
                } else {
                    path.canonicalize().ok()
                }
            })
        })
}
