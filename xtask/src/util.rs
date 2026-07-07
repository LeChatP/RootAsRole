use std::{
    collections::HashMap,
    fmt::Display,
    fs::{self, File},
    io,
    num::ParseIntError,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output},
    str::FromStr,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, anyhow};
use capctl::Cap;
use capctl::CapState;
use chrono::Duration;
use clap::ValueEnum;
use konst::{eq_str, iter, option, result, string};
use log::{debug, info};
use nix::libc::{FS_IOC_GETFLAGS, FS_IOC_SETFLAGS};
use semver::Version;
use serde::{Deserialize, Serialize, de};
use serde_json::Value;

#[derive(Debug, Clone, ValueEnum, PartialEq, Eq, Hash)]
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
            if os.contains("debian") {
                return Ok(Self::Debian);
            } else if os.contains("ubuntu") {
                return Ok(Self::Ubuntu);
            } else if os.contains("fedora") {
                return Ok(Self::Fedora);
            } else if os.contains("arch") {
                return Ok(Self::ArchLinux);
            } else if os.contains("redhat") || os.contains("rhel") {
                return Ok(Self::RedHat);
            }
        }
        Err(anyhow!("Unsupported OS"))
    }
}

impl Display for OsTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let os_str = match self {
            Self::Debian => "debian",
            Self::Ubuntu => "ubuntu",
            Self::RedHat => "redhat",
            Self::Fedora => "fedora",
            Self::OpenSUSE => "opensuse",
            Self::ArchLinux => "archlinux",
        };
        write!(f, "{os_str}")
    }
}

pub const RST: &str = "\x1B[0m";
pub const BOLD: &str = "\x1B[1m";
pub const UNDERLINE: &str = "\x1B[4m";
pub const RED: &str = "\x1B[31m";
pub const GREEN: &str = "\x1B[32m";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RootSettings {
    pub version: Version,
    #[serde(default)]
    pub storage: Settings,
    #[serde(default)]
    #[serde(flatten)]
    pub policy: Policy,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Policy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Opt>,
    #[serde(default)]
    #[serde(flatten)]
    pub extra_fields: Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

impl StorageMethod {
    pub const VARIANTS: &'static [&str] = &["cbor", "json"];
    /// # Panics
    /// Panics if the string does not correspond to a valid storage method.
    #[must_use]
    pub const fn const_parse(s: &str) -> Self {
        match s {
            _ if konst::eq_str(s, "cbor") | konst::eq_str(s, "CBOR") => Self::Cbor,
            _ if konst::eq_str(s, "json") | konst::eq_str(s, "JSON") => Self::Json,
            _ => panic!("fail to parse StorageMethod from string: invalid value"),
        }
    }

    #[must_use]
    pub const fn is_cbor(&self) -> bool {
        matches!(self, Self::Cbor)
    }
    #[must_use]
    pub const fn is_json(&self) -> bool {
        matches!(self, Self::Json)
    }
}

impl Default for StorageMethod {
    fn default() -> Self {
        RAR_CFG_TYPE
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Settings {
    pub method: StorageMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<RemoteStorageSettings>,
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PathBehavior {
    Delete,
    KeepSafe,
    KeepUnsafe,
    #[default]
    Inherit,
}

impl PathBehavior {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``PathBehavior`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if eq_str(input, "delete") => Self::Delete,
            _ if eq_str(input, "keep_safe") => Self::KeepSafe,
            _ if eq_str(input, "keep_unsafe") => Self::KeepUnsafe,
            _ if eq_str(input, "inherit") => Self::Inherit,
            _ => panic!("fail to parse PathBehavior"),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TimestampType {
    #[default]
    Ppid,
    Tty,
    Uid,
}

impl TimestampType {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``TimestampType`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if konst::eq_str(input, "ppid") => Self::Ppid,
            _ if konst::eq_str(input, "tty") => Self::Tty,
            _ if konst::eq_str(input, "uid") => Self::Uid,
            _ => panic!("fail to parse TimestampType"),
        }
    }
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SUMask(
    #[serde(
        deserialize_with = "deserialize_umask",
        serialize_with = "serialize_umask"
    )]
    pub u16,
);

impl FromStr for SUMask {
    type Err = ParseIntError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        u16::from_str_radix(s, 8).map(SUMask)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
#[repr(u32)]
pub enum SInfo {
    #[default]
    Hide,
    Show,
}

impl SInfo {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``SInfo`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if eq_str(input, "hide") => Self::Hide,
            _ if eq_str(input, "show") => Self::Show,
            _ => panic!("fail to parse SInfo"),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum EnvBehavior {
    Delete,
    Keep,
    #[default]
    Inherit,
}

impl EnvBehavior {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``EnvBehavior`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if eq_str(input, "delete") => Self::Delete,
            _ if eq_str(input, "keep") => Self::Keep,
            _ if eq_str(input, "inherit") => Self::Inherit,
            _ => panic!("fail to parse EnvBehavior"),
        }
    }
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SBounding {
    Strict,
    Ignore,
    #[default]
    Inherit,
}

impl SBounding {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``SBounding`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if eq_str(input, "strict") => Self::Strict,
            _ if eq_str(input, "ignore") => Self::Ignore,
            _ => panic!("fail to parse SBounding"),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SPrivileged {
    Privileged,
    #[default]
    User,
    Inherit,
}

impl SPrivileged {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``SPrivileged`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if eq_str(input, "user") => Self::User,
            _ if eq_str(input, "privileged") => Self::Privileged,
            _ => panic!("fail to parse SPrivileged"),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SAuthentication {
    Skip,
    #[default]
    Perform,
    Inherit,
}

impl SAuthentication {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``SAuthentication`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if eq_str(input, "perform") => Self::Perform,
            _ if eq_str(input, "skip") => Self::Skip,
            _ => panic!("fail to parse SAuthentication"),
        }
    }
}

#[derive(Serialize, Hash, Deserialize, PartialEq, Eq, Debug, Clone, Copy, Default)]
pub enum WorkdirBehavior {
    #[serde(rename = "none")]
    Allowlist, // Deny all except for the listed ones in "add" minus "sub" ofc
    #[serde(rename = "all")]
    Blacklist, // Allow all except for the listed ones in "sub"
    #[default]
    #[serde(rename = "inherit")]
    Inherit, // Inherit from parent levels, which can be combined with the above two behaviors.
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Opt {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<SPathOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<SEnvOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<SPrivileged>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounding: Option<SBounding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execinfo: Option<SInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<SWorkdirSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<STimeout>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub umask: Option<SUMask>,
    #[serde(default, flatten)]
    pub extra_fields: Value,
}

const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
pub const RAR_CFG_PATH: &str = env!("RAR_CFG_PATH");
pub const RAR_CFG_DATA_PATH: &str = env!("RAR_CFG_DATA_PATH");
pub const RAR_CFG_TYPE: StorageMethod = StorageMethod::const_parse(env!("RAR_CFG_TYPE"));
pub const PACKAGE_VERSION: semver::Version = semver::Version::new(
    konst::result::unwrap!(u64::from_str_radix(env!("CARGO_PKG_VERSION_MAJOR"), 10)),
    konst::result::unwrap!(u64::from_str_radix(env!("CARGO_PKG_VERSION_MINOR"), 10)),
    konst::result::unwrap!(u64::from_str_radix(env!("CARGO_PKG_VERSION_PATCH"), 10)),
);

pub const PAM_CONFIG_SERVICE: &str = env!("RAR_PAM_SERVICE");

#[cfg(debug_assertions)]
pub const RAR_CFG_IMMUTABLE: bool = false;
#[cfg(not(debug_assertions))]
pub const RAR_CFG_IMMUTABLE: bool = eq_str(env!("RAR_CFG_IMMUTABLE"), "true");

pub const ENV_PATH_BEHAVIOR: PathBehavior = PathBehavior::const_parse(env!("RAR_PATH_DEFAULT"));

pub const ENV_PATH_ADD_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_PATH_ADD_LIST"), ":"),
        map(str::trim_ascii),
);

pub const ENV_PATH_REMOVE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_PATH_REMOVE_LIST"), ":"),
        map(str::trim_ascii),
);

//=== ENV ===
pub const ENV_DEFAULT_BEHAVIOR: EnvBehavior = EnvBehavior::const_parse(env!("RAR_ENV_DEFAULT"));

pub const ENV_KEEP_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_KEEP_LIST"), ","),
        map(str::trim_ascii),
);

pub const ENV_CHECK_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_CHECK_LIST"), ","),
        map(str::trim_ascii),
);

pub const ENV_DELETE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_DELETE_LIST"), ","),
        map(str::trim_ascii),
);

pub const ENV_SET_LIST_SLICE: &[(&str, &str)] = &iter::collect_const!((&str, &str) =>
    string::split(env!("RAR_ENV_SET_LIST"), "\n"),
        filter_map(|s| {
            if string::trim_matches(s, ' ').is_empty() {
                None
            } else if let Some((key,value)) = string::split_once(s, '=') {
                Some((str::trim_ascii(key),str::trim_ascii(value)))
            } else {
                panic!("Invalid ENV_SET_LIST entry, must be in the form KEY=VALUE");
            }
        })
);

pub const ENV_OVERRIDE_BEHAVIOR: bool = result::unwrap_or!(
    konst::primitive::parse_bool(env!("RAR_ENV_OVERRIDE_BEHAVIOR")),
    false
);

pub static ENV_KEEP_LIST: &[&str; ENV_KEEP_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(ENV_KEEP_LIST_SLICE));

pub static ENV_CHECK_LIST: &[&str; ENV_CHECK_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(ENV_CHECK_LIST_SLICE));

pub static ENV_DELETE_LIST: &[&str; ENV_DELETE_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(ENV_DELETE_LIST_SLICE));

pub static ENV_SET_LIST: &[(&str, &str); ENV_SET_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(ENV_SET_LIST_SLICE));

//=== STimeout ===

pub const TIMEOUT_TYPE: TimestampType = TimestampType::const_parse(env!("RAR_TIMEOUT_TYPE"));

pub const TIMEOUT_DURATION: Duration = option::unwrap_or!(
    result::unwrap_or!(
        convert_string_to_duration(env!("RAR_TIMEOUT_DURATION")),
        None
    ),
    Duration::seconds(5)
);

pub const TIMEOUT_MAX_USAGE: Option<u64> = if eq_str(env!("RAR_TIMEOUT_MAX_USAGE"), "") {
    None
} else {
    Some(result::unwrap!(u64::from_str_radix(
        env!("RAR_TIMEOUT_MAX_USAGE"),
        10
    )))
};

pub const WORKDIR_BEHAVIOR: WorkdirBehavior =
    assert_valid_workdir_behavior(WorkdirBehavior::const_parse(env!("RAR_WORKDIR_BEHAVIOR")));

const fn assert_valid_workdir_behavior(e: WorkdirBehavior) -> WorkdirBehavior {
    match e {
        WorkdirBehavior::Inherit => panic!("Workdir behavior cannot be inherit"),
        e => e,
    }
}

pub const WORKDIR_FALLBACK: Option<&str> = option_env!("RAR_WORKDIR_FALLBACK");

pub const WORKDIR_ADD_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_WORKDIR_ADD_LIST"), ","),
        map(str::trim_ascii),
);

pub const WORKDIR_REMOVE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_WORKDIR_REMOVE_LIST"), ","),
        map(str::trim_ascii),
);

pub static WORKDIR_ADD_LIST: &[&str; WORKDIR_ADD_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(WORKDIR_ADD_LIST_SLICE));

pub static WORKDIR_REMOVE_LIST: &[&str; WORKDIR_REMOVE_LIST_SLICE.len()] =
    result::unwrap!(konst::slice::try_into_array(WORKDIR_REMOVE_LIST_SLICE));

pub const RAR_PAM_SERVICE: &str = env!("RAR_PAM_SERVICE");
pub const RAR_BOUNDING: SBounding = SBounding::const_parse(env!("RAR_BOUNDING"));
pub const RAR_AUTHENTICATION: SAuthentication =
    SAuthentication::const_parse(env!("RAR_AUTHENTICATION"));
pub const RAR_USER_CONSIDERED: SPrivileged = SPrivileged::const_parse(env!("RAR_USER_CONSIDERED"));

pub const BOUNDING: SBounding = SBounding::const_parse(env!("RAR_BOUNDING"));

pub const AUTHENTICATION: SAuthentication =
    SAuthentication::const_parse(env!("RAR_AUTHENTICATION"));

pub const PRIVILEGED: SPrivileged = SPrivileged::const_parse(env!("RAR_USER_CONSIDERED"));

pub const UMASK: SUMask = SUMask(result::unwrap_or!(
    u16::from_str_radix(env!("RAR_UMASK"), 10),
    0o022
));

pub const INFO: SInfo = SInfo::const_parse(env!("RAR_EXEC_INFO_DISPLAY"));

static DRY_RUN: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub enum ImmutableLock {
    Set,
    Unset,
}

impl ImmutableLock {
    #[must_use]
    pub const fn is_set(&self) -> bool {
        matches!(self, Self::Set)
    }
    #[must_use]
    pub const fn is_unset(&self) -> bool {
        matches!(self, Self::Unset)
    }
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

#[derive(Debug)]
struct DurationParseError;
impl std::fmt::Display for DurationParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid duration format")
    }
}

const fn convert_string_to_duration(
    s: &str,
) -> Result<Option<chrono::TimeDelta>, DurationParseError> {
    let mut parts = string::split(s, ':');
    let Some(hours) = parts.next() else {
        return Err(DurationParseError);
    };
    let Some(minutes) = parts.next() else {
        return Err(DurationParseError);
    };
    let Some(seconds) = parts.next() else {
        return Err(DurationParseError);
    };

    let hours: i64 = if let Ok(hours) = i64::from_str_radix(hours, 10) {
        hours
    } else {
        return Err(DurationParseError);
    };
    let minutes: i64 = if let Ok(minutes) = i64::from_str_radix(minutes, 10) {
        minutes
    } else {
        return Err(DurationParseError);
    };
    let seconds: i64 = if let Ok(seconds) = i64::from_str_radix(seconds, 10) {
        seconds
    } else {
        return Err(DurationParseError);
    };
    Ok(Some(Duration::seconds(
        hours * 3600 + minutes * 60 + seconds,
    )))
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
    format!(
        "{} {}",
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

fn log_command_execution(command: &Command, action: &str) {
    info!(
        "{BOLD}Running:{RED} {}{RST}\n{BOLD}  Objective -->{RST}{GREEN} {}{RST}",
        shell_quote_command(command),
        action
    );
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
    if file.as_ref().is_dir() {
        for entry in fs::read_dir(file)? {
            let entry = entry?;
            toggle_lock_config(&entry.path(), lock)?;
        }
    } else if file.as_ref().is_file() {
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
    }
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
    env_path.iter().find_map(|dir| {
        let full_path = Path::new(dir).join(&exe_name);
        debug!("Checking path: {}", full_path.display());
        full_path.is_file().then_some(full_path).and_then(|path| {
            if path.is_symlink() {
                fs::read_link(path).ok()
            } else {
                path.canonicalize().ok()
            }
        })
    })
}

#[allow(clippy::trivially_copy_pass_by_ref)] // Function used by serde, must take a reference
fn serialize_umask<S>(value: &u16, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("{value:03o}"))
}

fn deserialize_umask<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    SUMask::from_str(&s)
        .map(|umask| umask.0)
        .map_err(serde::de::Error::custom)
}

impl WorkdirBehavior {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``PathBehavior`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if eq_str(input, "all") => Self::Blacklist,
            _ if eq_str(input, "none") => Self::Allowlist,
            _ if eq_str(input, "inherit") => Self::Inherit,
            _ => panic!("fail to parse WorkdirBehavior"),
        }
    }

    #[must_use]
    pub const fn is_allowlist(&self) -> bool {
        matches!(self, Self::Allowlist)
    }
    #[must_use]
    pub const fn is_blacklist(&self) -> bool {
        matches!(self, Self::Blacklist)
    }
    #[must_use]
    pub const fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
pub struct SWorkdirSet {
    /// The default behavior for workdir handling. This determines how the "add" and "sub" lists are interpreted.
    /// - If set to `Allowlist`, only the paths in the "add" list (minus those in the "sub" list) will be allowed as workdirs.
    /// - If set to `Blacklist`, all paths will be allowed as workdirs except those in the "sub" list.
    /// - If set to `Inherit`, the behavior will be inherited from parent levels, which can be combined with the above two behaviors.
    ///
    /// Note: The target user must have permissions to access the allowed workdirs, otherwise the command will fail to execute.
    /// If you want bypass the access control check, grant the `CAP_DAC_READ_SEARCH` capability in the "cred" section
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    pub default_behavior: WorkdirBehavior,

    /// The "fallback" field specifies a fallback directory to use as the working directory.
    /// This will override the current user working directory.
    /// For example:
    /// someone type: `dosr ls` in his home directory, but the config has a fallback of `/tmp`,
    /// then the command will be executed with `/tmp` as the working directory instead of the user's home directory.
    /// This is useful in scenarios where users do not have to know or care about the actual working directory of a command
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub add: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "del")]
    pub sub: Option<Vec<String>>,
}
