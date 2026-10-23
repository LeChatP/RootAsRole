use core::panic;
use std::borrow::Cow;
use std::collections::HashMap;
use std::num::{NonZeroU8, ParseIntError};
use std::result::Result;
use std::str::FromStr;
use std::{cell::RefCell, rc::Rc};

use bon::{Builder, bon};

use indexmap::IndexSet;
use konst::eq_str;

use nix::sys::stat::Mode;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use log::debug;

use crate::rc_refcell;
use crate::util::{
    AUTHENTICATION, BOUNDING, ENV_CHECK_LIST, ENV_DEFAULT_BEHAVIOR, ENV_DELETE_LIST, ENV_KEEP_LIST,
    ENV_OVERRIDE_BEHAVIOR, ENV_PATH_ADD_LIST_SLICE, ENV_PATH_BEHAVIOR, ENV_PATH_REMOVE_LIST_SLICE,
    ENV_SET_LIST, HARDENED_ENUM_VALUE_0, HARDENED_ENUM_VALUE_1, HARDENED_ENUM_VALUE_2,
    HARDENED_ENUM_VALUE_3, INFO, PASSWORD_DELAY, PASSWORD_TRIES, PRIVILEGED, TIMEOUT_DURATION,
    TIMEOUT_MAX_USAGE, TIMEOUT_TYPE, UMASK, is_valid_env_name, is_valid_env_pattern,
};

use super::{
    FilterMatcher, deserialize_duration,
    env::{EnvLevel, ResolvedEnv},
    is_default,
    path::{PathLevel, ResolvedPath},
    serialize_duration,
};

use super::{
    lhs_deserialize, lhs_deserialize_envkey, lhs_serialize, lhs_serialize_envkey,
    structs::{SPolicy, SRole, STask},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    #[default]
    None,
    Default,
    Global,
    Role,
    Task,
}

#[derive(Debug, Clone, Copy)]
pub enum OptType {
    Path,
    Env,
    Root,
    Bounding,
    Timeout,
    Authentication,
    ExecInfo,
    UMask,
    Workdir,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
#[repr(u32)]
pub enum PathBehavior {
    Delete = HARDENED_ENUM_VALUE_0,
    // written like in chsr; the spellings of 4.0 and of the build settings are still read
    #[serde(rename = "keep-safe", alias = "keepsafe", alias = "keep_safe")]
    KeepSafe = HARDENED_ENUM_VALUE_1,
    #[serde(rename = "keep-unsafe", alias = "keepunsafe", alias = "keep_unsafe")]
    KeepUnsafe = HARDENED_ENUM_VALUE_2,
    #[default]
    Inherit = HARDENED_ENUM_VALUE_3,
}

impl PathBehavior {
    #[must_use]
    pub const fn is_delete(&self) -> bool {
        matches!(self, Self::Delete)
    }
    #[must_use]
    pub const fn is_keep_safe(&self) -> bool {
        matches!(self, Self::KeepSafe)
    }
    #[must_use]
    pub const fn is_keep_unsafe(&self) -> bool {
        matches!(self, Self::KeepUnsafe)
    }
    #[must_use]
    pub const fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
#[repr(u8)]
pub enum TimestampType {
    #[default]
    PPID,
    TTY,
    UID,
}

/// How many times the password is asked, and how long dosr waits after a wrong one.
///
/// A level that does not set a field inherits it from the upper levels, down to the build-time
/// defaults (`RAR_PASSWORD_TRIES`, `RAR_PASSWORD_DELAY`). `tries` is at least 1: 0 would never
/// let anyone in, or never stop asking.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default, Builder)]
pub struct SPassword {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tries: Option<NonZeroU8>,
    #[serde(
        default,
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration",
        skip_serializing_if = "Option::is_none"
    )]
    pub delay: Option<jiff::SignedDuration>,
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    #[builder(default)]
    pub extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default, Builder)]
pub struct STimeout {
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub type_field: Option<TimestampType>,
    #[serde(
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration",
        skip_serializing_if = "Option::is_none"
    )]
    pub duration: Option<jiff::SignedDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_usage: Option<u64>,
    #[serde(default)]
    #[serde(flatten, skip_serializing_if = "Map::is_empty")]
    #[builder(default)]
    pub extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Builder, Default)]
pub struct SPathOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default_behavior: PathBehavior,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| { v.into_iter().map(|s| s.to_string()).collect() })]
    pub add: Option<IndexSet<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize",
        alias = "del"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| { v.into_iter().map(|s| s.to_string()).collect() })]
    pub sub: Option<IndexSet<String>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
#[repr(u32)]
pub enum EnvBehavior {
    Delete = HARDENED_ENUM_VALUE_0,
    Keep = HARDENED_ENUM_VALUE_1,
    #[default]
    Inherit = HARDENED_ENUM_VALUE_2,
}

impl EnvBehavior {
    #[must_use]
    pub const fn is_delete(&self) -> bool {
        matches!(self, Self::Delete)
    }
    #[must_use]
    pub const fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }
    #[must_use]
    pub const fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }
}

#[derive(Serialize, Hash, Deserialize, PartialEq, Eq, Debug, Clone)]
pub enum EnvKeyType {
    Wildcarded,
    Normal,
}

impl EnvKeyType {
    #[must_use]
    pub const fn is_wildcarded(&self) -> bool {
        matches!(self, Self::Wildcarded)
    }
    #[must_use]
    pub const fn is_normal(&self) -> bool {
        matches!(self, Self::Normal)
    }
}

#[derive(Eq, Hash, PartialEq, Serialize, Debug, Clone, Builder)]
#[serde(transparent)]
pub struct EnvKey {
    #[serde(skip)]
    env_type: EnvKeyType,
    value: String,
}

impl std::fmt::Display for EnvKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Environment options of a level: global, role or task.
///
/// `default` selects how the user's environment is filtered:
/// - `delete`: every variable is removed, except those of the `keep` and `check` lists,
/// - `keep`: every variable is kept, except those of the `delete` list,
/// - `inherit`: the behavior of the upper level applies.
///
/// In both modes, a variable of the `check` list is passed only if its value is safe, and a shell
/// function definition is never passed (see [`crate::util::is_shell_function`]). The `set` list
/// gives variables a value chosen by the policy.
///
/// # Lists that a level does not define are inherited
/// A list that a level does not define is inherited from the upper levels, and from the built-in
/// defaults, even when the level sets its own `default`. A defined list replaces the inherited one
/// when the level sets `default`, and extends it when the level inherits. Only an explicitly empty
/// list (`[]`) removes an inherited list.
///
/// This is the fail-safe choice: a protection is never lost by omission, removing it has to be
/// written in the policy, where it can be reviewed.
/// - In keep mode, the `delete` and `check` lists are what protect the command. A level that
///   switches to keep mode without restating them still removes and checks the same variables.
///   A deny list can never list every dangerous variable (CWE-184); a level that forgets the whole
///   list must not make it worse.
/// - In delete mode, an inherited `keep` or `check` list only passes variables that an upper level
///   already allows, and the variables of the `check` list are still validated.
#[allow(clippy::missing_errors_doc)]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default, Builder)]
pub struct SEnvOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default_behavior: EnvBehavior,
    #[serde(alias = "override", default, skip_serializing_if = "Option::is_none")]
    pub override_behavior: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[builder(with = |iter: impl IntoIterator<Item = (impl ToString, impl ToString)>| {
        let mut map = HashMap::with_hasher(Default::default());
        map.extend(iter.into_iter().map(|(k, v)| (k.to_string(), v.to_string())));
        map
    })]
    pub set: Option<HashMap<String, String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| -> Result<_,String> { let mut res = IndexSet::new(); for s in v { res.insert(EnvKey::new(s.to_string())?); } Ok(res)})]
    pub keep: Option<IndexSet<EnvKey>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| -> Result<_,String> { let mut res = IndexSet::new(); for s in v { res.insert(EnvKey::new(s.to_string())?); } Ok(res)})]
    pub check: Option<IndexSet<EnvKey>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| -> Result<_,String> { let mut res = IndexSet::new(); for s in v { res.insert(EnvKey::new(s.to_string())?); } Ok(res)})]
    pub delete: Option<IndexSet<EnvKey>>,
    #[serde(default, flatten)]
    #[builder(default)]
    pub extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(untagged)]
pub enum SWorkdirEither {
    /// This is the equivalent of deny all and fallback to the specified path.
    Path(String),
    Struct(SWorkdirSet),
}

#[derive(Serialize, Hash, Deserialize, PartialEq, Eq, Debug, Clone, Copy, Default)]
#[repr(u32)]
pub enum WorkdirBehavior {
    #[serde(rename = "none")]
    Allowlist = HARDENED_ENUM_VALUE_0, // Deny all except for the listed ones in "add" minus "sub" ofc
    #[serde(rename = "all")]
    Blacklist = HARDENED_ENUM_VALUE_1, // Allow all except for the listed ones in "sub"
    #[default]
    #[serde(rename = "inherit")]
    Inherit = HARDENED_ENUM_VALUE_2, // Inherit from parent levels, which can be combined with the above two behaviors.
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default, Builder)]
pub struct SWorkdirSet {
    /// The default behavior for workdir handling. This determines how the "add" and "sub" lists are interpreted.
    /// - If set to `Allowlist`, only the paths in the "add" list (minus those in the "sub" list) will be allowed as workdirs.
    /// - If set to `Blacklist`, all paths will be allowed as workdirs except those in the "sub" list.
    /// - If set to `Inherit`, the behavior will be inherited from parent levels, which can be combined with the above two behaviors.
    ///
    /// Note: The target user must have permissions to access the allowed workdirs, otherwise the command will fail to execute.
    /// If you want bypass the access control check, grant the `CAP_DAC_READ_SEARCH` capability in the "cred" section
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default_behavior: WorkdirBehavior,

    /// The "fallback" field specifies a fallback directory to use as the working directory.
    /// This will override the current user working directory.
    /// For example:
    /// someone type: `dosr ls` in his home directory, but the config has a fallback of `/tmp`,
    /// then the command will be executed with `/tmp` as the working directory instead of the user's home directory.
    /// This is useful in scenarios where users do not have to know or care about the actual working directory of a command
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| { v.into_iter().map(|s| s.to_string()).collect() })]
    pub add: Option<IndexSet<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize",
        alias = "del"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| { v.into_iter().map(|s| s.to_string()).collect() })]
    pub sub: Option<IndexSet<String>>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[repr(u32)]
pub enum SBounding {
    Strict = HARDENED_ENUM_VALUE_0,
    Ignore = HARDENED_ENUM_VALUE_2,
}

impl SBounding {
    #[must_use]
    pub const fn is_strict(&self) -> bool {
        matches!(self, Self::Strict)
    }
    #[must_use]
    pub const fn is_ignore(&self) -> bool {
        matches!(self, Self::Ignore)
    }
}

impl FromStr for SBounding {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "ignore" => Ok(Self::Ignore),
            _ => Err(format!("Invalid SBounding value: {s}")),
        }
    }
}

impl Default for SBounding {
    fn default() -> Self {
        BOUNDING
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
#[repr(u32)]
pub enum SPrivileged {
    User = HARDENED_ENUM_VALUE_0,
    Privileged = HARDENED_ENUM_VALUE_1,
}

impl SPrivileged {
    #[must_use]
    pub const fn is_privileged(&self) -> bool {
        matches!(self, Self::Privileged)
    }
    #[must_use]
    pub const fn is_user(&self) -> bool {
        matches!(self, Self::User)
    }
}

impl FromStr for SPrivileged {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "user" => Ok(Self::User),
            "privileged" => Ok(Self::Privileged),
            _ => Err(format!("Invalid SPrivileged value: {s}")),
        }
    }
}

impl Default for SPrivileged {
    fn default() -> Self {
        PRIVILEGED
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
#[repr(u32)]
pub enum SAuthentication {
    Perform = HARDENED_ENUM_VALUE_0,
    Skip = HARDENED_ENUM_VALUE_1,
}

impl SAuthentication {
    #[must_use]
    pub const fn is_skip(&self) -> bool {
        matches!(self, Self::Skip)
    }
}

impl FromStr for SAuthentication {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "perform" => Ok(Self::Perform),
            "skip" => Ok(Self::Skip),
            _ => Err(format!("Invalid SAuthentication value: {s}")),
        }
    }
}

impl Default for SAuthentication {
    fn default() -> Self {
        AUTHENTICATION
    }
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

impl Default for SUMask {
    fn default() -> Self {
        UMASK
    }
}

impl From<SUMask> for Mode {
    fn from(umask: SUMask) -> Self {
        Self::from_bits_truncate(u32::from(umask.0))
    }
}

impl FromStr for SUMask {
    type Err = ParseIntError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        u16::from_str_radix(s, 8).map(SUMask)
    }
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
    let s: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
    SUMask::from_str(&s)
        .map(|umask| umask.0)
        .map_err(serde::de::Error::custom)
}

impl From<SUMask> for u16 {
    fn from(val: SUMask) -> Self {
        val.0
    }
}

impl From<u16> for SUMask {
    fn from(val: u16) -> Self {
        Self(val)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
#[repr(u32)]
pub enum SInfo {
    #[default]
    Hide = HARDENED_ENUM_VALUE_0,
    Show = HARDENED_ENUM_VALUE_1,
}

impl SInfo {
    #[must_use]
    pub const fn is_hide(&self) -> bool {
        matches!(self, Self::Hide)
    }
}

impl FromStr for SInfo {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hide" => Ok(Self::Hide),
            "show" => Ok(Self::Show),
            _ => Err(format!("Invalid SInfo value: {s}")),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Opt {
    #[serde(skip)]
    pub level: Level,
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
    pub workdir: Option<SWorkdirEither>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<STimeout>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SPassword>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub umask: Option<SUMask>,
    #[serde(default, flatten)]
    pub extra_fields: Map<String, Value>,
}

#[bon]
impl Opt {
    #[builder]
    pub const fn new(
        #[builder(start_fn)] level: Level,
        path: Option<SPathOptions>,
        env: Option<SEnvOptions>,
        root: Option<SPrivileged>,
        bounding: Option<SBounding>,
        authentication: Option<SAuthentication>,
        execinfo: Option<SInfo>,
        workdir: Option<SWorkdirEither>,
        timeout: Option<STimeout>,
        password: Option<SPassword>,
        umask: Option<SUMask>,
        #[builder(default)] extra_fields: Map<String, Value>,
    ) -> Self {
        Self {
            level,
            path,
            env,
            root,
            bounding,
            authentication,
            execinfo,
            workdir,
            timeout,
            password,
            umask,
            extra_fields,
        }
    }

    /// # Panics
    /// Panics if any of the default values defined in config.toml are invalid.
    /// This should never happen, as the defaults are hardcoded and tested.
    #[must_use]
    pub fn level_default() -> Self {
        Self::builder(Level::Default)
            .root(PRIVILEGED)
            .bounding(BOUNDING)
            .path(SPathOptions::level_default())
            .authentication(AUTHENTICATION)
            .execinfo(INFO)
            .umask(UMASK)
            .env(
                #[allow(clippy::unwrap_used)]
                SEnvOptions::builder(ENV_DEFAULT_BEHAVIOR)
                    .keep(ENV_KEEP_LIST.iter().copied())
                    .unwrap()
                    .check(ENV_CHECK_LIST.iter().copied())
                    .unwrap()
                    .delete(ENV_DELETE_LIST.iter().copied())
                    .unwrap()
                    .set(ENV_SET_LIST.iter().copied())
                    .override_behavior(ENV_OVERRIDE_BEHAVIOR)
                    .build(),
            )
            .timeout(
                STimeout::builder()
                    .type_field(TIMEOUT_TYPE)
                    .maybe_duration(TIMEOUT_DURATION)
                    .maybe_max_usage(TIMEOUT_MAX_USAGE)
                    .build(),
            )
            .password(
                SPassword::builder()
                    .tries(PASSWORD_TRIES)
                    .delay(PASSWORD_DELAY)
                    .build(),
            )
            .build()
    }
}

impl SPathOptions {
    #[must_use]
    pub fn level_default() -> Self {
        Self::builder(ENV_PATH_BEHAVIOR)
            .add(ENV_PATH_ADD_LIST_SLICE)
            .sub(ENV_PATH_REMOVE_LIST_SLICE)
            .build()
    }
}

impl EnvKey {
    /// # Errors
    /// Returns an error if the provided string is not a valid environment variable name
    /// or a valid regex (if regex support is enabled).
    pub fn new(s: String) -> Result<Self, String> {
        //debug!("Creating env key: {}", s);
        if is_valid_env_name(&s) {
            Ok(Self {
                env_type: EnvKeyType::Normal,
                value: s,
            })
        } else if is_valid_env_pattern(&s) {
            Ok(Self {
                env_type: EnvKeyType::Wildcarded,
                value: s,
            })
        } else {
            Err(format!(
                "env key {s}, must be a variable name, where `*` matches any characters"
            ))
        }
    }
}

impl PartialEq<str> for EnvKey {
    fn eq(&self, other: &str) -> bool {
        self.value == *other
    }
}

impl From<EnvKey> for String {
    fn from(val: EnvKey) -> Self {
        val.value
    }
}

impl From<String> for EnvKey {
    fn from(s: String) -> Self {
        Self::new(s).expect("Invalid env key")
    }
}

impl From<&str> for EnvKey {
    fn from(s: &str) -> Self {
        Self::new(s.into()).expect("Invalid env key")
    }
}

impl<'de> Deserialize<'de> for EnvKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

impl PathLevel for SPathOptions {
    fn behavior(&self) -> PathBehavior {
        self.default_behavior
    }
    fn add(&self) -> Option<impl Iterator<Item = &str>> {
        self.add.as_ref().map(|l| l.iter().map(String::as_str))
    }
    fn sub(&self) -> Option<impl Iterator<Item = &str>> {
        self.sub.as_ref().map(|l| l.iter().map(String::as_str))
    }
}

impl EnvLevel for SEnvOptions {
    fn behavior(&self) -> EnvBehavior {
        self.default_behavior
    }
    fn keep(&self) -> Option<impl Iterator<Item = &str>> {
        self.keep
            .as_ref()
            .map(|l| l.iter().map(|k| k.value.as_str()))
    }
    fn check(&self) -> Option<impl Iterator<Item = &str>> {
        self.check
            .as_ref()
            .map(|l| l.iter().map(|k| k.value.as_str()))
    }
    fn delete(&self) -> Option<impl Iterator<Item = &str>> {
        self.delete
            .as_ref()
            .map(|l| l.iter().map(|k| k.value.as_str()))
    }
    fn set(&self) -> Option<impl Iterator<Item = (&str, &str)>> {
        self.set
            .as_ref()
            .map(|s| s.iter().map(|(k, v)| (k.as_str(), v.as_str())))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConstParseError(pub &'static str);
use std::fmt::{self, Display};

impl Display for ConstParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "Failed to parse the const {} defined in .cargo/config.toml",
            self.0
        ))
    }
}

impl PathBehavior {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``PathBehavior`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if eq_str(input, "delete") => Self::Delete,
            _ if eq_str(input, "keep-safe")
                || eq_str(input, "keep_safe")
                || eq_str(input, "keepsafe") =>
            {
                Self::KeepSafe
            }
            _ if eq_str(input, "keep-unsafe")
                || eq_str(input, "keep_unsafe")
                || eq_str(input, "keepunsafe") =>
            {
                Self::KeepUnsafe
            }
            _ if eq_str(input, "inherit") => Self::Inherit,
            _ => panic!("fail to parse PathBehavior"),
        }
    }
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

impl TimestampType {
    #[must_use]
    /// # Panics
    /// Panics if the input string does not match any of the valid ``TimestampType`` variants.
    pub const fn const_parse(input: &str) -> Self {
        match input {
            _ if eq_str(input, "ppid") => Self::PPID,
            _ if eq_str(input, "tty") => Self::TTY,
            _ if eq_str(input, "uid") => Self::UID,
            _ => panic!("fail to parse TimestampType"),
        }
    }
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

// === Defaults based on config.toml ===
impl Default for Opt {
    fn default() -> Self {
        Self {
            level: Level::None,
            ..Self::level_default()
        }
    }
}

#[allow(dead_code)] //Maybe used for other binaries
#[derive(Debug, Clone)]
pub struct OptStack {
    pub(crate) stack: [Option<Rc<RefCell<Opt>>>; 5],
    roles: Option<Rc<RefCell<SPolicy>>>,
    role: Option<Rc<RefCell<SRole>>>,
    task: Option<Rc<RefCell<STask>>>,
}

#[cfg(not(tarpaulin_include))]
impl<S: opt_stack_builder::State> OptStackBuilder<S> {
    fn opt(mut self, opt: Option<Rc<RefCell<Opt>>>) -> Self {
        if let Some(opt) = opt {
            self.stack[opt.as_ref().borrow().level as usize] = Some(opt.clone());
        }
        self
    }
    fn with_task(
        self,
        task: &Rc<RefCell<STask>>,
    ) -> OptStackBuilder<
        opt_stack_builder::SetTask<opt_stack_builder::SetRole<opt_stack_builder::SetRoles<S>>>,
    >
    where
        <S as opt_stack_builder::State>::Roles: opt_stack_builder::IsUnset,
        <S as opt_stack_builder::State>::Role: opt_stack_builder::IsUnset,
        <S as opt_stack_builder::State>::Task: opt_stack_builder::IsUnset,
    {
        self.with_role(
            &task
                .as_ref()
                .borrow()
                .role
                .as_ref()
                .expect("task must belong to a role")
                .upgrade()
                .expect("role should not be dropped before task"),
        )
        .task(task.clone())
        .opt(task.as_ref().borrow().options.clone())
    }
    fn with_role(
        self,
        role: &Rc<RefCell<SRole>>,
    ) -> OptStackBuilder<opt_stack_builder::SetRole<opt_stack_builder::SetRoles<S>>>
    where
        <S as opt_stack_builder::State>::Roles: opt_stack_builder::IsUnset,
        <S as opt_stack_builder::State>::Role: opt_stack_builder::IsUnset,
    {
        self.with_roles(
            &role
                .as_ref()
                .borrow()
                .config
                .as_ref()
                .expect("role must belong to a config")
                .upgrade()
                .expect("config should not be dropped before role"),
        )
        .role(role.clone())
        .opt(role.as_ref().borrow().options.clone())
    }

    fn with_roles(
        self,
        roles: &Rc<RefCell<SPolicy>>,
    ) -> OptStackBuilder<opt_stack_builder::SetRoles<S>>
    where
        <S as opt_stack_builder::State>::Roles: opt_stack_builder::IsUnset,
    {
        self.with_default()
            .roles(roles.clone())
            .opt(roles.as_ref().borrow().options.clone())
    }

    fn with_default(self) -> Self {
        self.opt(Some(rc_refcell!(Opt::level_default())))
    }
}

#[bon]
impl OptStack {
    #[builder]
    pub const fn new(
        #[builder(field)] stack: [Option<Rc<RefCell<Opt>>>; 5],
        roles: Option<Rc<RefCell<SPolicy>>>,
        role: Option<Rc<RefCell<SRole>>>,
        task: Option<Rc<RefCell<STask>>>,
    ) -> Self {
        Self {
            stack,
            roles,
            role,
            task,
        }
    }
    pub fn from_task(task: &Rc<RefCell<STask>>) -> Self {
        Self::builder().with_task(task).build()
    }
    pub fn from_role(role: &Rc<RefCell<SRole>>) -> Self {
        Self::builder().with_role(role).build()
    }
    pub fn from_roles(roles: &Rc<RefCell<SPolicy>>) -> Self {
        Self::builder().with_roles(roles).build()
    }

    fn find_in_options<F: Fn(&Opt) -> Option<(Level, V)>, V>(&self, f: F) -> Option<(Level, V)> {
        for opt in self.stack.iter().rev() {
            if let Some(opt) = opt.to_owned() {
                let res = f(&opt.as_ref().borrow());
                if let Some((lvl, _)) = res {
                    debug!("res: {lvl:?}");
                    return res;
                }
            }
        }
        None
    }

    /// The path options of the stack, resolved like dosr does (see [`super::path`]).
    fn get_final_path(&self) -> SPathOptions {
        let levels: Vec<_> = self
            .stack
            .iter()
            .flatten()
            .map(|opt| opt.as_ref().borrow())
            .collect();
        let mut path = ResolvedPath::default();
        for level in levels.iter().filter_map(|level| level.path.as_ref()) {
            path.apply(level);
        }
        SPathOptions::builder(path.behavior)
            .add(path.add.iter())
            .sub(path.sub.iter())
            .build()
    }

    /// The env options of the stack, resolved like dosr does (see [`super::env`]).
    fn get_final_env(&self, cmd_filter: Option<&FilterMatcher>) -> Result<SEnvOptions, String> {
        let levels: Vec<_> = self
            .stack
            .iter()
            .flatten()
            .map(|opt| opt.as_ref().borrow())
            .collect();
        let mut env = ResolvedEnv::default();
        for level in levels.iter().filter_map(|level| level.env.as_ref()) {
            env.apply(level);
        }
        let override_allowed = levels
            .iter()
            .rev()
            .find_map(|level| level.env.as_ref().and_then(|env| env.override_behavior))
            .unwrap_or(ENV_OVERRIDE_BEHAVIOR);
        let env = env.with_requested_behavior(
            cmd_filter.and_then(|filter| filter.env_behavior),
            override_allowed,
        );
        let builder = SEnvOptions::builder(env.behavior)
            .set(env.set.iter().map(|(key, value)| (*key, *value)))
            .keep(env.keep.iter().copied())
            .map_err(|err| format!("Failed to set env keep list: {err}"))?
            .check(env.check.iter().copied())
            .map_err(|err| format!("Failed to set env check list: {err}"))?
            .delete(env.delete.iter().copied())
            .map_err(|err| format!("Failed to set env delete list: {err}"))?;
        Ok(builder.build())
    }

    fn get_level(&self) -> Level {
        let (level, ()) = self
            .find_in_options(|opt| Some((opt.level, ())))
            .unwrap_or((Level::None, ()));
        level
    }

    /// # Errors
    /// Returns an error if any environment option builder step fails.
    pub fn to_opt(&self) -> Result<Rc<RefCell<Opt>>, String> {
        Ok(rc_refcell!(
            Opt::builder(self.get_level())
                .path(self.get_final_path())
                .env(self.get_final_env(None)?)
                .maybe_root(
                    self.find_in_options(|opt| opt.root.map(|root| (opt.level, root)))
                        .map(|(_, root)| root),
                )
                .maybe_bounding(
                    self.find_in_options(|opt| opt.bounding.map(|bounding| (opt.level, bounding)))
                        .map(|(_, bounding)| bounding),
                )
                .maybe_authentication(
                    self.find_in_options(|opt| {
                        opt.authentication
                            .map(|authentication| (opt.level, authentication))
                    })
                    .map(|(_, authentication)| authentication),
                )
                .maybe_timeout(
                    self.find_in_options(|opt| opt
                        .timeout
                        .clone()
                        .map(|timeout| (opt.level, timeout)))
                        .map(|(_, timeout)| timeout),
                )
                .password(
                    SPassword::builder()
                        .maybe_tries(
                            self.find_in_options(|opt| opt
                                .password
                                .as_ref()
                                .and_then(|password| password.tries)
                                .map(|tries| (opt.level, tries)))
                                .map(|(_, tries)| tries)
                        )
                        .maybe_delay(
                            self.find_in_options(|opt| opt
                                .password
                                .as_ref()
                                .and_then(|password| password.delay)
                                .map(|delay| (opt.level, delay)))
                                .map(|(_, delay)| delay)
                        )
                        .build(),
                )
                .build()
        ))
    }
}

#[cfg(test)]
mod tests {

    use jiff::SignedDuration;
    use serde_test::Token;
    use serde_test::assert_de_tokens;
    use serde_test::assert_de_tokens_error;
    use serde_test::assert_tokens;

    use super::super::options::*;
    use super::super::structs::*;

    fn env_key_set_equal<'a, I, J>(a: I, b: J) -> bool
    where
        I: IntoIterator<Item = &'a EnvKey>,
        J: IntoIterator<Item = &'a EnvKey>,
    {
        let mut a_vec: Vec<_> = a.into_iter().collect();
        let mut b_vec: Vec<_> = b.into_iter().collect();
        a_vec.sort_by(|a, b| a.value.cmp(&b.value));
        b_vec.sort_by(|a, b| a.value.cmp(&b.value));
        a_vec == b_vec
    }

    fn hashset_vec_equal<I, J>(a: I, b: J) -> bool
    where
        I: IntoIterator,
        I::Item: Into<String>,
        J: IntoIterator,
        J::Item: Into<String>,
    {
        let mut a_vec: Vec<String> = a.into_iter().map(Into::into).collect();
        let mut b_vec: Vec<String> = b.into_iter().map(Into::into).collect();
        a_vec.sort();
        b_vec.sort();
        a_vec == b_vec
    }

    #[test]
    fn test_find_in_options() {
        let config = SPolicy::builder()
            .role(
                SRole::builder("test")
                    .options(|opt| {
                        opt.path(
                            SPathOptions::builder(PathBehavior::Inherit)
                                .add(["path2"])
                                .build(),
                        )
                        .build()
                    })
                    .build(),
            )
            .options(|opt| {
                opt.path(
                    SPathOptions::builder(PathBehavior::Delete)
                        .add(["path1"])
                        .build(),
                )
                .build()
            })
            .build();
        let options = OptStack::from_role(&config.as_ref().borrow().roles[0].clone());
        let res: Option<(Level, SPathOptions)> =
            options.find_in_options(|opt| opt.path.clone().map(|value| (opt.level, value)));
        assert_eq!(
            res,
            Some((
                Level::Role,
                SPathOptions::builder(PathBehavior::Inherit)
                    .add(["path2"])
                    .build()
            ))
        );
    }

    #[test]
    fn test_env_global_to_task() {
        let config = SPolicy::builder()
            .role(
                SRole::builder("test")
                    .task(
                        STask::builder(1)
                            .options(|opt| {
                                opt.env(
                                    SEnvOptions::builder(EnvBehavior::Delete)
                                        .keep(["env1"])
                                        .unwrap()
                                        .build(),
                                )
                                .build()
                            })
                            .build(),
                    )
                    .options(|opt| {
                        opt.env(
                            SEnvOptions::builder(EnvBehavior::Delete)
                                .keep(["env2"])
                                .unwrap()
                                .build(),
                        )
                        .build()
                    })
                    .build(),
            )
            .options(|opt| {
                opt.env(
                    SEnvOptions::builder(EnvBehavior::Delete)
                        .keep(["env3"])
                        .unwrap()
                        .build(),
                )
                .build()
            })
            .build();
        let binding = OptStack::from_task(&config.task("test", 1).unwrap())
            .to_opt()
            .expect("Failed to build task options");
        let options = binding.as_ref().borrow();
        let res = &options.env.as_ref().unwrap().keep;
        assert!(
            res.as_ref()
                .into_iter()
                .flatten()
                .any(|x| x == &EnvKey::from("env1"))
        );
    }

    #[test]
    fn test_env_undefined_lists_are_inherited() {
        let task_env = |env: SEnvOptions| {
            SPolicy::builder()
                .role(
                    SRole::builder("test")
                        .task(
                            STask::builder(1)
                                .options(|opt| opt.env(env.clone()).build())
                                .build(),
                        )
                        .build(),
                )
                .options(|opt| {
                    opt.env(
                        SEnvOptions::builder(EnvBehavior::Delete)
                            .keep(["KEEPME"])
                            .unwrap()
                            .check(["CHECKME"])
                            .unwrap()
                            .delete(["LD_*"])
                            .unwrap()
                            .build(),
                    )
                    .build()
                })
                .build()
        };
        let final_env = |config: &Rc<RefCell<SPolicy>>| {
            let opt = OptStack::from_task(&config.task("test", 1).unwrap())
                .to_opt()
                .expect("Failed to build task options");
            opt.as_ref().borrow().env.clone().unwrap()
        };
        let names = |list: &Option<IndexSet<EnvKey>>| {
            let mut names: Vec<String> = list.iter().flatten().map(ToString::to_string).collect();
            names.sort();
            names
        };
        // a task that switches to keep mode without restating its lists inherits them
        let env = final_env(&task_env(SEnvOptions::builder(EnvBehavior::Keep).build()));
        assert_eq!(env.default_behavior, EnvBehavior::Keep);
        assert_eq!(names(&env.delete), ["LD_*"]);
        assert_eq!(names(&env.check), ["CHECKME"]);
        assert_eq!(names(&env.keep), ["KEEPME"]);
        // a defined list replaces the inherited one, only an empty list removes it
        let env = final_env(&task_env(
            SEnvOptions::builder(EnvBehavior::Keep)
                .delete(Vec::<&str>::new())
                .unwrap()
                .check(["OTHER"])
                .unwrap()
                .build(),
        ));
        assert!(names(&env.delete).is_empty());
        assert_eq!(names(&env.check), ["OTHER"]);
    }

    // test to_opt() for OptStack
    #[allow(clippy::too_many_lines)]
    #[test]
    fn test_to_opt() {
        let config = SPolicy::builder()
            .role(
                SRole::builder("test")
                    .task(
                        STask::builder(1)
                            .options(|opt| {
                                opt.path(
                                    SPathOptions::builder(PathBehavior::Inherit)
                                        .add(["path3"])
                                        .build(),
                                )
                                .env(
                                    SEnvOptions::builder(EnvBehavior::Inherit)
                                        .keep(["env3"])
                                        .unwrap()
                                        .build(),
                                )
                                .root(SPrivileged::User)
                                .bounding(SBounding::Strict)
                                .authentication(SAuthentication::Perform)
                                .timeout(
                                    STimeout::builder()
                                        .type_field(TimestampType::TTY)
                                        .duration(SignedDuration::from_mins(3))
                                        .build(),
                                )
                                .build()
                            })
                            .build(),
                    )
                    .options(|opt| {
                        opt.path(
                            SPathOptions::builder(PathBehavior::Inherit)
                                .add(["path2"])
                                .build(),
                        )
                        .env(
                            SEnvOptions::builder(EnvBehavior::Delete)
                                .keep(["env1"])
                                .unwrap()
                                .build(),
                        )
                        .root(SPrivileged::Privileged)
                        .bounding(SBounding::Strict)
                        .authentication(SAuthentication::Skip)
                        .timeout(
                            STimeout::builder()
                                .type_field(TimestampType::PPID)
                                .duration(SignedDuration::from_mins(2))
                                .build(),
                        )
                        .build()
                    })
                    .build(),
            )
            .options(|opt| {
                opt.path(
                    SPathOptions::builder(PathBehavior::Delete)
                        .add(["path1"])
                        .build(),
                )
                .env(
                    SEnvOptions::builder(EnvBehavior::Delete)
                        .keep(["env2"])
                        .unwrap()
                        .build(),
                )
                .root(SPrivileged::Privileged)
                .bounding(SBounding::Ignore)
                .authentication(SAuthentication::Perform)
                .timeout(
                    STimeout::builder()
                        .type_field(TimestampType::TTY)
                        .duration(SignedDuration::from_mins(1))
                        .build(),
                )
                .build()
            })
            .build();
        let default = IndexSet::new();
        let stack = OptStack::from_roles(&config);
        let opt = stack.to_opt().expect("Failed to build global options");
        let global_options = opt.as_ref().borrow();
        assert_eq!(
            global_options.path.as_ref().unwrap().default_behavior,
            PathBehavior::Delete
        );
        assert!(hashset_vec_equal(
            global_options
                .path
                .as_ref()
                .unwrap()
                .add
                .as_ref()
                .unwrap_or(&default)
                .clone(),
            vec!["path1"]
        ));
        assert_eq!(
            global_options.env.as_ref().unwrap().default_behavior,
            EnvBehavior::Delete
        );
        assert!(env_key_set_equal(
            global_options
                .env
                .as_ref()
                .unwrap()
                .keep
                .as_ref()
                .into_iter()
                .flatten()
                .clone(),
            vec![&EnvKey::from("env2")]
        ));
        assert_eq!(
            global_options
                .env
                .as_ref()
                .unwrap()
                .keep
                .as_ref()
                .into_iter()
                .flatten()
                .map(|e| e.clone().into())
                .collect::<Vec<String>>(),
            vec!["env2".to_string()]
        );
        assert_eq!(global_options.root.unwrap(), SPrivileged::Privileged);
        assert_eq!(global_options.bounding.unwrap(), SBounding::Ignore);
        assert_eq!(
            global_options.authentication.unwrap(),
            SAuthentication::Perform
        );
        assert_eq!(
            global_options.timeout.as_ref().unwrap().duration.unwrap(),
            SignedDuration::from_mins(1)
        );
        assert_eq!(
            global_options.timeout.as_ref().unwrap().type_field.unwrap(),
            TimestampType::TTY
        );
        let opt = OptStack::from_role(&config.role("test").unwrap())
            .to_opt()
            .expect("Failed to build role options");
        let role_options = opt.as_ref().borrow();
        assert_eq!(
            role_options.path.as_ref().unwrap().default_behavior,
            PathBehavior::Delete
        );
        assert!(hashset_vec_equal(
            role_options
                .path
                .as_ref()
                .unwrap()
                .add
                .as_ref()
                .unwrap_or(&default)
                .clone(),
            vec!["path1", "path2"]
        ));
        assert_eq!(
            role_options.env.as_ref().unwrap().default_behavior,
            EnvBehavior::Delete
        );
        assert!(env_key_set_equal(
            role_options
                .env
                .as_ref()
                .unwrap()
                .keep
                .as_ref()
                .into_iter()
                .flatten()
                .clone(),
            vec![&EnvKey::from("env1")]
        ));
        assert_eq!(role_options.root.unwrap(), SPrivileged::Privileged);
        assert_eq!(role_options.bounding.unwrap(), SBounding::Strict);
        assert_eq!(role_options.authentication.unwrap(), SAuthentication::Skip);
        assert_eq!(
            role_options.timeout.as_ref().unwrap().duration.unwrap(),
            SignedDuration::from_mins(2)
        );
        assert_eq!(
            role_options.timeout.as_ref().unwrap().type_field.unwrap(),
            TimestampType::PPID
        );
        let opt = OptStack::from_task(&config.task("test", 1).unwrap())
            .to_opt()
            .expect("Failed to build task options");
        let task_options = opt.as_ref().borrow();
        assert_eq!(
            task_options.path.as_ref().unwrap().default_behavior,
            PathBehavior::Delete
        );
        assert!(hashset_vec_equal(
            task_options
                .path
                .as_ref()
                .unwrap()
                .add
                .as_ref()
                .unwrap_or(&default)
                .clone(),
            vec!["path1", "path2", "path3"]
        ));
        assert_eq!(
            task_options.env.as_ref().unwrap().default_behavior,
            EnvBehavior::Delete
        );
        assert!(env_key_set_equal(
            task_options
                .env
                .as_ref()
                .unwrap()
                .keep
                .as_ref()
                .into_iter()
                .flatten()
                .clone(),
            vec![&EnvKey::from("env1"), &EnvKey::from("env3")]
        ));
        assert_eq!(task_options.root.unwrap(), SPrivileged::User);
        assert_eq!(task_options.bounding.unwrap(), SBounding::Strict);
        assert_eq!(
            task_options.authentication.unwrap(),
            SAuthentication::Perform
        );
        assert_eq!(
            task_options.timeout.as_ref().unwrap().duration.unwrap(),
            SignedDuration::from_mins(3)
        );
        assert_eq!(
            task_options.timeout.as_ref().unwrap().type_field.unwrap(),
            TimestampType::TTY
        );
    }

    #[test]
    fn is_wildcard_env_key() {
        assert!(!is_valid_env_name("TEST_*"));
        assert!(!is_valid_env_name("123"));
        assert!(!is_valid_env_name(""));
        assert!(is_valid_env_pattern("TEST_*"));
        // regexes are not patterns anymore
        assert!(!is_valid_env_pattern("TEST_.*"));
        assert!(EnvKey::new("TEST_.*".to_string()).is_err());
        let key = EnvKey::new("LC_*".to_string()).unwrap();
        assert_eq!(key.env_type, EnvKeyType::Wildcarded);
    }

    #[test]
    fn test_get_final_env_set_inherit() {
        let config = SPolicy::builder()
            .role(
                SRole::builder("test")
                    .task(
                        STask::builder(1)
                            .options(|opt| {
                                opt.env(
                                    SEnvOptions::builder(EnvBehavior::Inherit)
                                        .set([("env1", "value3")])
                                        .build(),
                                )
                                .build()
                            })
                            .build(),
                    )
                    .options(|opt| {
                        opt.env(
                            SEnvOptions::builder(EnvBehavior::Inherit)
                                .set([("env2", "value2")])
                                .build(),
                        )
                        .build()
                    })
                    .build(),
            )
            .options(|opt| {
                opt.env(
                    SEnvOptions::builder(EnvBehavior::Delete)
                        .set([("env1", "value1")])
                        .build(),
                )
                .build()
            })
            .build();
        let stack = OptStack::from_task(&config.task("test", 1).unwrap());
        let opt = stack.to_opt().expect("Failed to build task options");
        let options = opt.as_ref().borrow();
        assert_eq!(
            options
                .env
                .as_ref()
                .unwrap()
                .set
                .as_ref()
                .into_iter()
                .flatten()
                .find_map(|(key, v)| if key == "env1" { Some(v) } else { None })
                .unwrap(),
            "value3"
        );
    }

    #[test]
    fn test_get_final_path_inherit() {
        let config = SPolicy::builder()
            .role(
                SRole::builder("test")
                    .task(
                        STask::builder(1)
                            .options(|opt| {
                                opt.path(
                                    SPathOptions::builder(PathBehavior::Inherit)
                                        .sub(["/path3"])
                                        .build(),
                                )
                                .build()
                            })
                            .build(),
                    )
                    .options(|opt| {
                        opt.path(
                            SPathOptions::builder(PathBehavior::Inherit)
                                .sub(["/path2"])
                                .build(),
                        )
                        .build()
                    })
                    .build(),
            )
            .options(|opt| {
                opt.path(
                    SPathOptions::builder(PathBehavior::KeepSafe)
                        .sub(["/path1"])
                        .build(),
                )
                .build()
            })
            .build();
        let stack = OptStack::from_task(&config.task("test", 1).unwrap());
        let opt = stack.to_opt().expect("Failed to build task options");
        let options = opt.as_ref().borrow();
        assert!(
            options
                .path
                .as_ref()
                .unwrap()
                .sub
                .as_ref()
                .unwrap()
                .contains("/path1")
        );
        assert!(
            options
                .path
                .as_ref()
                .unwrap()
                .sub
                .as_ref()
                .unwrap()
                .contains("/path2")
        );
        assert!(
            options
                .path
                .as_ref()
                .unwrap()
                .sub
                .as_ref()
                .unwrap()
                .contains("/path3")
        );
    }

    #[test]
    fn test_find_in_options_none() {
        let config = SPolicy::builder()
            .role(
                SRole::builder("test")
                    .task(STask::builder(1).build())
                    .build(),
            )
            .build();
        let stack = OptStack::from_task(&config.task("test", 1).unwrap());
        let res: Option<(Level, SPathOptions)> = stack.find_in_options(|_| None);
        assert_eq!(res, None);
    }

    #[test]
    fn test_invalid_envkey() {
        let invalid_env = "3TE(ST_a";
        let env_key = EnvKey::new(invalid_env.to_string());
        assert!(env_key.is_err());
        assert_eq!(
            env_key.unwrap_err(),
            format!(
                "env key {invalid_env}, must be a variable name, where `*` matches any characters"
            )
        );
    }

    #[test]
    fn test_envkey_parsing_and_display() {
        let env_key = EnvKey::new("TEST_VALUE".to_string()).expect("valid environment key");
        assert_eq!(env_key.to_string(), "TEST_VALUE");
        assert_eq!(EnvKey::from("TEST_VALUE"), env_key);
        assert_eq!(String::from(env_key), "TEST_VALUE");
    }

    #[test]
    fn test_path_behavior_spellings() {
        // written like in chsr, every spelling read: 4.0 policies and build settings
        assert_eq!(
            serde_json::to_value(PathBehavior::KeepSafe).unwrap(),
            serde_json::json!("keep-safe")
        );
        assert_eq!(
            serde_json::to_value(PathBehavior::KeepUnsafe).unwrap(),
            serde_json::json!("keep-unsafe")
        );
        for (spellings, behavior) in [
            (
                ["keep-safe", "keepsafe", "keep_safe"],
                PathBehavior::KeepSafe,
            ),
            (
                ["keep-unsafe", "keepunsafe", "keep_unsafe"],
                PathBehavior::KeepUnsafe,
            ),
        ] {
            for spelling in spellings {
                assert_eq!(
                    serde_json::from_value::<PathBehavior>(serde_json::json!(spelling)).unwrap(),
                    behavior,
                    "{spelling}"
                );
                assert_eq!(PathBehavior::const_parse(spelling), behavior, "{spelling}");
            }
        }
    }

    #[test]
    fn test_const_parse_helpers() {
        assert_eq!(PathBehavior::const_parse("delete"), PathBehavior::Delete);
        assert_eq!(
            PathBehavior::const_parse("keep_safe"),
            PathBehavior::KeepSafe
        );
        assert_eq!(EnvBehavior::const_parse("keep"), EnvBehavior::Keep);
        assert_eq!(SPrivileged::const_parse("user"), SPrivileged::User);
        assert_eq!(SInfo::const_parse("show"), SInfo::Show);
        assert_eq!(TimestampType::const_parse("tty"), TimestampType::TTY);
        assert_eq!(SBounding::const_parse("strict"), SBounding::Strict);
        assert_eq!(SAuthentication::const_parse("skip"), SAuthentication::Skip);
    }

    #[test]
    fn test_sumask_from_u16() {
        let umask = SUMask::from(0o755);
        assert_eq!(umask.0, 0o755);
    }

    #[test]
    fn test_u16_from_sumask() {
        let umask = SUMask(0o644);
        let value: u16 = umask.into();
        assert_eq!(value, 0o644);
    }

    #[test]
    fn test_mode_from_sumask() {
        let umask = SUMask(0o22);
        let mode: Mode = umask.into();
        assert_eq!(mode, Mode::from_bits_truncate(0o22));
    }

    #[test]
    fn test_sumask_serde_standard_umask() {
        let umask = SUMask(0o22);
        assert_tokens(&umask, &[Token::Str("022")]);
    }

    #[test]
    fn test_sumask_serde_three_digits() {
        let umask = SUMask(0o755);
        assert_tokens(&umask, &[Token::Str("755")]);
    }

    #[test]
    fn test_sumask_serde_single_digit() {
        let umask = SUMask(0o7);
        assert_tokens(&umask, &[Token::Str("007")]);
    }

    #[test]
    fn test_sumask_serde_zero() {
        let umask = SUMask(0);
        assert_tokens(&umask, &[Token::Str("000")]);
    }

    #[test]
    fn test_sumask_serde_max_value() {
        let umask = SUMask(0o777);
        assert_tokens(&umask, &[Token::Str("777")]);
    }

    #[test]
    fn test_sumask_deserialize_various_formats() {
        // Test single digit
        assert_de_tokens(&SUMask(0o7), &[Token::Str("7")]);

        // Test two digits
        assert_de_tokens(&SUMask(0o22), &[Token::Str("22")]);

        // Test three digits with leading zeros
        assert_de_tokens(&SUMask(0o022), &[Token::Str("022")]);

        // Test four digit octal (though unusual for umask)
        assert_de_tokens(&SUMask(0o1755), &[Token::Str("1755")]);
    }

    #[test]
    fn test_sumask_deserialize_invalid_octal() {
        // Test invalid octal digit
        assert_de_tokens_error::<SUMask>(&[Token::Str("888")], "invalid digit found in string");

        // Test mixed valid/invalid
        assert_de_tokens_error::<SUMask>(&[Token::Str("729")], "invalid digit found in string");
    }

    #[test]
    fn test_sumask_deserialize_invalid_format() {
        // Test non-numeric string
        assert_de_tokens_error::<SUMask>(&[Token::Str("abc")], "invalid digit found in string");

        // Test empty string
        assert_de_tokens_error::<SUMask>(
            &[Token::Str("")],
            "cannot parse integer from empty string",
        );

        // Test string with spaces
        assert_de_tokens_error::<SUMask>(&[Token::Str(" 22")], "invalid digit found in string");

        // Test hexadecimal format (should fail)
        assert_de_tokens_error::<SUMask>(&[Token::Str("0x22")], "invalid digit found in string");
    }

    #[test]
    fn test_sumask_partial_eq() {
        let umask1 = SUMask(0o22);
        let umask2 = SUMask(0o22);
        let umask3 = SUMask(0o755);

        assert_eq!(umask1, umask2);
        assert_ne!(umask1, umask3);
    }

    #[test]
    fn test_sumask_debug() {
        let umask = SUMask(0o22);
        let debug_str = format!("{umask:?}");
        assert_eq!(debug_str, "SUMask(18)"); // 0o22 = 18 in decimal
    }

    #[test]
    fn test_sumask_common_umask_values() {
        // Test common umask values
        assert_tokens(&SUMask(0o022), &[Token::Str("022")]); // Default
        assert_tokens(&SUMask(0o002), &[Token::Str("002")]); // Group writable
        assert_tokens(&SUMask(0o077), &[Token::Str("077")]); // Private
        assert_tokens(&SUMask(0o000), &[Token::Str("000")]); // No restrictions
        assert_tokens(&SUMask(0o027), &[Token::Str("027")]); // Group readable
    }

    #[test]
    fn test_sumask_transparent_serde() {
        // Test that the struct is truly transparent in serialization
        // The tokens should be exactly the same as if we serialized the inner u16 with our custom functions
        let umask = SUMask(0o644);

        // This should serialize as just a string, not as a struct
        assert_tokens(&umask, &[Token::Str("644")]);
    }

    #[test]
    fn test_password_option() {
        let password: SPassword =
            serde_json::from_str(r#"{"tries": 2, "delay": "00:00:01"}"#).unwrap();
        assert_eq!(password.tries, std::num::NonZeroU8::new(2));
        assert_eq!(password.delay, Some(SignedDuration::from_secs(1)));
        assert_eq!(
            serde_json::to_value(&password).unwrap(),
            serde_json::json!({"tries": 2, "delay": "00:00:01"})
        );
        // 0 tries would never let anyone in, or never stop asking; a delay is never negative
        for invalid in [
            r#"{"tries": 0}"#,
            r#"{"tries": 256}"#,
            r#"{"tries": -1}"#,
            r#"{"delay": "-00:00:01"}"#,
            r#"{"delay": "5s"}"#,
        ] {
            assert!(
                serde_json::from_str::<SPassword>(invalid).is_err(),
                "{invalid} is refused"
            );
        }
        let cbor = cbor4ii::serde::to_vec(Vec::new(), &password).unwrap();
        let from_cbor: SPassword = cbor4ii::serde::from_slice(&cbor).unwrap();
        assert_eq!(from_cbor, password);
    }

    #[test]
    fn test_password_defaults() {
        let defaults = Opt::level_default().password.unwrap();
        assert_eq!(defaults.tries, Some(crate::util::PASSWORD_TRIES));
        assert_eq!(defaults.delay, Some(crate::util::PASSWORD_DELAY));
        assert_eq!(crate::util::PASSWORD_TRIES.get(), 3);
        assert_eq!(crate::util::PASSWORD_DELAY, SignedDuration::from_secs(5));
    }
}
