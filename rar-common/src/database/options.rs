use std::collections::HashMap;
#[cfg(feature = "finder")]
use std::path::PathBuf;
use std::{borrow::Borrow, cell::RefCell, rc::Rc};

use chrono::Duration;

#[cfg(feature = "finder")]
use libc::PATH_MAX;
use linked_hash_set::LinkedHashSet;

#[cfg(feature = "pcre2")]
use pcre2::bytes::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use strum::{Display, EnumIs, EnumIter, FromRepr};

use tracing::debug;
#[cfg(feature = "finder")]
use tracing::warn;

use crate::rc_refcell;

#[cfg(feature = "finder")]
use super::finder::Cred;
use super::{deserialize_duration, is_default, serialize_duration};

use super::{
    lhs_deserialize, lhs_deserialize_envkey, lhs_serialize, lhs_serialize_envkey,
    structs::{SConfig, SRole, STask},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Level {
    None,
    #[default]
    Default,
    Global,
    Role,
    Task,
}

#[derive(Debug, Clone, Copy, FromRepr, EnumIter, Display)]
pub enum OptType {
    Path,
    Env,
    Root,
    Bounding,
    Wildcard,
    Timeout,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PathBehavior {
    Delete,
    KeepSafe,
    KeepUnsafe,
    #[default]
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone, Copy, Display)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TimestampType {
    #[default]
    PPID,
    TTY,
    UID,
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
    #[serde(flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct SPathOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    pub default_behavior: PathBehavior,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize"
    )]
    pub add: LinkedHashSet<String>,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize"
    )]
    pub sub: LinkedHashSet<String>,
    #[serde(default)]
    #[serde(flatten)]
    pub _extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum EnvBehavior {
    Delete,
    Keep,
    #[default]
    Inherit,
}

#[derive(Serialize, Hash, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
enum EnvKeyType {
    Wildcarded,
    Normal,
}

#[derive(Eq, Hash, PartialEq, Serialize, Debug, Clone)]
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct SEnvOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    pub default_behavior: EnvBehavior,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub set: HashMap<String, String>,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    pub keep: LinkedHashSet<EnvKey>,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    pub check: LinkedHashSet<EnvKey>,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    pub delete: LinkedHashSet<EnvKey>,
    #[serde(default, flatten)]
    pub _extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SBounding {
    Strict,
    Ignore,
    #[default]
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum SPrivileged {
    Privileged,
    #[default]
    User,
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wildcard_denied: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<STimeout>,
    #[serde(default)]
    #[serde(flatten)]
    pub _extra_fields: Map<String, Value>,
    #[serde(skip)]
    pub level: Level,
}

impl Opt {
    pub fn new(level: Level) -> Self {
        Opt {
            level,
            ..Default::default()
        }
    }

    pub fn level_default() -> Self {
        let mut opt = Self::new(Level::Default);
        opt.root = Some(SPrivileged::User);
        opt.bounding = Some(SBounding::Strict);
        opt.path.as_mut().unwrap().default_behavior = PathBehavior::Delete;
        opt.path.as_mut().unwrap().add = vec![
            "/usr/local/sbin".to_string(),
            "/usr/local/bin".to_string(),
            "/usr/sbin".to_string(),
            "/usr/bin".to_string(),
            "/sbin".to_string(),
            "/bin".to_string(),
            "/snap/bin".to_string(),
        ]
        .into_iter()
        .collect();
        opt.authentication = SAuthentication::Perform.into();
        let mut env = SEnvOptions::new(EnvBehavior::Delete);
        env.keep = vec![
            "HOME".into(),
            "USER".into(),
            "LOGNAME".into(),
            "COLORS".into(),
            "DISPLAY".into(),
            "HOSTNAME".into(),
            "KRB5CCNAME".into(),
            "LS_COLORS".into(),
            "PS1".into(),
            "PS2".into(),
            "XAUTHORY".into(),
            "XAUTHORIZATION".into(),
            "XDG_CURRENT_DESKTOP".into(),
        ]
        .into_iter()
        .collect();
        env.check = vec![
            "COLORTERM".into(),
            "LANG".into(),
            "LANGUAGE".into(),
            "LC_*".into(),
            "LINGUAS".into(),
            "TERM".into(),
            "TZ".into(),
        ]
        .into_iter()
        .collect();
        opt.env = Some(env);
        let timeout = STimeout {
            type_field: Some(TimestampType::PPID),
            duration: Some(Duration::minutes(5)),
            ..Default::default()
        };
        opt.timeout = Some(timeout);
        opt.wildcard_denied = Some(";&|".to_string());
        opt
    }
}

impl Default for Opt {
    fn default() -> Self {
        Opt {
            path: Some(SPathOptions::default()),
            env: Some(SEnvOptions::default()),
            root: Some(SPrivileged::default()),
            bounding: Some(SBounding::default()),
            authentication: None,
            wildcard_denied: None,
            timeout: None,
            _extra_fields: Map::default(),
            level: Level::Default,
        }
    }
}

impl Default for OptStack {
    fn default() -> Self {
        OptStack {
            stack: [
                None,
                Some(Rc::new(Opt::level_default().into())),
                None,
                None,
                None,
            ],
            roles: None,
            role: None,
            task: None,
        }
    }
}

impl Default for SPathOptions {
    fn default() -> Self {
        SPathOptions {
            default_behavior: PathBehavior::Inherit,
            add: LinkedHashSet::new(),
            sub: LinkedHashSet::new(),
            _extra_fields: Map::default(),
        }
    }
}

fn is_valid_env_name(s: &str) -> bool {
    let mut chars = s.chars();

    // Check if the first character is a letter or underscore
    if let Some(first_char) = chars.next() {
        if !(first_char.is_ascii_alphabetic() || first_char == '_') {
            return false;
        }
    } else {
        return false; // Empty string
    }

    // Check if the remaining characters are alphanumeric or underscores
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(feature = "pcre2")]
fn is_regex(s: &str) -> bool {
    Regex::new(s).is_ok()
}

#[cfg(not(feature = "pcre2"))]
fn is_regex(_s: &str) -> bool {
    true // Always return true if regex feature is disabled
}

impl EnvKey {
    pub fn new(s: String) -> Result<Self, String> {
        //debug!("Creating env key: {}", s);
        if is_valid_env_name(&s) {
            Ok(EnvKey {
                env_type: EnvKeyType::Normal,
                value: s,
            })
        } else if is_regex(&s) {
            Ok(EnvKey {
                env_type: EnvKeyType::Wildcarded,
                value: s,
            })
        } else {
            Err(format!(
                "env key {}, must be a valid env, or a valid regex",
                s
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
        EnvKey::new(s).expect("Invalid env key")
    }
}

impl From<&str> for EnvKey {
    fn from(s: &str) -> Self {
        EnvKey::new(s.into()).expect("Invalid env key")
    }
}

impl<'de> Deserialize<'de> for EnvKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        EnvKey::new(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
impl SPathOptions {
    fn new(behavior: PathBehavior) -> Self {
        let mut res = SPathOptions::default();
        res.default_behavior = behavior;
        res
    }
}

impl Default for SEnvOptions {
    fn default() -> Self {
        SEnvOptions {
            default_behavior: EnvBehavior::default(),
            set: HashMap::new(),
            keep: LinkedHashSet::new(),
            check: LinkedHashSet::new(),
            delete: LinkedHashSet::new(),
            _extra_fields: Map::default(),
        }
    }
}

impl SEnvOptions {
    pub fn new(behavior: EnvBehavior) -> Self {
        SEnvOptions {
            default_behavior: behavior,
            ..Default::default()
        }
    }
}

trait EnvSet {
    fn env_matches(&self, wildcarded: &EnvKey) -> bool;
}

impl<T> EnvSet for HashMap<String, T> {
    fn env_matches(&self, wildcarded: &EnvKey) -> bool {
        match wildcarded.env_type {
            EnvKeyType::Normal => self.contains_key(&wildcarded.value),
            EnvKeyType::Wildcarded => self.keys().any(|s| check_wildcarded(wildcarded, s)),
        }
    }
}

impl EnvSet for LinkedHashSet<EnvKey> {
    fn env_matches(&self, wildcarded: &EnvKey) -> bool {
        match wildcarded.env_type {
            EnvKeyType::Normal => self.contains(wildcarded),
            EnvKeyType::Wildcarded => self.iter().any(|s| check_wildcarded(wildcarded, &s.value)),
        }
    }
}

#[cfg(feature = "pcre2")]
fn check_wildcarded(wildcarded: &EnvKey, s: &String) -> bool {
    Regex::new(&format!("^{}$", wildcarded.value)) // convert to regex
        .unwrap()
        .is_match(s.as_bytes())
        .is_ok_and(|m| m)
}

#[cfg(not(feature = "pcre2"))]
fn check_wildcarded(_wildcarded: &EnvKey, _s: &String) -> bool {
    true
}

#[cfg(feature = "finder")]
fn tz_is_safe(tzval: &str) -> bool {
    // tzcode treats a value beginning with a ':' as a path.
    let tzval = if let Some(val) = tzval.strip_prefix(':') {
        val
    } else {
        tzval
    };

    // Reject fully-qualified TZ that doesn't begin with the zoneinfo dir.
    if tzval.starts_with('/') {
        return false;
    }

    // Make sure TZ only contains printable non-space characters
    // and does not contain a '..' path element.
    let mut lastch = '/';
    for cp in tzval.chars() {
        if cp.is_ascii_whitespace() || !cp.is_ascii_graphic() {
            return false;
        }
        if lastch == '/'
            && cp == '.'
            && tzval
                .chars()
                .nth(tzval.chars().position(|c| c == '.').unwrap() + 1)
                == Some('.')
            && (tzval
                .chars()
                .nth(tzval.chars().position(|c| c == '.').unwrap() + 2)
                == Some('/')
                || tzval
                    .chars()
                    .nth(tzval.chars().position(|c| c == '.').unwrap() + 2)
                    .is_none())
        {
            return false;
        }
        lastch = cp;
    }

    // Reject extra long TZ values (even if not a path).
    if tzval.len() >= PATH_MAX.try_into().unwrap() {
        return false;
    }

    true
}

#[cfg(feature = "finder")]
fn check_env(key: &str, value: &str) -> bool {
    debug!("Checking env: {}={}", key, value);
    match key {
        "TZ" => tz_is_safe(value),
        _ => !value.chars().any(|c| c == '/' || c == '%'),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptStack {
    pub(crate) stack: [Option<Rc<RefCell<Opt>>>; 5],
    roles: Option<Rc<RefCell<SConfig>>>,
    role: Option<Rc<RefCell<SRole>>>,
    task: Option<Rc<RefCell<STask>>>,
}

type FinalPath = (
    PathBehavior,
    Rc<RefCell<LinkedHashSet<String>>>,
    Rc<RefCell<LinkedHashSet<String>>>,
);

type FinalEnv = (
    EnvBehavior,
    HashMap<String, String>,
    LinkedHashSet<EnvKey>,
    LinkedHashSet<EnvKey>,
    LinkedHashSet<EnvKey>,
);

impl OptStack {
    pub fn from_task(task: Rc<RefCell<STask>>) -> Self {
        let mut stack = OptStack::from_role(
            task.as_ref()
                .borrow()
                ._role
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap(),
        );
        stack.task = Some(task.to_owned());
        stack.set_opt(Level::Task, task.as_ref().borrow().options.to_owned());
        stack
    }
    pub fn from_role(role: Rc<RefCell<SRole>>) -> Self {
        let mut stack = OptStack::from_roles(
            role.as_ref()
                .borrow()
                ._config
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap(),
        );
        stack.role = Some(role.to_owned());
        stack.set_opt(Level::Role, role.as_ref().borrow().options.to_owned());
        stack
    }
    pub fn from_roles(roles: Rc<RefCell<SConfig>>) -> Self {
        let mut stack = OptStack::new(roles);
        stack.set_opt(
            Level::Global,
            stack
                .get_roles()
                .unwrap()
                .as_ref()
                .borrow()
                .options
                .to_owned(),
        );
        stack
    }

    fn new(roles: Rc<RefCell<SConfig>>) -> OptStack {
        let mut res = OptStack::default();
        let mut opt = Opt {
            level: Level::Global,
            root: Some(SPrivileged::User),
            bounding: Some(SBounding::Strict),
            ..Default::default()
        };
        let mut env = SEnvOptions::new(EnvBehavior::Delete);
        env.check = ["TZ".into(), "LOGNAME".into(), "LOGIN".into(), "USER".into()]
            .iter()
            .cloned()
            .collect();
        opt.env = Some(env);
        opt.path.as_mut().unwrap().default_behavior = PathBehavior::Delete;
        res.set_opt(Level::Global, Some(Rc::new(RefCell::new(opt))));
        res.roles = Some(roles);
        res
    }

    fn get_roles(&self) -> Option<Rc<RefCell<SConfig>>> {
        self.roles.to_owned()
    }

    fn set_opt(&mut self, level: Level, opt: Option<Rc<RefCell<Opt>>>) {
        if let Some(opt) = opt {
            self.stack[level as usize] = Some(opt);
        } else {
            self.stack[level as usize] = Some(Rc::new(Opt::new(level).into()));
        }
    }

    fn find_in_options<F: Fn(&Opt) -> Option<(Level, V)>, V>(&self, f: F) -> Option<(Level, V)> {
        for opt in self.stack.iter().rev() {
            if let Some(opt) = opt.to_owned() {
                let res = f(&opt.as_ref().borrow());
                if res.is_some() {
                    debug!("res: {:?}", res.as_ref().unwrap().0);
                    return res;
                }
            }
        }
        None
    }

    fn iter_in_options<F: FnMut(&Opt)>(&self, mut f: F) {
        for opt in self.stack.iter() {
            if let Some(opt) = opt.to_owned() {
                f(&opt.as_ref().borrow());
            }
        }
    }

    #[cfg(feature = "finder")]
    fn calculate_path(&self) -> String {
        let (final_behavior, final_add, final_sub) = self.get_final_path();
        let final_add = final_add
            .clone()
            .as_ref()
            .borrow()
            .difference(&final_sub.as_ref().borrow())
            .fold("".to_string(), |mut acc, s| {
                if !acc.is_empty() {
                    acc.insert(0, ':');
                }
                acc.insert_str(0, s);
                acc
            });
        match final_behavior {
            PathBehavior::Inherit | PathBehavior::Delete => final_add,
            is_safe => std::env::vars()
                .find_map(|(key, value)| if key == "PATH" { Some(value) } else { None })
                .unwrap_or(String::new())
                .split(':')
                .filter(|s| {
                    !final_sub.as_ref().borrow().contains(*s)
                        && (!is_safe.is_keep_safe() || PathBuf::from(s).exists())
                })
                .fold(final_add, |mut acc, s| {
                    if !acc.is_empty() {
                        acc.push(':');
                    }
                    acc.push_str(s);
                    acc
                }),
        }
    }

    fn get_final_path(&self) -> FinalPath {
        let mut final_behavior = PathBehavior::Delete;
        let final_add = rc_refcell!(LinkedHashSet::new());
        // Cannot use HashSet as we need to keep order
        let final_sub = rc_refcell!(LinkedHashSet::new());
        self.iter_in_options(|opt| {
            let final_add_clone = Rc::clone(&final_add);
            let final_sub_clone = Rc::clone(&final_sub);
            if let Some(p) = opt.path.borrow().as_ref() {
                match p.default_behavior {
                    PathBehavior::Delete => {
                        final_add_clone.as_ref().replace(p.add.clone());
                    }
                    PathBehavior::KeepSafe | PathBehavior::KeepUnsafe => {
                        final_sub_clone.as_ref().replace(p.sub.clone());
                    }
                    PathBehavior::Inherit => {
                        if final_behavior.is_delete() {
                            let union: LinkedHashSet<String> = final_add_clone
                                .as_ref()
                                .borrow()
                                .union(&p.add)
                                .filter(|e| !p.sub.contains(*e))
                                .cloned()
                                .collect();
                            final_add_clone.as_ref().borrow_mut().extend(union);
                            debug!("inherit final_add: {:?}", final_add_clone.as_ref().borrow());
                        } else {
                            let union: LinkedHashSet<String> = final_sub_clone
                                .as_ref()
                                .borrow()
                                .union(&p.sub)
                                .filter(|e| !p.add.contains(*e))
                                .cloned()
                                .collect();
                            final_sub_clone.as_ref().borrow_mut().extend(union);
                        }
                    }
                }
                if !p.default_behavior.is_inherit() {
                    final_behavior = p.default_behavior;
                }
            }
        });
        (final_behavior, final_add, final_sub)
    }

    #[allow(dead_code)]
    #[cfg(not(tarpaulin_include))]
    fn union_all_path(&self) -> FinalPath {
        let mut final_behavior = PathBehavior::Delete;
        let final_add = rc_refcell!(LinkedHashSet::new());
        // Cannot use HashSet as we need to keep order
        let final_sub = rc_refcell!(LinkedHashSet::new());
        self.iter_in_options(|opt| {
            let final_add_clone = Rc::clone(&final_add);
            let final_sub_clone = Rc::clone(&final_sub);
            if let Some(p) = opt.path.borrow().as_ref() {
                match p.default_behavior {
                    PathBehavior::Delete => {
                        let union = final_add_clone
                            .as_ref()
                            .borrow()
                            .union(&p.add)
                            .filter(|e| !p.sub.contains(*e))
                            .cloned()
                            .collect();
                        // policy is to delete, so we add whitelist and remove blacklist
                        final_add_clone.as_ref().replace(union);
                        debug!("delete final_add: {:?}", final_add_clone.as_ref().borrow());
                    }
                    PathBehavior::KeepSafe | PathBehavior::KeepUnsafe => {
                        let union = final_sub_clone
                            .as_ref()
                            .borrow()
                            .union(&p.sub)
                            .filter(|e| !p.add.contains(*e))
                            .cloned()
                            .collect();
                        //policy is to keep, so we remove blacklist and add whitelist
                        final_sub_clone.as_ref().replace(union);
                    }
                    PathBehavior::Inherit => {
                        if final_behavior.is_delete() {
                            let union: LinkedHashSet<String> = final_add_clone
                                .as_ref()
                                .borrow()
                                .union(&p.add)
                                .filter(|e| !p.sub.contains(*e))
                                .cloned()
                                .collect();
                            final_add_clone.as_ref().borrow_mut().extend(union);
                            debug!("inherit final_add: {:?}", final_add_clone.as_ref().borrow());
                        } else {
                            let union: LinkedHashSet<String> = final_sub_clone
                                .as_ref()
                                .borrow()
                                .union(&p.sub)
                                .filter(|e| !p.add.contains(*e))
                                .cloned()
                                .collect();
                            final_sub_clone.as_ref().borrow_mut().extend(union);
                        }
                    }
                }
                if !p.default_behavior.is_inherit() {
                    final_behavior = p.default_behavior;
                }
            }
        });
        (final_behavior, final_add, final_sub)
    }

    #[cfg(feature = "finder")]
    pub fn calculate_filtered_env<I>(
        &self,
        target: Cred,
        final_env: I,
    ) -> Result<HashMap<String, String>, String>
    where
        I: Iterator<Item = (String, String)>,
    {
        let (final_behavior, final_set, final_keep, final_check, final_delete) =
            self.get_final_env();
        if final_behavior.is_keep() {
            warn!("Keeping environment variables is dangerous operation, it can lead to security vulnerabilities. 
            Please consider using delete instead. 
            See https://www.sudo.ws/security/advisories/bash_env/, 
            https://www.sudo.ws/security/advisories/perl_env/ or 
            https://nvd.nist.gov/vuln/detail/CVE-2006-0151");
        }
        let mut final_env: HashMap<String, String> = match final_behavior {
            EnvBehavior::Inherit => Err("Internal Error with environment behavior".to_string()),
            EnvBehavior::Delete => Ok(final_env
                .filter_map(|(key, value)| {
                    let key = EnvKey::new(key).expect("Unexpected environment variable");
                    if final_keep.env_matches(&key)
                        || (final_check.env_matches(&key) && check_env(&key.value, &value))
                    {
                        debug!("Keeping env: {}={}", key.value, value);
                        Some((key.value, value))
                    } else {
                        debug!("Dropping env: {}", key.value);
                        None
                    }
                })
                .collect()),
            EnvBehavior::Keep => Ok(final_env
                .filter_map(|(key, value)| {
                    let key = EnvKey::new(key).expect("Unexpected environment variable");
                    if !final_delete.env_matches(&key)
                        || (final_check.env_matches(&key) && check_env(&key.value, &value))
                    {
                        debug!("Keeping env: {}={}", key.value, value);
                        Some((key.value, value))
                    } else {
                        debug!("Dropping env: {}", key.value);
                        None
                    }
                })
                .collect()),
        }?;
        final_env.insert("PATH".into(), self.calculate_path());
        final_env.insert("LOGNAME".into(), target.user.name.clone());
        final_env.insert("USER".into(), target.user.name);
        final_env.insert("HOME".into(), target.user.dir.to_string_lossy().to_string());
        final_env
            .entry("TERM".into())
            .or_insert_with(|| "unknown".into());
        final_env.insert(
            "SHELL".into(),
            target.user.shell.to_string_lossy().to_string(),
        );
        final_env.extend(final_set);
        Ok(final_env)
    }

    fn get_final_env(&self) -> FinalEnv {
        let mut final_behavior = EnvBehavior::default();
        let mut final_set = HashMap::new();
        let mut final_keep = LinkedHashSet::new();
        let mut final_check = LinkedHashSet::new();
        let mut final_delete = LinkedHashSet::new();
        self.iter_in_options(|opt| {
            if let Some(p) = opt.env.borrow().as_ref() {
                final_behavior = match p.default_behavior {
                    EnvBehavior::Delete => {
                        // policy is to delete, so we add whitelist and remove blacklist
                        final_keep = p
                            .keep
                            .iter()
                            .filter(|e| {
                                !p.set.env_matches(e)
                                    || !p.check.env_matches(e)
                                    || !p.delete.env_matches(e)
                            })
                            .cloned()
                            .collect();
                        final_check = p
                            .check
                            .iter()
                            .filter(|e| !p.set.env_matches(e) || !p.delete.env_matches(e))
                            .cloned()
                            .collect();
                        final_set = p.set.clone();
                        debug!("check: {:?}", final_check);
                        p.default_behavior
                    }
                    EnvBehavior::Keep => {
                        //policy is to keep, so we remove blacklist and add whitelist
                        final_delete = p
                            .delete
                            .iter()
                            .filter(|e| {
                                !p.set.env_matches(e)
                                    || !p.keep.env_matches(e)
                                    || !p.check.env_matches(e)
                            })
                            .cloned()
                            .collect();
                        final_check = p
                            .check
                            .iter()
                            .filter(|e| !p.set.env_matches(e) || !p.keep.env_matches(e))
                            .cloned()
                            .collect();
                        final_set = p.set.clone();
                        p.default_behavior
                    }
                    EnvBehavior::Inherit => {
                        if final_behavior.is_delete() {
                            final_keep = final_keep
                                .union(&p.keep)
                                .filter(|e| {
                                    !p.set.env_matches(e)
                                        || !p.delete.env_matches(e)
                                        || !p.check.env_matches(e)
                                })
                                .cloned()
                                .collect();
                            final_check = final_check
                                .union(&p.check)
                                .filter(|e| !p.set.env_matches(e) || !p.delete.env_matches(e))
                                .cloned()
                                .collect();
                        } else {
                            final_delete = final_delete
                                .union(&p.delete)
                                .filter(|e| {
                                    !p.set.env_matches(e)
                                        || !p.keep.env_matches(e)
                                        || !p.check.env_matches(e)
                                })
                                .cloned()
                                .collect();
                            final_check = final_check
                                .union(&p.check)
                                .filter(|e| !p.set.env_matches(e) || !p.keep.env_matches(e))
                                .cloned()
                                .collect();
                        }
                        final_set.extend(p.set.clone());
                        debug!("check: {:?}", final_check);
                        final_behavior
                    }
                };
            }
        });
        (
            final_behavior,
            final_set,
            final_keep,
            final_check,
            final_delete,
        )
    }

    #[allow(dead_code)]
    #[cfg(not(tarpaulin_include))]
    fn union_all_env(
        &self,
    ) -> (
        EnvBehavior,
        LinkedHashSet<EnvKey>,
        LinkedHashSet<EnvKey>,
        LinkedHashSet<EnvKey>,
    ) {
        let mut final_behavior = EnvBehavior::default();
        let mut final_keep = LinkedHashSet::new();
        let mut final_check = LinkedHashSet::new();
        let mut final_delete = LinkedHashSet::new();
        self.iter_in_options(|opt| {
            if let Some(p) = opt.env.borrow().as_ref() {
                final_behavior = match p.default_behavior {
                    EnvBehavior::Delete => {
                        // policy is to delete, so we add whitelist and remove blacklist
                        final_keep = final_keep
                            .union(&p.keep)
                            .filter(|e| !p.check.env_matches(e) || !p.delete.env_matches(e))
                            .cloned()
                            .collect();
                        final_check = final_check
                            .union(&p.check)
                            .filter(|e| !p.delete.env_matches(e))
                            .cloned()
                            .collect();
                        p.default_behavior
                    }
                    EnvBehavior::Keep => {
                        //policy is to keep, so we remove blacklist and add whitelist
                        final_delete = final_delete
                            .union(&p.delete)
                            .filter(|e| !p.keep.env_matches(e) || !p.check.env_matches(e))
                            .cloned()
                            .collect();
                        final_check = final_check
                            .union(&p.check)
                            .filter(|e| !p.keep.env_matches(e))
                            .cloned()
                            .collect();
                        p.default_behavior
                    }
                    EnvBehavior::Inherit => {
                        if final_behavior.is_delete() {
                            final_keep = final_keep
                                .union(&p.keep)
                                .filter(|e| !p.delete.env_matches(e) || !p.check.env_matches(e))
                                .cloned()
                                .collect();
                            final_check = final_check
                                .union(&p.check)
                                .filter(|e| !p.delete.env_matches(e))
                                .cloned()
                                .collect();
                        } else {
                            final_delete = final_delete
                                .union(&p.delete)
                                .filter(|e| !p.keep.env_matches(e) || !p.check.env_matches(e))
                                .cloned()
                                .collect();
                            final_check = final_check
                                .union(&p.check)
                                .filter(|e| !p.keep.env_matches(e))
                                .cloned()
                                .collect();
                        }
                        final_behavior
                    }
                };
            }
        });
        (final_behavior, final_keep, final_check, final_delete)
    }
    pub fn get_root_behavior(&self) -> (Level, SPrivileged) {
        self.find_in_options(|opt| {
            if let Some(p) = &opt.borrow().root {
                return Some((opt.level, *p));
            }
            None
        })
        .unwrap_or((Level::None, SPrivileged::default()))
    }
    pub fn get_bounding(&self) -> (Level, SBounding) {
        self.find_in_options(|opt| {
            if let Some(p) = &opt.borrow().bounding {
                return Some((opt.level, *p));
            }
            None
        })
        .unwrap_or((Level::None, SBounding::default()))
    }
    pub fn get_authentication(&self) -> (Level, SAuthentication) {
        self.find_in_options(|opt| {
            if let Some(p) = &opt.borrow().authentication {
                return Some((opt.level, *p));
            }
            None
        })
        .unwrap_or((Level::None, SAuthentication::default()))
    }

    pub fn get_wildcard(&self) -> (Level, String) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().wildcard_denied.borrow().as_ref() {
                return Some((opt.level, p.clone()));
            }
            None
        })
        .unwrap_or((Level::None, "".to_owned()))
    }

    pub fn get_timeout(&self) -> (Level, STimeout) {
        self.find_in_options(|opt| {
            if let Some(p) = &opt.borrow().timeout {
                return Some((opt.level, p.clone()));
            }
            None
        })
        .unwrap_or((Level::None, STimeout::default()))
    }

    pub fn to_opt(&self) -> Opt {
        let mut res = Opt::default();
        let (final_behavior, final_add, final_sub) = self.get_final_path();
        res.path.as_mut().unwrap().default_behavior = final_behavior;
        res.path.as_mut().unwrap().add = final_add.as_ref().borrow().clone();
        res.path.as_mut().unwrap().sub = final_sub.as_ref().borrow().clone();
        let (final_behavior, final_set, final_keep, final_check, final_delete) =
            self.get_final_env();
        res.env.as_mut().unwrap().default_behavior = final_behavior;
        res.env.as_mut().unwrap().set = final_set;
        res.env.as_mut().unwrap().keep = final_keep;
        res.env.as_mut().unwrap().check = final_check;
        res.env.as_mut().unwrap().delete = final_delete;
        self.iter_in_options(|opt| {
            if let Some(p) = opt.root.as_ref() {
                res.root.as_ref().replace(p);
            }
            if let Some(p) = opt.bounding.as_ref() {
                res.bounding.as_ref().replace(p);
            }
            if let Some(p) = opt.wildcard_denied.as_ref() {
                res.wildcard_denied.as_ref().replace(p);
            }
            if let Some(p) = opt.timeout.as_ref() {
                res.timeout.as_ref().replace(p);
            }
        });
        res
    }
}

impl PartialEq for OptStack {
    fn eq(&self, other: &Self) -> bool {
        // we must assess that every option result in the same final result
        let (final_behavior, final_add, final_sub) = self.get_final_path();
        let (other_final_behavior, other_final_add, other_final_sub) = other.get_final_path();
        let res = final_behavior == other_final_behavior
            && final_add
                .as_ref()
                .borrow()
                .symmetric_difference(&other_final_add.as_ref().borrow())
                .count()
                == 0
            && final_sub
                .as_ref()
                .borrow()
                .symmetric_difference(&other_final_sub.as_ref().borrow())
                .count()
                == 0
            && self.get_root_behavior().1 == other.get_root_behavior().1
            && self.get_bounding().1 == other.get_bounding().1
            && self.get_wildcard().1 == other.get_wildcard().1
            && self.get_authentication().1 == other.get_authentication().1
            && self.get_timeout().1 == other.get_timeout().1;
        debug!(
            "final_behavior == other_final_behavior : {}
        && add {:?} - other_add {:?} == 0 : {}
        && sub - other_sub == 0 : {}
        && self.get_root_behavior().1 == other.get_root_behavior().1 : {}
        && self.get_bounding().1 == other.get_bounding().1 : {}
        && self.get_wildcard().1 == other.get_wildcard().1 : {}
        && self.get_authentication().1 == other.get_authentication().1 : {}
        && self.get_timeout().1 == other.get_timeout().1 : {}",
            final_behavior == other_final_behavior,
            final_add.as_ref().borrow(),
            other_final_add.as_ref().borrow(),
            final_add
                .as_ref()
                .borrow()
                .symmetric_difference(&other_final_add.as_ref().borrow())
                .count()
                == 0,
            final_sub
                .as_ref()
                .borrow()
                .symmetric_difference(&other_final_sub.as_ref().borrow())
                .count()
                == 0,
            self.get_root_behavior().1 == other.get_root_behavior().1,
            self.get_bounding().1 == other.get_bounding().1,
            self.get_wildcard().1 == other.get_wildcard().1,
            self.get_authentication().1 == other.get_authentication().1,
            self.get_timeout().1 == other.get_timeout().1
        );
        debug!("OPT check: {}", res);
        res
    }
}

#[cfg(test)]
mod tests {

    use nix::unistd::Group;
    use nix::unistd::Pid;
    use nix::unistd::User;

    use crate::as_borrow_mut;
    use crate::database::wrapper::SConfigWrapper;
    use crate::database::wrapper::SRoleWrapper;
    use crate::database::wrapper::STaskWrapper;
    use crate::rc_refcell;

    use super::super::options::*;
    use super::super::structs::*;

    #[test]
    fn test_find_in_options() {
        let config = rc_refcell!(SConfig::default());
        let role = rc_refcell!(SRole::new("test".to_string(), Rc::downgrade(&config)));
        let mut global_path = SPathOptions::default();
        global_path.default_behavior = PathBehavior::Delete;
        global_path.add.insert("path1".to_string());
        let mut role_path = SPathOptions::default();
        role_path.default_behavior = PathBehavior::Inherit;
        role_path.add.insert("path2".to_string());
        let mut config_global = Opt::new(Level::Global);
        config_global.path = Some(global_path);
        as_borrow_mut!(config).options = Some(rc_refcell!(config_global));
        let mut config_role = Opt::new(Level::Role);
        config_role.path = Some(role_path.clone());
        as_borrow_mut!(role).options = Some(rc_refcell!(config_role));
        as_borrow_mut!(config).roles.push(role);
        let options = OptStack::from_role(config.as_ref().borrow().roles[0].clone());

        let res: Option<(Level, SPathOptions)> =
            options.find_in_options(|opt| opt.path.clone().map(|value| (opt.level, value)));
        assert_eq!(res, Some((Level::Role, role_path)));
    }

    #[test]
    fn test_get_path() {
        let config = rc_refcell!(SConfig::default());
        let role = rc_refcell!(SRole::new("test".to_string(), Rc::downgrade(&config)));
        let mut global_path = SPathOptions::default();
        global_path.default_behavior = PathBehavior::Delete;
        global_path.add.insert("path1".to_string());
        let mut role_path = SPathOptions::default();
        role_path.default_behavior = PathBehavior::Inherit;
        role_path.add.insert("path2".to_string());
        let mut config_global = Opt::new(Level::Global);
        config_global.path = Some(global_path);
        as_borrow_mut!(config).options = Some(rc_refcell!(config_global));
        let mut config_role = Opt::new(Level::Role);
        config_role.path = Some(role_path);
        as_borrow_mut!(role).options = Some(rc_refcell!(config_role));
        as_borrow_mut!(config).roles.push(role);
        let options = OptStack::from_role(config.as_ref().borrow().roles.first().unwrap().clone());
        let res = options.calculate_path();
        assert_eq!(res, "path2:path1");
    }

    #[test]
    fn test_get_path_delete() {
        let role = SRoleWrapper::default();
        as_borrow_mut!(role).name = "test".to_string();
        let mut path_options = SPathOptions::new(PathBehavior::Delete);
        path_options.add.insert("path2".to_string());
        let mut opt_role = Opt::new(Level::Role);
        opt_role.path = Some(path_options);
        as_borrow_mut!(role).options = Some(rc_refcell!(opt_role));
        let config = SConfigWrapper::default();
        as_borrow_mut!(config).roles.push(role.clone());
        let mut global_options = Opt::new(Level::Global);
        global_options.path = Some(SPathOptions::new(PathBehavior::Delete));
        global_options
            .path
            .as_mut()
            .unwrap()
            .add
            .insert("path1".to_string());
        as_borrow_mut!(role)._config = Some(Rc::downgrade(&config));
        let options = OptStack::from_role(role).calculate_path();
        assert!(options.contains("path2"));
    }

    #[test]
    fn test_opt_add_sub() {
        let role = SRoleWrapper::default();
        as_borrow_mut!(role).name = "test".to_string();
        let mut path_options = SPathOptions::new(PathBehavior::Delete);
        path_options.sub.insert("path1".to_string());
        let mut opt_role = Opt::new(Level::Role);
        opt_role.path = Some(path_options);
        as_borrow_mut!(role).options = Some(rc_refcell!(opt_role));
        let mut path_options = SPathOptions::new(PathBehavior::Delete);
        path_options.add.insert("path1".to_string());
        let mut opt_global = Opt::new(Level::Global);
        opt_global.path = Some(path_options);
        let config = SConfigWrapper::default();
        as_borrow_mut!(config).roles.push(role.clone());
        as_borrow_mut!(config).options = Some(rc_refcell!(opt_global));
        as_borrow_mut!(role)._config = Some(Rc::downgrade(&config));
        let options = OptStack::from_role(role).calculate_path();
        assert!(!options.contains("path1"));
    }

    #[test]
    fn test_env_global_to_task() {
        let mut env_options = SEnvOptions::new(EnvBehavior::Delete);
        env_options.keep.insert("env1".into());
        let mut opt = Opt::new(Level::Task);
        opt.env = Some(env_options);
        let task = STaskWrapper::default();
        as_borrow_mut!(task).name = IdTask::Number(1);
        as_borrow_mut!(task).options = Some(rc_refcell!(opt));
        let role = SRoleWrapper::default();
        as_borrow_mut!(role).name = "test".to_string();
        let mut env_options = SEnvOptions::new(EnvBehavior::Delete);
        env_options.keep.insert("env2".into());
        let mut opt = Opt::new(Level::Role);
        opt.env = Some(env_options);
        as_borrow_mut!(role).options = Some(rc_refcell!(opt));
        as_borrow_mut!(task)._role = Some(Rc::downgrade(&role));

        let mut env_options = SEnvOptions::new(EnvBehavior::Delete);
        env_options.keep.insert("env3".into());

        let mut opt = Opt::new(Level::Global);
        opt.env = Some(env_options);
        let config = SConfigWrapper::default();
        as_borrow_mut!(config).roles.push(role.clone());
        as_borrow_mut!(config).options = Some(rc_refcell!(opt));
        as_borrow_mut!(role)._config = Some(Rc::downgrade(&config));
        let options = OptStack::from_task(task).to_opt();
        let res = options.env.unwrap().keep;
        assert!(res.contains(&EnvKey::from("env1")));
    }

    // test to_opt() for OptStack
    #[test]
    fn test_to_opt() {
        let role = SRoleWrapper::default();
        as_borrow_mut!(role).name = "test".to_string();
        let mut path_options = SPathOptions::new(PathBehavior::Inherit);
        path_options.add.insert("path2".to_string());
        let mut opt_role = Opt::new(Level::Role);
        opt_role.path = Some(path_options);
        as_borrow_mut!(role).options = Some(rc_refcell!(opt_role));
        let mut path_options = SPathOptions::new(PathBehavior::Delete);
        path_options.add.insert("path1".to_string());
        let mut opt_global = Opt::new(Level::Global);
        opt_global.path = Some(path_options);
        let config = SConfigWrapper::default();
        as_borrow_mut!(config).roles.push(role.clone());
        as_borrow_mut!(config).options = Some(rc_refcell!(opt_global));
        as_borrow_mut!(role)._config = Some(Rc::downgrade(&config));
        let options = OptStack::from_role(role).to_opt();
        assert_eq!(options.path.unwrap().add.len(), 2);
    }

    #[test]
    fn test_get_timeout() {
        let role = SRoleWrapper::default();
        as_borrow_mut!(role).name = "test".to_string();
        let mut timeout = STimeout::default();
        timeout.duration = Some(Duration::minutes(5));
        let mut opt_role = Opt::new(Level::Role);
        opt_role.timeout = Some(timeout);
        as_borrow_mut!(role).options = Some(rc_refcell!(opt_role));
        let mut timeout = STimeout::default();
        timeout.duration = Some(Duration::minutes(10));
        let mut opt_global = Opt::new(Level::Global);
        opt_global.timeout = Some(timeout);
        let config = SConfigWrapper::default();
        as_borrow_mut!(config).roles.push(role.clone());
        as_borrow_mut!(config).options = Some(rc_refcell!(opt_global));
        as_borrow_mut!(role)._config = Some(Rc::downgrade(&config));
        let options = OptStack::from_role(role).get_timeout();
        assert_eq!(options.1.duration.unwrap(), Duration::minutes(5));
        assert_eq!(options.0, Level::Role);
        assert!(options.1.type_field.is_none());
    }

    #[test]
    fn test_get_root_behavior() {
        let task = STaskWrapper::default();
        as_borrow_mut!(task).name = IdTask::Number(1);
        as_borrow_mut!(task).options = Some(rc_refcell!(Opt::new(Level::Task)));
        let role = SRoleWrapper::default();
        as_borrow_mut!(role).name = "test".to_string();
        let root = SPrivileged::User;
        let mut opt_role = Opt::new(Level::Role);
        opt_role.root = Some(root);
        as_borrow_mut!(role).options = Some(rc_refcell!(opt_role));
        let root = SPrivileged::Privileged;
        let mut opt_global = Opt::new(Level::Global);
        opt_global.root = Some(root);
        let config = SConfigWrapper::default();
        as_borrow_mut!(task)._role = Some(Rc::downgrade(&role));
        as_borrow_mut!(role).tasks.push(task.clone());
        as_borrow_mut!(config).roles.push(role.clone());
        as_borrow_mut!(config).options = Some(rc_refcell!(opt_global));
        as_borrow_mut!(role)._config = Some(Rc::downgrade(&config));
        let options = OptStack::from_task(task).get_root_behavior();
        assert_eq!(options.1, SPrivileged::User);
    }

    #[test]
    fn test_get_bounding() {
        let role = SRoleWrapper::default();
        as_borrow_mut!(role).name = "test".to_string();
        let bounding = SBounding::Strict;
        let mut opt_role = Opt::new(Level::Role);
        opt_role.bounding = Some(bounding);
        as_borrow_mut!(role).options = Some(rc_refcell!(opt_role));
        let bounding = SBounding::Ignore;
        let mut opt_global = Opt::new(Level::Global);
        opt_global.bounding = Some(bounding);
        let config = SConfigWrapper::default();
        as_borrow_mut!(config).roles.push(role.clone());
        as_borrow_mut!(config).options = Some(rc_refcell!(opt_global));
        as_borrow_mut!(role)._config = Some(Rc::downgrade(&config));
        let options = OptStack::from_role(role).get_bounding();
        assert_eq!(options.1, SBounding::Strict);
    }

    #[test]
    fn test_get_wildcard() {
        let role = SRoleWrapper::default();
        as_borrow_mut!(role).name = "test".to_string();
        let wildcard = ";&|".to_string();
        let mut opt_role = Opt::new(Level::Role);
        opt_role.wildcard_denied = Some(wildcard);
        as_borrow_mut!(role).options = Some(rc_refcell!(opt_role));
        let wildcard = ";&|".to_string();
        let mut opt_global = Opt::new(Level::Global);
        opt_global.wildcard_denied = Some(wildcard);
        let config = SConfigWrapper::default();
        as_borrow_mut!(config).roles.push(role.clone());
        as_borrow_mut!(config).options = Some(rc_refcell!(opt_global));
        as_borrow_mut!(role)._config = Some(Rc::downgrade(&config));
        let options = OptStack::from_role(role).get_wildcard();
        assert_eq!(options.1, ";&|");
    }

    #[test]
    fn test_tz_is_safe() {
        assert!(tz_is_safe("America/New_York"));
        assert!(!tz_is_safe("/America/New_York"));
        assert!(!tz_is_safe("America/New_York/.."));
        //assert path max
        assert!(!tz_is_safe(
            String::from_utf8(vec![b'a'; (PATH_MAX + 1).try_into().unwrap()])
                .unwrap()
                .as_str()
        ));
    }

    #[cfg(feature = "finder")]
    #[test]
    fn test_check_env() {
        let mut env_options = SEnvOptions::new(EnvBehavior::Inherit);
        env_options.keep.insert("env1".into());
        let mut opt = Opt::new(Level::Task);
        opt.env = Some(env_options);
        let task = STaskWrapper::default();
        as_borrow_mut!(task).name = IdTask::Number(1);
        as_borrow_mut!(task).options = Some(rc_refcell!(opt));
        let role = SRoleWrapper::default();
        as_borrow_mut!(role).name = "test".to_string();
        let mut env_options = SEnvOptions::new(EnvBehavior::Inherit);
        env_options.check.insert("env2".into());
        let mut opt = Opt::new(Level::Role);
        opt.env = Some(env_options);
        as_borrow_mut!(role).options = Some(rc_refcell!(opt));
        as_borrow_mut!(task)._role = Some(Rc::downgrade(&role));

        let mut env_options = SEnvOptions::new(EnvBehavior::Delete);
        env_options.check.insert("env3".into());
        env_options.set.insert("env4".into(), "value4".into());

        let mut opt = Opt::new(Level::Global);
        opt.env = Some(env_options);
        let config = SConfigWrapper::default();
        as_borrow_mut!(config).roles.push(role.clone());
        as_borrow_mut!(config).options = Some(rc_refcell!(opt));
        as_borrow_mut!(role)._config = Some(Rc::downgrade(&config));
        let options = OptStack::from_task(task);
        let mut test_env = HashMap::new();
        test_env.insert("env1".to_string(), "value1".to_string());
        test_env.insert("env2".into(), "va%lue2".into());
        test_env.insert("env3".into(), "value3".into());
        let cred = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            groups: vec![Group::from_gid(0.into()).unwrap().unwrap()],
            tty: None,
            ppid: Pid::from_raw(0),
        };
        let result = options
            .calculate_filtered_env(cred, test_env.into_iter())
            .unwrap();
        assert_eq!(result.get("env1").unwrap(), "value1");
        assert_eq!(result.get("env3").unwrap(), "value3");
        assert!(result.get("env2").is_none());
        assert_eq!(result.get("env4").unwrap(), "value4");
    }
}
