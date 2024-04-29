
use std::{borrow::Borrow, cell::RefCell, path::PathBuf, rc::Rc};

use chrono::Duration;

use libc::PATH_MAX;
use linked_hash_set::LinkedHashSet;
use pcre2::bytes::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use strum::{Display, EnumIs, EnumIter, FromRepr, IntoEnumIterator};
use tracing::debug;

use crate::rc_refcell;

use super::{deserialize_duration, is_default, serialize_duration};

use super::{
    lhs_deserialize, lhs_deserialize_envkey, lhs_serialize, lhs_serialize_envkey,
    structs::{SConfig, SRole, STask},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    None,
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
pub enum PathBehavior {
    Delete,
    KeepSafe,
    KeepUnsafe,
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone, Copy, Display)]
#[serde(rename_all = "lowercase")]
pub enum TimestampType {
    PPID,
    TTY,
    UID,
}

impl Default for TimestampType {
    fn default() -> Self {
        TimestampType::PPID
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct STimeout {
    #[serde(default, rename = "type")]
    pub type_field: TimestampType,
    #[serde(
        serialize_with = "serialize_duration",
        deserialize_with = "deserialize_duration"
    )]
    pub duration: Duration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_usage: Option<u64>,
    #[serde(default)]
    #[serde(flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
}

impl Default for STimeout {
    fn default() -> Self {
        STimeout {
            type_field: TimestampType::default(),
            duration: Duration::minutes(5),
            max_usage: None,
            _extra_fields: Map::default(),
        }
    }
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
pub enum EnvBehavior {
    Delete,
    Keep,
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SEnvOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    pub default_behavior: EnvBehavior,
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
pub enum SBounding {
    Strict,
    Ignore,
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
pub enum SPrivileged {
    Privileged,
    User,
    Inherit,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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

impl Default for Level {
    fn default() -> Self {
        Level::Default
    }
}

impl Default for EnvBehavior {
    fn default() -> Self {
        EnvBehavior::Inherit
    }
}

impl Default for SBounding {
    fn default() -> Self {
        SBounding::Inherit
    }
}

impl Default for SPrivileged {
    fn default() -> Self {
        SPrivileged::User
    }
}

impl Default for PathBehavior {
    fn default() -> Self {
        PathBehavior::Inherit
    }
}

impl Opt {
    pub fn new(level: Level) -> Self {
        let mut opt = Self::default();
        opt.level = level;
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
            wildcard_denied: Some(";&|".to_string()),
            timeout: Some(STimeout::default()),
            _extra_fields: Map::default(),
            level: Level::Default,
        }
    }
}

impl Default for OptStack {
    fn default() -> Self {
        OptStack {
            stack: [None, Some(Rc::new(Opt::default().into())), None, None, None],
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

impl EnvKey {
    pub fn new(s: String) -> Result<Self, String> {
        if Regex::new("^[a-zA-Z_]+[a-zA-Z0-9_]*$") // check if it is a valid env name
            .unwrap()
            .is_match(s.as_bytes())
            .is_ok_and(|m| m)
        {
            Ok(EnvKey {
                env_type: EnvKeyType::Normal,
                value: s,
            })
        } else if Regex::new("^[a-zA-Z_*?]+[a-zA-Z0-9_*?]*$") // check if it is a valid env name
            .unwrap()
            .is_match(s.as_bytes())
            .is_ok_and(|m| m)
        {
            Ok(EnvKey {
                env_type: EnvKeyType::Wildcarded,
                value: s,
            })
        } else {
            Err(format!("Invalid env key {}, must start with letter or underscore following by letters, numbers or underscores. Wildcard accepts only '?' and '*'", s))
        }
    }
}

impl PartialEq<str> for EnvKey {
    fn eq(&self, other: &str) -> bool {
        self.value == *other
    }
}

impl Into<String> for EnvKey {
    fn into(self) -> String {
        self.value
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

impl SPathOptions {
    fn new(behavior: PathBehavior) -> Self {
        let mut res = SPathOptions::default();
        res.default_behavior = behavior;
        res
    }
    pub fn get_description(&self) -> String {
        let mut description = String::new();
        description.push_str(format!("Default behavior: {}\n", self.default_behavior).as_str());
        if !self.add.is_empty() {
            description.push_str("Add:\n");
            for s in self.add.iter() {
                description.push_str(format!("{}\n", s).as_str());
            }
        }
        if !self.sub.is_empty() {
            description.push_str("Sub:\n");
            for s in self.sub.iter() {
                description.push_str(format!("{}\n", s).as_str());
            }
        }
        description
    }
}

impl Default for SEnvOptions {
    fn default() -> Self {
        SEnvOptions {
            default_behavior: EnvBehavior::default(),
            keep: LinkedHashSet::new(),
            check: LinkedHashSet::new(),
            delete: LinkedHashSet::new(),
            _extra_fields: Map::default(),
        }
    }
}

impl SEnvOptions {
    pub fn new(behavior: EnvBehavior) -> Self {
        let mut res = SEnvOptions::default();
        res.default_behavior = behavior;
        res
    }
    pub fn get_description(&self) -> String {
        let mut description = String::new();
        description.push_str(format!("Default behavior: {}\n", self.default_behavior).as_str());
        if !self.keep.is_empty() {
            description.push_str("Keep:\n");
            for s in self.keep.iter() {
                description.push_str(format!("{}\n", s.value).as_str());
            }
        }
        if !self.check.is_empty() {
            description.push_str("Check:\n");
            for s in self.check.iter() {
                description.push_str(format!("{}\n", s.value).as_str());
            }
        }
        if !self.delete.is_empty() {
            description.push_str("Delete:\n");
            for s in self.delete.iter() {
                description.push_str(format!("{}\n", s.value).as_str());
            }
        }
        description
    }
}

impl Opt {
    pub fn get_description(&self) -> String {
        let mut description = String::new();
        if let Some(path) = &self.path {
            description.push_str(format!("{}\n", path.get_description()).as_str());
        }
        if let Some(env) = &self.env {
            description.push_str(format!("{}\n", env.get_description()).as_str());
        }
        if let Some(no_root) = &self.root {
            description.push_str(format!("Root type: {}\n", no_root).as_str());
        }
        if let Some(bounding) = &self.bounding {
            description.push_str(format!("Bounding enforcement: {}\n", bounding).as_str());
        }
        description
    }
}

trait EnvSet {
    fn env_matches(&self, wildcarded: &EnvKey) -> bool;
}

impl EnvSet for LinkedHashSet<EnvKey> {
    fn env_matches(&self, wildcarded: &EnvKey) -> bool {
        match wildcarded.env_type {
            EnvKeyType::Normal => self.contains(wildcarded),
            EnvKeyType::Wildcarded => {
                self.iter().any(|s| {
                    Regex::new(&format!(
                        "^{}$",
                        wildcarded.value.replace("*", ".*").replace("?", ".")
                    )) // convert to regex
                    .unwrap()
                    .is_match(s.value.as_bytes())
                    .is_ok_and(|m| m)
                })
            }
        }
    }
}

fn tz_is_safe(tzval: &str) -> bool {
    // tzcode treats a value beginning with a ':' as a path.
    let tzval = if tzval.starts_with(':') {
        &tzval[1..]
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

fn check_env(key: &str, value: &str) -> bool {
    match key {
        "TZ" => tz_is_safe(value),
        _ => value.chars().any(|c| c == '/' || c == '%'),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptStack {
    pub(crate) stack: [Option<Rc<RefCell<Opt>>>; 5],
    roles: Option<Rc<RefCell<SConfig>>>,
    role: Option<Rc<RefCell<SRole>>>,
    task: Option<Rc<RefCell<STask>>>,
}

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
        let mut opt = Opt::default();
        opt.level = Level::Global;
        opt.root = Some(SPrivileged::User);
        opt.bounding = Some(SBounding::Strict);
        let mut env = SEnvOptions::new(EnvBehavior::Delete);
        env.check = vec!["TZ".into(), "LOGNAME".into(), "LOGIN".into(), "USER".into()]
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

    fn save(&mut self) {
        let level = self.get_lowest_level();
        let opt = self.get_opt(level);
        match level {
            Level::Global => {
                self.get_roles().unwrap().as_ref().borrow_mut().options = opt;
            }
            Level::Role => {
                self.role.to_owned().unwrap().as_ref().borrow_mut().options = opt;
            }
            Level::Task => {
                self.task.to_owned().unwrap().as_ref().borrow_mut().options = opt;
            }
            Level::None | Level::Default => {
                panic!("Cannot save None/default options");
            }
        }
    }

    fn set_opt(&mut self, level: Level, opt: Option<Rc<RefCell<Opt>>>) {
        if let Some(opt) = opt {
            self.stack[level as usize] = Some(opt);
        } else {
            self.stack[level as usize] = Some(Rc::new(Opt::new(level).into()));
        }
    }

    fn get_opt(&self, level: Level) -> Option<Rc<RefCell<Opt>>> {
        self.stack[level as usize].to_owned()
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
                .split(":")
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

    fn get_final_path(
        &self,
    ) -> (
        PathBehavior,
        Rc<RefCell<LinkedHashSet<String>>>,
        Rc<RefCell<LinkedHashSet<String>>>,
    ) {
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

    pub fn calculate_filtered_env(&self) -> Result<LinkedHashSet<(String, String)>, String> {
        let final_env = std::env::vars();
        let (final_behavior, final_keep, final_check, final_delete) = self.get_final_env();
        match final_behavior {
            EnvBehavior::Inherit => Err("Internal Error with environment behavior".to_string()),
            EnvBehavior::Delete => Ok(final_env
                .filter_map(|(key, value)| {
                    let key = EnvKey::new(key).expect("Unexpected environment variable");
                    if final_keep.env_matches(&key)
                        || (final_check.env_matches(&key) && check_env(&key.value, &value))
                    {
                        Some((key.value, value))
                    } else {
                        None
                    }
                })
                .collect()),
            EnvBehavior::Keep => Ok(final_env
                .filter_map(|(key, value)| {
                    let key = EnvKey::new(key).expect("Unexpected environment variable");
                    if key.value == "PATH" {
                        Some((key.value, self.calculate_path()))
                    } else if final_delete.env_matches(&key)
                        || (final_check.env_matches(&key) && check_env(&key.value, &value))
                    {
                        Some((key.value, value))
                    } else {
                        None
                    }
                })
                .collect()),
        }
    }

    fn get_final_env(
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
                            .filter(|e| !p.check.env_matches(&e) || !p.delete.env_matches(e))
                            .cloned()
                            .collect();
                        final_check = final_check
                            .union(&p.check)
                            .filter(|e| !p.delete.env_matches(&e))
                            .cloned()
                            .collect();
                        p.default_behavior
                    }
                    EnvBehavior::Keep => {
                        //policy is to keep, so we remove blacklist and add whitelist
                        final_delete = final_delete
                            .union(&p.delete)
                            .filter(|e| !p.keep.env_matches(&e) || !p.check.env_matches(&e))
                            .cloned()
                            .collect();
                        final_check = final_check
                            .union(&p.check)
                            .filter(|e| !p.keep.env_matches(&e))
                            .cloned()
                            .collect();
                        p.default_behavior
                    }
                    EnvBehavior::Inherit => {
                        if final_behavior.is_delete() {
                            final_keep = final_keep
                                .union(&p.keep)
                                .filter(|e| !p.delete.env_matches(&e) || !p.check.env_matches(&e))
                                .cloned()
                                .collect();
                            final_check = final_check
                                .union(&p.check)
                                .filter(|e| !p.delete.env_matches(&e))
                                .cloned()
                                .collect();
                        } else {
                            final_delete = final_delete
                                .union(&p.delete)
                                .filter(|e| !p.keep.env_matches(&e) || !p.check.env_matches(&e))
                                .cloned()
                                .collect();
                            final_check = final_check
                                .union(&p.check)
                                .filter(|e| !p.keep.env_matches(&e))
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

    fn get_lowest_level(&self) -> Level {
        if self.task.is_some() {
            Level::Task
        } else if self.role.is_some() {
            Level::Role
        } else {
            Level::Global
        }
    }

    pub fn to_opt(&self) -> Opt {
        let mut res = Opt::default();
        let (final_behavior, final_add, final_sub) = self.get_final_path();
        res.path.as_mut().unwrap().default_behavior = final_behavior;
        res.path.as_mut().unwrap().add = final_add.as_ref().borrow().clone();
        res.path.as_mut().unwrap().sub = final_sub.as_ref().borrow().clone();
        let (final_behavior, final_keep, final_check, final_delete) = self.get_final_env();
        res.env.as_mut().unwrap().default_behavior = final_behavior;
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

#[cfg(test)]
mod tests {

    use crate::as_borrow_mut;
    use crate::common::database::wrapper::SConfigWrapper;
    use crate::common::database::wrapper::SRoleWrapper;
    use crate::common::database::wrapper::STaskWrapper;
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

        let res: Option<(Level, SPathOptions)> = options.find_in_options(|opt| {
            if let Some(value) = opt.path.clone() {
                Some((opt.level, value))
            } else {
                None
            }
        });
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
        let options = OptStack::from_role(config.as_ref().borrow().roles.get(0).unwrap().clone());
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
        assert_eq!(options, "path2");
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
        assert_eq!(options, "");
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
        assert!(res.contains(&EnvKey::from("env2")));
        assert!(res.contains(&EnvKey::from("env3")));
    }
}