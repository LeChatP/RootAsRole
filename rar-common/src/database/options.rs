use std::collections::HashMap;
#[cfg(feature = "finder")]
use std::path::PathBuf;
use std::{borrow::Borrow, cell::RefCell, rc::Rc};

use bon::{bon, builder, Builder};
use chrono::Duration;

#[cfg(feature = "finder")]
use libc::PATH_MAX;
use linked_hash_set::LinkedHashSet;

#[cfg(feature = "pcre2")]
use pcre2::bytes::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use strum::{Display, EnumIs, EnumIter, FromRepr};

use log::debug;
#[cfg(feature = "finder")]
use log::warn;

use crate::rc_refcell;

#[cfg(feature = "finder")]
use super::finder::Cred;
use super::{FilterMatcher, deserialize_duration, is_default, serialize_duration};

use super::{
    lhs_deserialize, lhs_deserialize_envkey, lhs_serialize, lhs_serialize_envkey,
    structs::{SConfig, SRole, STask},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Level {
    #[default]
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default, Builder)]
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
    #[builder(default)]
    pub _extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Builder)]
pub struct SPathOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default_behavior: PathBehavior,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize"
    )]
    #[builder(default, with = |v : impl IntoIterator<Item = impl ToString>| { v.into_iter().map(|s| s.to_string()).collect() })]
    pub add: LinkedHashSet<String>,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize",
        alias = "del"
    )]
    #[builder(default, with = |v : impl IntoIterator<Item = impl ToString>| { v.into_iter().map(|s| s.to_string()).collect() })]
    pub sub: LinkedHashSet<String>,
    #[serde(default)]
    #[serde(flatten)]
    #[builder(default)]
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default, Builder)]
pub struct SEnvOptions {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default_behavior: EnvBehavior,
    #[serde(alias = "override", default, skip_serializing_if = "Option::is_none")]
    pub override_behavior: Option<bool>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[builder(default, with = |iter: impl IntoIterator<Item = (impl ToString, impl ToString)>| {
        let mut map = HashMap::with_hasher(Default::default());
        map.extend(iter.into_iter().map(|(k, v)| (k.to_string(), v.to_string())));
        map
    })]
    pub set: HashMap<String, String>,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    #[builder(default, with = |v : impl IntoIterator<Item = impl ToString>| -> Result<_,String> { let mut res = LinkedHashSet::new(); for s in v { res.insert(EnvKey::new(s.to_string())?); } Ok(res)})]
    pub keep: LinkedHashSet<EnvKey>,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    #[builder(default, with = |v : impl IntoIterator<Item = impl ToString>| -> Result<_,String> { let mut res = LinkedHashSet::new(); for s in v { res.insert(EnvKey::new(s.to_string())?); } Ok(res)})]
    pub check: LinkedHashSet<EnvKey>,
    #[serde(
        default,
        skip_serializing_if = "LinkedHashSet::is_empty",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    #[builder(default, with = |v : impl IntoIterator<Item = impl ToString>| -> Result<_,String> { let mut res = LinkedHashSet::new(); for s in v { res.insert(EnvKey::new(s.to_string())?); } Ok(res)})]
    pub delete: LinkedHashSet<EnvKey>,
    #[serde(default, flatten)]
    #[builder(default)]
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
    #[serde(skip)]
    pub level: Level,
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
    #[serde(default, flatten)]
    pub _extra_fields: Map<String, Value>,
}

#[bon]
impl Opt {
    #[builder]
    pub fn new(
        #[builder(start_fn)] level: Level,
        path: Option<SPathOptions>,
        env: Option<SEnvOptions>,
        root: Option<SPrivileged>,
        bounding: Option<SBounding>,
        authentication: Option<SAuthentication>,
        #[builder(into)] wildcard_denied: Option<String>,
        timeout: Option<STimeout>,
        #[builder(default)] _extra_fields: Map<String, Value>,
    ) -> Rc<RefCell<Self>> {
        rc_refcell!(Opt {
            level,
            path,
            env,
            root,
            bounding,
            authentication,
            wildcard_denied,
            timeout,
            _extra_fields,
        })
    }

    pub fn raw_new(level: Level) -> Self {
        Opt {
            level,
            ..Default::default()
        }
    }

    pub fn level_default() -> Rc<RefCell<Self>> {
        Self::builder(Level::Default)
            .root(SPrivileged::User)
            .bounding(SBounding::Strict)
            .path(
                SPathOptions::builder(PathBehavior::Delete)
                    .add([
                        "/usr/local/sbin",
                        "/usr/local/bin",
                        "/usr/sbin",
                        "/usr/bin",
                        "/sbin",
                        "/snap/bin",
                    ])
                    .build(),
            )
            .authentication(SAuthentication::Perform)
            .env(
                SEnvOptions::builder(EnvBehavior::Delete)
                    .keep([
                        "HOME",
                        "USER",
                        "LOGNAME",
                        "COLORS",
                        "DISPLAY",
                        "HOSTNAME",
                        "KRB5CCNAME",
                        "LS_COLORS",
                        "PS1",
                        "PS2",
                        "XAUTHORY",
                        "XAUTHORIZATION",
                        "XDG_CURRENT_DESKTOP",
                    ])
                    .unwrap()
                    .check([
                        "COLORTERM",
                        "LANG",
                        "LANGUAGE",
                        "LC_*",
                        "LINGUAS",
                        "TERM",
                        "TZ",
                    ])
                    .unwrap()
                    .delete([
                        "PS4",
                        "SHELLOPTS",
                        "PERLLIB",
                        "PERL5LIB",
                        "PERL5OPT",
                        "PYTHONINSPECT",
                    ])
                    .unwrap()
                    .build(),
            )
            .timeout(
                STimeout::builder()
                    .type_field(TimestampType::PPID)
                    .duration(Duration::minutes(5))
                    .build(),
            )
            .wildcard_denied(";&|")
            .build()
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
            stack: [None, Some(Opt::level_default()), None, None, None],
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

impl<S: opt_stack_builder::State> OptStackBuilder<S> {
    fn opt(mut self, opt: Option<Rc<RefCell<Opt>>>) -> Self {
        if let Some(opt) = opt {
            self.stack[opt.as_ref().borrow().level as usize] = Some(opt.clone());
        }
        self
    }
    fn with_task(
        self,
        task: Rc<RefCell<STask>>,
    ) -> OptStackBuilder<
        opt_stack_builder::SetTask<opt_stack_builder::SetRole<opt_stack_builder::SetRoles<S>>>,
    >
    where
        <S as opt_stack_builder::State>::Roles: opt_stack_builder::IsUnset,
        <S as opt_stack_builder::State>::Role: opt_stack_builder::IsUnset,
        <S as opt_stack_builder::State>::Task: opt_stack_builder::IsUnset,
    {
        self.with_role(
            task.as_ref()
                .borrow()
                ._role
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap(),
        )
        .task(task.to_owned())
        .opt(task.as_ref().borrow().options.to_owned())
    }
    fn with_role(
        self,
        role: Rc<RefCell<SRole>>,
    ) -> OptStackBuilder<opt_stack_builder::SetRole<opt_stack_builder::SetRoles<S>>>
    where
        <S as opt_stack_builder::State>::Roles: opt_stack_builder::IsUnset,
        <S as opt_stack_builder::State>::Role: opt_stack_builder::IsUnset,
    {
        self.with_roles(
            role.as_ref()
                .borrow()
                ._config
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap(),
        )
        .role(role.to_owned())
        .opt(role.as_ref().borrow().options.to_owned())
    }

    fn with_roles(
        self,
        roles: Rc<RefCell<SConfig>>,
    ) -> OptStackBuilder<opt_stack_builder::SetRoles<S>>
    where
        <S as opt_stack_builder::State>::Roles: opt_stack_builder::IsUnset,
    {
        self.with_default().roles(roles.to_owned())
            .opt(roles.as_ref().borrow().options.to_owned())
    }

    fn with_default(self) -> Self {
        self.opt(Some(Opt::builder(Level::Default)
        .root(SPrivileged::User)
        .bounding(SBounding::Strict)
        .path(
            SPathOptions::builder(PathBehavior::Delete)
                .add([
                    "/usr/local/sbin",
                    "/usr/local/bin",
                    "/usr/sbin",
                    "/usr/bin",
                    "/sbin",
                    "/bin",
                    "/snap/bin",
                ])
                .build(),
        )
        .authentication(SAuthentication::Perform)
        .env(
            SEnvOptions::builder(EnvBehavior::Delete)
                .keep([
                    "HOME",
                    "USER",
                    "LOGNAME",
                    "COLORS",
                    "DISPLAY",
                    "HOSTNAME",
                    "KRB5CCNAME",
                    "LS_COLORS",
                    "PS1",
                    "PS2",
                    "XAUTHORY",
                    "XAUTHORIZATION",
                    "XDG_CURRENT_DESKTOP",
                ])
                .unwrap()
                .check([
                    "COLORTERM",
                    "LANG",
                    "LANGUAGE",
                    "LC_*",
                    "LINGUAS",
                    "TERM",
                    "TZ",
                ])
                .unwrap()
                .delete([
                    "PS4",
                    "SHELLOPTS",
                    "PERLLIB",
                    "PERL5LIB",
                    "PERL5OPT",
                    "PYTHONINSPECT",
                ])
                .unwrap()
                .build(),
        )
        .timeout(
            STimeout::builder()
                .type_field(TimestampType::TTY)
                .duration(Duration::minutes(5))
                .build(),
        )
        .wildcard_denied(";&|")
        .build()))
    }
}

#[bon]
impl OptStack {
    #[builder]
    pub fn new(
        #[builder(field)] stack: [Option<Rc<RefCell<Opt>>>; 5],
        roles: Option<Rc<RefCell<SConfig>>>,
        role: Option<Rc<RefCell<SRole>>>,
        task: Option<Rc<RefCell<STask>>>,
    ) -> Self {
        OptStack {
            stack,
            roles,
            role,
            task,
        }
    }
    pub fn from_task(task: Rc<RefCell<STask>>) -> Self {
        OptStack::builder().with_task(task).build()
    }
    pub fn from_role(role: Rc<RefCell<SRole>>) -> Self {
        OptStack::builder().with_role(role).build()
    }
    pub fn from_roles(roles: Rc<RefCell<SConfig>>) -> Self {
        OptStack::builder().with_roles(roles).build()
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
        let path = self.get_final_path();
        let final_add = path
            .add
            .difference(&path.sub)
            .fold("".to_string(), |mut acc, s| {
                if !acc.is_empty() {
                    acc.insert(0, ':');
                }
                acc.insert_str(0, s);
                acc
            });
        match path.default_behavior {
            PathBehavior::Inherit | PathBehavior::Delete => final_add,
            is_safe => std::env::vars()
                .find_map(|(key, value)| if key == "PATH" { Some(value) } else { None })
                .unwrap_or(String::new())
                .split(':')
                .filter(|s| {
                    !path.sub.contains(*s) && (!is_safe.is_keep_safe() || PathBuf::from(s).exists())
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

    fn get_final_path(&self) -> SPathOptions {
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
        SPathOptions::builder(final_behavior)
            .add(
                final_add
                    .clone()
                    .as_ref()
                    .borrow()
                    .iter()
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
            .sub(
                final_sub
                    .clone()
                    .as_ref()
                    .borrow()
                    .iter()
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
            .build()
    }

    #[allow(dead_code)]
    #[cfg(not(tarpaulin_include))]
    fn union_all_path(&self) -> SPathOptions {
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
        SPathOptions::builder(final_behavior)
            .add(
                final_add
                    .clone()
                    .as_ref()
                    .borrow()
                    .iter()
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
            .sub(
                final_sub
                    .clone()
                    .as_ref()
                    .borrow()
                    .iter()
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
            .build()
    }

    #[cfg(feature = "finder")]
    pub fn calculate_filtered_env<I>(
        &self,
        opt_filter: Option<FilterMatcher>,
        target: Cred,
        final_env: I,
    ) -> Result<HashMap<String, String>, String>
    where
        I: Iterator<Item = (String, String)>,
    {
        let env = self.get_final_env(opt_filter);
        if env.default_behavior.is_keep() {
            warn!("Keeping environment variables is dangerous operation, it can lead to security vulnerabilities. 
            Please consider using delete instead. 
            See https://www.sudo.ws/security/advisories/bash_env/, 
            https://www.sudo.ws/security/advisories/perl_env/ or 
            https://nvd.nist.gov/vuln/detail/CVE-2006-0151");
        }
        let mut final_env: HashMap<String, String> = match env.default_behavior {
            EnvBehavior::Inherit => Err("Internal Error with environment behavior".to_string()),
            EnvBehavior::Delete => Ok(final_env
                .filter_map(|(key, value)| {
                    let key = EnvKey::new(key).expect("Unexpected environment variable");
                    if env.keep.env_matches(&key)
                        || (env.check.env_matches(&key) && check_env(&key.value, &value))
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
                    if !env.delete.env_matches(&key)
                        || (env.check.env_matches(&key) && check_env(&key.value, &value))
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
        final_env.extend(env.set);
        Ok(final_env)
    }

    fn get_final_env(&self, cmd_filter: Option<FilterMatcher>) -> SEnvOptions {
        let mut final_behavior = cmd_filter
            .as_ref()
            .and_then(|f| f.env_behavior)
            .unwrap_or_default();
        let mut final_set = HashMap::new();
        let mut final_keep = LinkedHashSet::new();
        let mut final_check = LinkedHashSet::new();
        let mut final_delete = LinkedHashSet::new();
        let overriden = cmd_filter
            .as_ref()
            .is_some_and(|f| f.env_behavior.is_some());
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
                        if overriden {
                            final_behavior
                        } else {
                            p.default_behavior
                        }
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
                        if overriden {
                            final_behavior
                        } else {
                            p.default_behavior
                        }
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
        SEnvOptions::builder(final_behavior)
            .set(final_set)
            .keep(final_keep)
            .unwrap()
            .check(final_check)
            .unwrap()
            .delete(final_delete)
            .unwrap()
            .build()
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

    fn get_level(&self) -> Level {
        let (level, _) = self
            .find_in_options(|opt| Some((opt.level, ())))
            .unwrap_or((Level::None, ()));
        level
    }

    pub fn to_opt(&self) -> Rc<RefCell<Opt>> {
        Opt::builder(self.get_level())
            .path(self.get_final_path())
            .env(self.get_final_env(None))
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
            .maybe_wildcard_denied(
                self.find_in_options(|opt| {
                    opt.wildcard_denied
                        .borrow()
                        .as_ref()
                        .map(|wildcard| (opt.level, wildcard.clone()))
                })
                .map(|(_, wildcard)| wildcard),
            )
            .maybe_timeout(
                self.find_in_options(|opt| opt.timeout.clone().map(|timeout| (opt.level, timeout)))
                    .map(|(_, timeout)| timeout),
            )
            .build()
    }
}

impl PartialEq for OptStack {
    fn eq(&self, other: &Self) -> bool {
        // we must assess that every option result in the same final result
        let path = self.get_final_path();
        let other_path = other.get_final_path();
        let res = path.default_behavior == other_path.default_behavior
            && path.add.symmetric_difference(&other_path.add).count() == 0
            && path.sub.symmetric_difference(&other_path.sub).count() == 0
            && self.get_root_behavior().1 == other.get_root_behavior().1
            && self.get_bounding().1 == other.get_bounding().1
            && self.get_wildcard().1 == other.get_wildcard().1
            && self.get_authentication().1 == other.get_authentication().1
            && self.get_timeout().1 == other.get_timeout().1;
        debug!(
            "final_behavior == other_path.behavior : {}
        && add {:?} - other_add {:?} == 0 : {}
        && sub - other_sub == 0 : {}
        && self.get_root_behavior().1 == other.get_root_behavior().1 : {}
        && self.get_bounding().1 == other.get_bounding().1 : {}
        && self.get_wildcard().1 == other.get_wildcard().1 : {}
        && self.get_authentication().1 == other.get_authentication().1 : {}
        && self.get_timeout().1 == other.get_timeout().1 : {}",
            path.default_behavior == other_path.default_behavior,
            path.add,
            other_path.add,
            path.add.symmetric_difference(&other_path.add).count() == 0,
            path.sub.symmetric_difference(&other_path.sub).count() == 0,
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

    use nix::unistd::Pid;

    use super::super::options::*;
    use super::super::structs::*;

    fn env_key_set_equal<I, J>(a: I, b: J) -> bool
    where
        I: IntoIterator<Item = EnvKey>,
        J: IntoIterator<Item = EnvKey>,
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
        let config = SConfig::builder()
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
        let options = OptStack::from_role(config.as_ref().borrow().roles[0].clone());
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

    #[cfg(feature = "finder")]
    #[test]
    fn test_get_path() {
        let config = SConfig::builder()
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
        let options = OptStack::from_role(config.as_ref().borrow().roles.first().unwrap().clone());
        let res = options.calculate_path();
        assert_eq!(res, "path2:path1");
    }

    #[cfg(feature = "finder")]
    #[test]
    fn test_get_path_delete() {
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .options(|opt| {
                        opt.path(
                            SPathOptions::builder(PathBehavior::Delete)
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
        let options = OptStack::from_role(config.role("test").unwrap()).calculate_path();
        assert!(options.contains("path2"));
    }

    #[cfg(feature = "finder")]
    #[test]
    fn test_opt_add_sub() {
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .options(|opt| {
                        opt.path(
                            SPathOptions::builder(PathBehavior::Delete)
                                .sub(["path1"])
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
        let options = OptStack::from_role(config.role("test").unwrap()).calculate_path();
        assert!(!options.contains("path1"));
    }

    #[test]
    fn test_env_global_to_task() {
        let config = SConfig::builder()
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
        let binding = OptStack::from_task(config.task("test", 1).unwrap()).to_opt();
        let options = binding.as_ref().borrow();
        let res = &options.env.as_ref().unwrap().keep;
        assert!(res.contains(&EnvKey::from("env1")));
    }

    // test to_opt() for OptStack
    #[test]
    fn test_to_opt() {
        let config = SConfig::builder()
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
                                        .duration(Duration::minutes(3))
                                        .build(),
                                )
                                .wildcard_denied("c")
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
                                .duration(Duration::minutes(2))
                                .build(),
                        )
                        .wildcard_denied("b")
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
                        .duration(Duration::minutes(1))
                        .build(),
                )
                .wildcard_denied("a")
                .build()
            })
            .build();
        let stack = OptStack::from_roles(config.clone());
        let opt = stack.to_opt();
        let global_options = opt.as_ref().borrow();
        assert_eq!(
            global_options.path.as_ref().unwrap().default_behavior,
            PathBehavior::Delete
        );
        assert!(hashset_vec_equal(
            global_options.path.as_ref().unwrap().add.clone(),
            vec!["path1"]
        ));
        assert_eq!(
            global_options.env.as_ref().unwrap().default_behavior,
            EnvBehavior::Delete
        );
        assert!(env_key_set_equal(
            global_options.env.as_ref().unwrap().keep.clone(),
            vec![EnvKey::from("env2")]
        ));
        assert_eq!(global_options.root.unwrap(), SPrivileged::Privileged);
        assert_eq!(global_options.bounding.unwrap(), SBounding::Ignore);
        assert_eq!(
            global_options.authentication.unwrap(),
            SAuthentication::Perform
        );
        assert_eq!(
            global_options.timeout.as_ref().unwrap().duration.unwrap(),
            Duration::minutes(1)
        );
        assert_eq!(
            global_options.timeout.as_ref().unwrap().type_field.unwrap(),
            TimestampType::TTY
        );
        assert_eq!(global_options.wildcard_denied.as_ref().unwrap(), "a");
        let opt = OptStack::from_role(config.clone().role("test").unwrap()).to_opt();
        let role_options = opt.as_ref().borrow();
        assert_eq!(
            role_options.path.as_ref().unwrap().default_behavior,
            PathBehavior::Delete
        );
        assert!(hashset_vec_equal(
            role_options.path.as_ref().unwrap().add.clone(),
            vec!["path1", "path2"]
        ));
        assert_eq!(
            role_options.env.as_ref().unwrap().default_behavior,
            EnvBehavior::Delete
        );
        assert!(env_key_set_equal(
            role_options.env.as_ref().unwrap().keep.clone(),
            vec![EnvKey::from("env1")]
        ));
        assert_eq!(role_options.root.unwrap(), SPrivileged::Privileged);
        assert_eq!(role_options.bounding.unwrap(), SBounding::Strict);
        assert_eq!(role_options.authentication.unwrap(), SAuthentication::Skip);
        assert_eq!(
            role_options.timeout.as_ref().unwrap().duration.unwrap(),
            Duration::minutes(2)
        );
        assert_eq!(
            role_options.timeout.as_ref().unwrap().type_field.unwrap(),
            TimestampType::PPID
        );
        assert_eq!(role_options.wildcard_denied.as_ref().unwrap(), "b");
        let opt = OptStack::from_task(config.task("test", 1).unwrap()).to_opt();
        let task_options = opt.as_ref().borrow();
        assert_eq!(
            task_options.path.as_ref().unwrap().default_behavior,
            PathBehavior::Delete
        );
        assert!(hashset_vec_equal(
            task_options.path.as_ref().unwrap().add.clone(),
            vec!["path1", "path2", "path3"]
        ));
        assert_eq!(
            task_options.env.as_ref().unwrap().default_behavior,
            EnvBehavior::Delete
        );
        assert!(env_key_set_equal(
            task_options.env.as_ref().unwrap().keep.clone(),
            vec![EnvKey::from("env1"), EnvKey::from("env3")]
        ));
        assert_eq!(task_options.root.unwrap(), SPrivileged::User);
        assert_eq!(task_options.bounding.unwrap(), SBounding::Strict);
        assert_eq!(
            task_options.authentication.unwrap(),
            SAuthentication::Perform
        );
        assert_eq!(
            task_options.timeout.as_ref().unwrap().duration.unwrap(),
            Duration::minutes(3)
        );
        assert_eq!(
            task_options.timeout.as_ref().unwrap().type_field.unwrap(),
            TimestampType::TTY
        );
        assert_eq!(task_options.wildcard_denied.as_ref().unwrap(), "c");
    }

    #[test]
    fn test_get_timeout() {
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .options(|opt| {
                        opt.timeout(STimeout::builder().duration(Duration::minutes(5)).build())
                            .build()
                    })
                    .build(),
            )
            .options(|opt| {
                opt.timeout(
                    STimeout::builder()
                        .type_field(TimestampType::PPID)
                        .duration(Duration::minutes(10))
                        .build(),
                )
                .build()
            })
            .build();
        let options = OptStack::from_role(config.role("test").unwrap()).get_timeout();
        assert_eq!(options.1.duration.unwrap(), Duration::minutes(5));
        assert_eq!(options.0, Level::Role);
        assert!(options.1.type_field.is_none());
    }

    #[test]
    fn test_get_root_behavior() {
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .task(STask::builder(1).build())
                    .options(|opt| opt.root(SPrivileged::User).build())
                    .build(),
            )
            .options(|opt| opt.root(SPrivileged::Privileged).build())
            .build();
        let (level, sprivilege) =
            OptStack::from_task(config.task("test", 1).unwrap()).get_root_behavior();
        assert_eq!(level, Level::Role);
        assert_eq!(sprivilege, SPrivileged::User);
    }

    #[test]
    fn test_get_bounding() {
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .options(|opt| opt.bounding(SBounding::Strict).build())
                    .build(),
            )
            .options(|opt| opt.bounding(SBounding::Ignore).build())
            .build();
        let (level, bounding) = OptStack::from_role(config.role("test").unwrap()).get_bounding();
        assert_eq!(level, Level::Role);
        assert_eq!(bounding, SBounding::Strict);
    }

    #[test]
    fn test_get_wildcard() {
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .options(|opt| opt.wildcard_denied("b").build())
                    .build(),
            )
            .options(|opt| opt.wildcard_denied("a").build())
            .build();
        let (level, wildcard) = OptStack::from_role(config.role("test").unwrap()).get_wildcard();
        assert_eq!(level, Level::Role);
        assert_eq!(wildcard, "b");
    }

    #[cfg(feature = "finder")]
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
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .options(|opt| {
                        opt.env(
                            SEnvOptions::builder(EnvBehavior::Inherit)
                                .check(["env2"])
                                .unwrap()
                                .build(),
                        )
                        .build()
                    })
                    .task(
                        STask::builder(IdTask::Number(1))
                            .options(|opt| {
                                opt.env(
                                    SEnvOptions::builder(EnvBehavior::Inherit)
                                        .keep(["env1"])
                                        .unwrap()
                                        .build(),
                                )
                                .build()
                            })
                            .build(),
                    )
                    .build(),
            )
            .options(|opt| {
                opt.env(
                    SEnvOptions::builder(EnvBehavior::Delete)
                        .check(["env3"])
                        .unwrap()
                        .set([("env4".to_string(), "value4".to_string())])
                        .build(),
                )
                .build()
            })
            .build();
        let options = OptStack::from_task(config.task("test", 1).unwrap());
        let mut test_env = HashMap::new();
        test_env.insert("env1".to_string(), "value1".to_string());
        test_env.insert("env2".into(), "va%lue2".into());
        test_env.insert("env3".into(), "value3".into());
        let cred = Cred::builder()
            .user_id(0)
            .group_id(0)
            .ppid(Pid::from_raw(0))
            .build();
        let result = options
            .calculate_filtered_env(None, cred, test_env.into_iter())
            .unwrap();
        assert_eq!(result.get("env1").unwrap(), "value1");
        assert_eq!(result.get("env3").unwrap(), "value3");
        assert!(result.get("env2").is_none());
        assert_eq!(result.get("env4").unwrap(), "value4");
    }

    #[cfg(feature = "finder")]
    #[test]
    fn test_override_env() {
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .task(
                        STask::builder(IdTask::Number(1))
                            .options(|opt| {
                                opt.env(
                                    SEnvOptions::builder(EnvBehavior::Inherit)
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
                            SEnvOptions::builder(EnvBehavior::Inherit)
                                .check(["env2"])
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
                        .check(["env3"])
                        .unwrap()
                        .set([("env4".to_string(), "value4".to_string())])
                        .build(),
                )
                .build()
            })
            .build();

        let options = OptStack::from_task(config.task("test", 1).unwrap());
        let mut test_env = HashMap::new();
        test_env.insert("env1".to_string(), "value1".to_string());
        test_env.insert("env2".into(), "va%lue2".into());
        test_env.insert("env3".into(), "value3".into());
        let cred = Cred::builder().user_id(0).group_id(0).build();
        let result = options
            .calculate_filtered_env(None, cred, test_env.into_iter())
            .unwrap();
        assert_eq!(result.get("env1").unwrap(), "value1");
        assert_eq!(result.get("env3").unwrap(), "value3");
        assert!(result.get("env2").is_none());
        assert_eq!(result.get("env4").unwrap(), "value4");
    }
}
