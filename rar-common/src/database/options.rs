use std::collections::HashMap;
use std::env;
use std::{borrow::Borrow, cell::RefCell, rc::Rc};

use bon::{bon, builder, Builder};
use chrono::Duration;

use linked_hash_set::LinkedHashSet;

#[cfg(feature = "pcre2")]
use pcre2::bytes::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use strum::{Display, EnumIs, EnumIter, EnumString, FromRepr};

use log::debug;

use crate::rc_refcell;

//#[cfg(feature = "finder")]
//use super::finder::Cred;
//#[cfg(feature = "finder")]
//use super::finder::SecurityMin;
use super::{
    convert_string_to_duration, deserialize_duration, is_default, serialize_duration, FilterMatcher,
};

use super::{
    lhs_deserialize, lhs_deserialize_envkey, lhs_serialize, lhs_serialize_envkey,
    structs::{SConfig, SRole, STask},
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

#[derive(Debug, Clone, Copy, FromRepr, EnumIter, Display)]
pub enum OptType {
    Path,
    Env,
    Root,
    Bounding,
    Wildcard,
    Timeout,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
#[repr(u8)]
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
#[repr(u8)]
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
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| { v.into_iter().map(|s| s.to_string()).collect() })]
    pub add: Option<LinkedHashSet<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize",
        serialize_with = "lhs_serialize",
        alias = "del"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| { v.into_iter().map(|s| s.to_string()).collect() })]
    pub sub: Option<LinkedHashSet<String>>,
}

// ...existing code...
impl SPathOptions {}
// ...existing code...

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
#[repr(u8)]
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
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| -> Result<_,String> { let mut res = LinkedHashSet::new(); for s in v { res.insert(EnvKey::new(s.to_string())?); } Ok(res)})]
    pub keep: Option<LinkedHashSet<EnvKey>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| -> Result<_,String> { let mut res = LinkedHashSet::new(); for s in v { res.insert(EnvKey::new(s.to_string())?); } Ok(res)})]
    pub check: Option<LinkedHashSet<EnvKey>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "lhs_deserialize_envkey",
        serialize_with = "lhs_serialize_envkey"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl ToString>| -> Result<_,String> { let mut res = LinkedHashSet::new(); for s in v { res.insert(EnvKey::new(s.to_string())?); } Ok(res)})]
    pub delete: Option<LinkedHashSet<EnvKey>>,
    #[serde(default, flatten)]
    #[builder(default)]
    pub _extra_fields: Map<String, Value>,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
#[repr(u8)]
pub enum SBounding {
    Strict,
    #[default]
    Inherit,
    Ignore,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
#[repr(u8)]
pub enum SPrivileged {
    #[default]
    User,
    Inherit,
    Privileged,
}

#[derive(
    Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Display, Clone, Copy, EnumString,
)]
#[strum(ascii_case_insensitive)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
#[repr(u8)]
pub enum SAuthentication {
    #[default]
    Perform,
    Inherit,
    Skip,
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
    ) -> Self {
        Opt {
            level,
            path,
            env,
            root,
            bounding,
            authentication,
            wildcard_denied,
            timeout,
            _extra_fields,
        }
    }

    pub fn level_default() -> Self {
        Self::builder(Level::Default)
            .maybe_root(env!("RAR_USER_CONSIDERED").parse().ok())
            .maybe_bounding(env!("RAR_BOUNDING").parse().ok())
            .path(SPathOptions::level_default())
            .maybe_authentication(env!("RAR_AUTHENTICATION").parse().ok())
            .env(
                SEnvOptions::builder(
                    env!("RAR_ENV_DEFAULT")
                        .parse()
                        .unwrap_or(EnvBehavior::Delete),
                )
                .keep(env!("RAR_ENV_KEEP_LIST").split(',').collect::<Vec<&str>>())
                .unwrap()
                .check(env!("RAR_ENV_CHECK_LIST").split(',').collect::<Vec<&str>>())
                .unwrap()
                .delete(
                    env!("RAR_ENV_DELETE_LIST")
                        .split(',')
                        .collect::<Vec<&str>>(),
                )
                .unwrap()
                .set(
                    serde_json::from_str(env!("RAR_ENV_SET_LIST"))
                        .unwrap_or_else(|_| Map::default()),
                )
                .maybe_override_behavior(env!("RAR_ENV_OVERRIDE_BEHAVIOR").parse().ok())
                .build(),
            )
            .timeout(
                STimeout::builder()
                    .maybe_type_field(env!("RAR_TIMEOUT_TYPE").parse().ok())
                    .maybe_duration(
                        convert_string_to_duration(&env!("RAR_TIMEOUT_DURATION").to_string())
                            .ok()
                            .flatten(),
                    )
                    .build(),
            )
            .wildcard_denied(env!("RAR_WILDCARD_DENIED"))
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

impl Default for SPathOptions {
    fn default() -> Self {
        SPathOptions {
            default_behavior: PathBehavior::Inherit,
            add: None,
            sub: None,
        }
    }
}

impl SPathOptions {
    pub fn level_default() -> Self {
        SPathOptions::builder(
            env!("RAR_PATH_DEFAULT")
                .parse()
                .unwrap_or(PathBehavior::Delete),
        )
        .add(env!("RAR_PATH_ADD_LIST").split(':').collect::<Vec<&str>>())
        .sub(
            env!("RAR_PATH_REMOVE_LIST")
                .split(':')
                .collect::<Vec<&str>>(),
        )
        .build()
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
    Regex::new(&format!("^{}$", s)).is_ok()
}

#[cfg(not(feature = "pcre2"))]
fn is_regex(_s: &str) -> bool {
    false // Always return true if regex feature is disabled
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

trait EnvSet {
    fn env_matches(&self, wildcarded: &EnvKey) -> bool;
}

impl EnvSet for LinkedHashSet<EnvKey> {
    fn env_matches(&self, needle: &EnvKey) -> bool {
        self.iter().any(|s| match s.env_type {
            EnvKeyType::Normal => s == needle,
            EnvKeyType::Wildcarded => check_wildcarded(s, &needle.value),
        })
    }
}

impl EnvSet for Option<LinkedHashSet<EnvKey>> {
    fn env_matches(&self, needle: &EnvKey) -> bool {
        self.as_ref().map_or(false, |set| set.env_matches(needle))
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptStack {
    pub(crate) stack: [Option<Rc<RefCell<Opt>>>; 5],
    roles: Option<Rc<RefCell<SConfig>>>,
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
        self.with_default()
            .roles(roles.to_owned())
            .opt(roles.as_ref().borrow().options.to_owned())
    }

    fn with_default(self) -> Self {
        self.opt(Some(rc_refcell!(Opt::level_default())))
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

    fn get_final_path(&self) -> SPathOptions {
        let mut final_behavior = PathBehavior::Delete;
        let default = LinkedHashSet::new();
        let final_add = rc_refcell!(LinkedHashSet::new());
        // Cannot use HashSet as we need to keep order
        let final_sub = rc_refcell!(LinkedHashSet::new());
        self.iter_in_options(|opt| {
            let final_add_clone = Rc::clone(&final_add);
            let final_sub_clone = Rc::clone(&final_sub);
            if let Some(p) = opt.path.borrow().as_ref() {
                match p.default_behavior {
                    PathBehavior::KeepSafe | PathBehavior::KeepUnsafe | PathBehavior::Delete => {
                        if let Some(add) = p.add.as_ref() {
                            final_add_clone.as_ref().replace(add.clone());
                        }
                        if let Some(sub) = p.sub.as_ref() {
                            final_sub_clone.as_ref().replace(sub.clone());
                        }
                    }
                    PathBehavior::Inherit => {
                        if final_behavior.is_delete() {
                            let union: LinkedHashSet<String> = final_add_clone
                                .as_ref()
                                .borrow()
                                .union(p.add.as_ref().unwrap_or(&default))
                                .filter(|e| !p.sub.as_ref().unwrap_or(&default).contains(*e))
                                .cloned()
                                .collect();
                            final_add_clone.as_ref().borrow_mut().extend(union);
                            debug!("inherit final_add: {:?}", final_add_clone.as_ref().borrow());
                        } else {
                            let union: LinkedHashSet<String> = final_sub_clone
                                .as_ref()
                                .borrow()
                                .union(p.sub.as_ref().unwrap_or(&default))
                                .filter(|e| !p.add.as_ref().unwrap_or(&default).contains(*e))
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

    fn get_final_env(&self, cmd_filter: Option<FilterMatcher>) -> SEnvOptions {
        let mut final_behavior = EnvBehavior::default();
        let mut final_set = HashMap::new();
        let mut final_keep = LinkedHashSet::new();
        let mut final_check = LinkedHashSet::new();
        let mut final_delete = LinkedHashSet::new();
        let overriden_behavior = cmd_filter.as_ref().and_then(|f| f.env_behavior);
        self.iter_in_options(|opt| {
            if let Some(p) = opt.env.borrow().as_ref() {
                final_behavior = match p.default_behavior {
                    EnvBehavior::Delete | EnvBehavior::Keep => {
                        // policy is to delete, so we add whitelist and remove blacklist
                        final_keep = p
                            .keep
                            .as_ref()
                            .unwrap_or(&LinkedHashSet::new())
                            .iter()
                            .filter(|e| {
                                //p.set.as_ref().is_some_and(|set| !set.env_matches(e)) ||

                                !p.check.env_matches(e) || !p.delete.env_matches(e)
                            })
                            .cloned()
                            .collect();
                        final_check = p
                            .check
                            .as_ref()
                            .unwrap_or(&LinkedHashSet::new())
                            .iter()
                            .filter(|e| {
                                //p.set.as_ref().is_some_and(|set| !set.env_matches(e))
                                //||
                                !p.delete.env_matches(e)
                            })
                            .cloned()
                            .collect();
                        final_delete = p
                            .delete
                            .as_ref()
                            .unwrap_or(&LinkedHashSet::new())
                            .iter()
                            .filter(|e| {
                                //p.set.as_ref().is_some_and(|set| !set.env_matches(e)) ||
                                !p.check.env_matches(e)
                            })
                            .cloned()
                            .collect();
                        if let Some(set) = &p.set {
                            final_set = set.clone();
                        }
                        debug!("check: {:?}", final_check);
                        p.default_behavior
                    }
                    EnvBehavior::Inherit => {
                        final_keep = final_keep
                            .union(p.keep.as_ref().unwrap_or(&LinkedHashSet::new()))
                            .cloned()
                            .collect();
                        final_check = final_check
                            .union(p.check.as_ref().unwrap_or(&LinkedHashSet::new()))
                            .cloned()
                            .collect();
                        final_delete = final_delete
                            .union(p.delete.as_ref().unwrap_or(&LinkedHashSet::new()))
                            .cloned()
                            .collect();
                        if let Some(set) = &p.set {
                            final_set.extend(set.clone());
                        }
                        debug!("check: {:?}", final_check);
                        final_behavior
                    }
                };
            }
        });
        SEnvOptions::builder(overriden_behavior.unwrap_or(final_behavior))
            .set(final_set)
            .keep(final_keep)
            .unwrap()
            .check(final_check)
            .unwrap()
            .delete(final_delete)
            .unwrap()
            .build()
    }

    fn get_level(&self) -> Level {
        let (level, _) = self
            .find_in_options(|opt| Some((opt.level, ())))
            .unwrap_or((Level::None, ()));
        level
    }

    pub fn to_opt(&self) -> Rc<RefCell<Opt>> {
        rc_refcell!(Opt::builder(self.get_level())
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
            .build())
    }
}

#[cfg(test)]
mod tests {

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
        assert!(res
            .as_ref()
            .unwrap_or(&LinkedHashSet::new())
            .contains(&EnvKey::from("env1")));
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
        let default = LinkedHashSet::new();
        let stack = OptStack::from_roles(config.clone());
        let opt = stack.to_opt();
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
                .unwrap_or(&LinkedHashSet::new())
                .clone(),
            vec![EnvKey::from("env2")]
        ));
        assert_eq!(
            global_options
                .env
                .as_ref()
                .unwrap()
                .keep
                .as_ref()
                .unwrap_or(&LinkedHashSet::new())
                .iter()
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
                .unwrap_or(&LinkedHashSet::new())
                .clone(),
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
                .unwrap_or(&LinkedHashSet::new())
                .clone(),
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
    fn is_wildcard_env_key() {
        assert!(!is_valid_env_name("TEST_.*"));
        assert!(!is_valid_env_name("123"));
        assert!(!is_valid_env_name(""));
        assert!(is_regex("TEST_.*"));
    }

    #[test]
    fn test_get_final_env_set_inherit() {
        let config = SConfig::builder()
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
        let stack = OptStack::from_task(config.task("test", 1).unwrap());
        let opt = stack.to_opt();
        let options = opt.as_ref().borrow();
        assert_eq!(
            options
                .env
                .as_ref()
                .unwrap()
                .set
                .as_ref()
                .unwrap_or(&HashMap::new())
                .get("env1")
                .unwrap(),
            "value3"
        );
    }

    #[test]
    fn test_get_final_path_inherit() {
        let config = SConfig::builder()
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
        let stack = OptStack::from_task(config.task("test", 1).unwrap());
        let opt = stack.to_opt();
        let options = opt.as_ref().borrow();
        assert!(options
            .path
            .as_ref()
            .unwrap()
            .sub
            .as_ref()
            .unwrap()
            .contains("/path1"));
        assert!(options
            .path
            .as_ref()
            .unwrap()
            .sub
            .as_ref()
            .unwrap()
            .contains("/path2"));
        assert!(options
            .path
            .as_ref()
            .unwrap()
            .sub
            .as_ref()
            .unwrap()
            .contains("/path3"));
    }

    #[test]
    fn test_find_in_options_none() {
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .task(STask::builder(1).build())
                    .build(),
            )
            .build();
        let stack = OptStack::from_task(config.task("test", 1).unwrap());
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
                "env key {}, must be a valid env, or a valid regex",
                invalid_env
            )
        );
    }
}
