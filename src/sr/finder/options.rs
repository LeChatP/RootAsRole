use std::collections::HashSet;
use std::{borrow::Cow, collections::HashMap};

use bon::{bon, builder, Builder};
use chrono::Duration;

use konst::primitive::parse_i64;
use konst::{iter, option, result, slice, string, unwrap_ctx};
use libc::PATH_MAX;
use nix::unistd::User;
use rar_common::database::options::{
    EnvBehavior, Level, PathBehavior, SAuthentication, SBounding, SInfo, SPathOptions, SPrivileged,
    STimeout, TimestampType,
};
use rar_common::database::score::SecurityMin;
use rar_common::database::FilterMatcher;
use std::hash::Hash;

#[cfg(feature = "pcre2")]
use pcre2::bytes::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use log::{debug, error};

use crate::error::{SrError, SrResult};
use crate::Cred;

use super::de::DLinkedTask;

//#[cfg(feature = "finder")]
//use super::finder::Cred;
//#[cfg(feature = "finder")]
//use super::finder::SecurityMin;

//=== DPathOptions ===

const ENV_PATH_BEHAVIOR: PathBehavior = result::unwrap_or!(
    PathBehavior::try_parse(env!("RAR_PATH_DEFAULT")),
    PathBehavior::Delete
);

const ENV_PATH_ADD_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_PATH_ADD_LIST"), ":"),
        map(string::trim),
);

//static ENV_PATH_ADD_LIST: [&str; ENV_PATH_ADD_LIST_SLICE.len()] = *unwrap_ctx!(slice::try_into_array(ENV_PATH_ADD_LIST_SLICE));

const ENV_PATH_REMOVE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_PATH_REMOVE_LIST"), ":"),
        map(string::trim),
);

//static ENV_PATH_REMOVE_LIST: [&str; ENV_PATH_REMOVE_LIST_SLICE.len()] = *unwrap_ctx!(slice::try_into_array(ENV_PATH_REMOVE_LIST_SLICE));

//=== ENV ===
const ENV_DEFAULT_BEHAVIOR: EnvBehavior = result::unwrap_or!(
    EnvBehavior::try_parse(env!("RAR_ENV_DEFAULT")),
    EnvBehavior::Delete
);

const ENV_KEEP_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_KEEP_LIST"), ","),
        map(string::trim),
);

const ENV_CHECK_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_CHECK_LIST"), ","),
        map(string::trim),
);

const ENV_DELETE_LIST_SLICE: &[&str] = &iter::collect_const!(&str =>
    string::split(env!("RAR_ENV_DELETE_LIST"), ","),
        map(string::trim),
);

const ENV_SET_LIST_SLICE: &[(&str, &str)] = &iter::collect_const!((&str, &str) =>
    string::split(env!("RAR_ENV_SET_LIST"), "\n"),
        filter_map(|s| {
            if let Some((key,value)) = string::split_once(s, '=') {
                Some((string::trim(key),string::trim(value)))
            } else {
                None
            }
        })
);

const ENV_OVERRIDE_BEHAVIOR: bool = result::unwrap_or!(
    konst::primitive::parse_bool(env!("RAR_ENV_OVERRIDE_BEHAVIOR")),
    false
);

static ENV_KEEP_LIST: [&str; ENV_KEEP_LIST_SLICE.len()] =
    *unwrap_ctx!(slice::try_into_array(ENV_KEEP_LIST_SLICE));

static ENV_CHECK_LIST: [&str; ENV_CHECK_LIST_SLICE.len()] =
    *unwrap_ctx!(slice::try_into_array(ENV_CHECK_LIST_SLICE));

static ENV_DELETE_LIST: [&str; ENV_DELETE_LIST_SLICE.len()] =
    *unwrap_ctx!(slice::try_into_array(ENV_DELETE_LIST_SLICE));

static ENV_SET_LIST: [(&str, &str); ENV_SET_LIST_SLICE.len()] =
    *unwrap_ctx!(slice::try_into_array(ENV_SET_LIST_SLICE));

//=== STimeout ===

const TIMEOUT_TYPE: TimestampType = result::unwrap_or!(
    TimestampType::try_parse(env!("RAR_TIMEOUT_TYPE")),
    TimestampType::PPID
);

const TIMEOUT_DURATION: Duration = option::unwrap_or!(
    result::unwrap_or!(
        convert_string_to_duration(env!("RAR_TIMEOUT_DURATION")),
        None
    ),
    Duration::seconds(5)
);

const TIMEOUT_MAX_USAGE: u64 = result::unwrap_or!(
    konst::primitive::parse_u64(env!("RAR_TIMEOUT_MAX_USAGE")),
    0
);

const BOUNDING: SBounding = result::unwrap_or!(
    SBounding::try_parse(env!("RAR_BOUNDING")),
    SBounding::Strict
);

const AUTHENTICATION: SAuthentication = result::unwrap_or!(
    SAuthentication::try_parse(env!("RAR_AUTHENTICATION")),
    SAuthentication::Perform
);

const PRIVILEGED: SPrivileged = result::unwrap_or!(
    SPrivileged::try_parse(env!("RAR_USER_CONSIDERED")),
    SPrivileged::User
);

const INFO: SInfo =
    result::unwrap_or!(SInfo::try_parse(env!("RAR_EXEC_INFO_DISPLAY")), SInfo::Hide);

//#[cfg(not(tarpaulin_include))]
//const fn default() -> Opt<'static> {
/* Opt::builder(Level::Default)
.maybe_root(env!("RAR_USER_CONSIDERED").parse().ok())
.maybe_bounding(env!("RAR_BOUNDING").parse().ok())
.path(DPathOptions::default_path())
.maybe_authentication(env!("RAR_AUTHENTICATION").parse().ok())
.env(
    DEnvOptions::builder(
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
            .unwrap_or_else(|_| Map::default())
            .into_iter()
            .filter_map(|(k, v)| {
                if let Some(v) = v.as_str() {
                    Some((k.to_string(), v.to_string()))
                } else {
                    None
                }
            }),
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
.build() */
//}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Builder, Default)]
pub struct DPathOptions<'a> {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default_behavior: PathBehavior,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    #[builder(with = |v : impl IntoIterator<Item = impl Into<Cow<'a, str>>>| { v.into_iter().map(|s| s.into()).collect() })]
    pub add: Option<Cow<'a, [Cow<'a, str>]>>,
    #[serde(
        borrow,
        default,
        skip_serializing_if = "Option::is_none",
        alias = "del"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl Into<Cow<'a, str>>>| { v.into_iter().map(|s| s.into()).collect() })]
    pub sub: Option<Cow<'a, [Cow<'a, str>]>>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone, Default, Builder)]
pub struct DEnvOptions<'a> {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default_behavior: EnvBehavior,
    #[serde(alias = "override", default, skip_serializing_if = "Option::is_none")]
    pub override_behavior: Option<bool>,
    #[serde(borrow, default, skip_serializing_if = "HashMap::is_empty")]
    #[builder(default, with = |iter: impl IntoIterator<Item = (impl Into<Cow<'a,str>>, impl Into<Cow<'a,str>>)>| {
        let mut map = HashMap::with_hasher(Default::default());
        map.extend(iter.into_iter().map(|(k, v)| (k.into(), v.into())));
        map
    })]
    pub set: HashMap<Cow<'a, str>, Cow<'a, str>>,
    #[serde(borrow, default, skip_serializing_if = "HashSet::is_empty")]
    #[builder(default, with = |v : impl IntoIterator<Item = impl Into<Cow<'a,str>>>| -> Result<_,Cow<'a,str>> { let mut res = HashSet::new(); for s in v { res.insert(s.into()); } Ok(res)})]
    pub keep: HashSet<Cow<'a, str>>,
    #[serde(borrow, default, skip_serializing_if = "HashSet::is_empty")]
    #[builder(default, with = |v : impl IntoIterator<Item = impl Into<Cow<'a,str>>>| -> Result<_,Cow<'a,str>> { let mut res = HashSet::new(); for s in v { res.insert(s.into()); } Ok(res)})]
    pub check: HashSet<Cow<'a, str>>,
    #[serde(borrow, default, skip_serializing_if = "HashSet::is_empty")]
    #[builder(default, with = |v : impl IntoIterator<Item = impl Into<Cow<'a,str>>>| -> Result<_,Cow<'a,str>> { let mut res = HashSet::new(); for s in v { res.insert(s.into()); } Ok(res)})]
    pub delete: HashSet<Cow<'a, str>>,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Opt<'a> {
    #[serde(skip)]
    pub level: Level,
    #[serde(borrow, skip_serializing_if = "Option::is_none")]
    pub path: Option<DPathOptions<'a>>,
    #[serde(borrow, skip_serializing_if = "Option::is_none")]
    pub env: Option<DEnvOptions<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<SPrivileged>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounding: Option<SBounding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execinfo: Option<SInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<STimeout>,
    #[serde(default, flatten)]
    pub _extra_fields: Value,
}

#[bon]
impl<'a> Opt<'a> {
    #[builder]
    pub fn new(
        #[builder(start_fn)] level: Level,
        path: Option<DPathOptions<'a>>,
        env: Option<DEnvOptions<'a>>,
        root: Option<SPrivileged>,
        bounding: Option<SBounding>,
        authentication: Option<SAuthentication>,
        execinfo: Option<SInfo>,
        timeout: Option<STimeout>,
        #[builder(default)] _extra_fields: Value,
    ) -> Self {
        Self {
            level,
            path,
            env,
            root,
            bounding,
            authentication,
            execinfo,
            timeout,
            _extra_fields,
        }
    }
}

impl DEnvOptions<'_> {
    pub fn calc_final_env(
        &self,
        env_vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
        env_path: impl IntoIterator<Item = impl AsRef<str>>,
        current_user: &Cred,
        target: &Option<User>,
        command: String,
    ) -> SrResult<HashMap<String, String>> {
        let mut final_set = match self.default_behavior {
            EnvBehavior::Inherit => {
                error!("Internal Error with environment behavior");
                Err(SrError::ConfigurationError)
            }
            EnvBehavior::Delete => Ok(env_vars
                .into_iter()
                .filter_map(|(key, value)| {
                    let needle = key.into().into();
                    let value: String = value.into();
                    if env_matches(&self.keep, &needle)
                        || (env_matches(&self.check, &needle) && check_env(&needle, &value))
                    {
                        Some((needle.to_string(), value))
                    } else {
                        None
                    }
                })
                .collect::<HashMap<String, String>>()),
            EnvBehavior::Keep => Ok(env_vars
                .into_iter()
                .filter_map(|(key, value)| {
                    let needle = key.into().into();
                    let value: String = value.into();
                    if !env_matches(&self.delete, &needle)
                        || (env_matches(&self.check, &needle) && check_env(&needle, &value))
                    {
                        Some((needle.to_string(), value))
                    } else {
                        None
                    }
                })
                .collect::<HashMap<String, String>>()),
        }?;
        final_set.insert(
            "PATH".into(),
            env_path.into_iter().fold(String::new(), |acc, path| {
                if acc.is_empty() {
                    path.as_ref().to_string()
                } else {
                    format!("{}:{}", acc, path.as_ref())
                }
            }),
        );
        let target_user = target.as_ref().unwrap_or_else(|| &current_user.user);
        final_set.insert("LOGNAME".into(), target_user.name.clone());
        final_set.insert("USER".into(), target_user.name.clone());
        final_set.insert("HOME".into(), target_user.dir.to_string_lossy().to_string());
        final_set.insert(
            "SHELL".into(),
            target_user.shell.to_string_lossy().to_string(),
        );
        final_set.insert("RAR_UID".into(), current_user.user.uid.to_string());
        final_set.insert("RAR_GID".into(), current_user.user.gid.to_string());
        final_set.insert("RAR_USER".into(), current_user.user.name.clone());
        final_set.insert("RAR_COMMAND".into(), command);
        final_set
            .entry("TERM".into())
            .or_insert_with(|| "unknown".into());
        final_set.extend(
            self.set
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<HashMap<String, String>>(),
        );
        Ok(final_set)
    }
}

impl From<Opt<'_>> for rar_common::database::options::Opt {
    fn from(val: Opt<'_>) -> Self {
        rar_common::database::options::Opt::builder(val.level)
            .maybe_path(if let Some(spath) = val.path {
                Some(
                    rar_common::database::options::SPathOptions::builder(spath.default_behavior)
                        .maybe_add(
                            spath
                                .add
                                .map(|v| v.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
                        )
                        .maybe_sub(
                            spath
                                .sub
                                .map(|v| v.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
                        )
                        .build(),
                )
            } else {
                None
            })
            .maybe_env(if let Some(senv) = val.env {
                Some(
                    rar_common::database::options::SEnvOptions::builder(senv.default_behavior)
                        .maybe_override_behavior(senv.override_behavior)
                        .set(
                            senv.set
                                .into_iter()
                                .map(|(k, v)| (k.to_string(), v.to_string()))
                                .collect::<HashMap<_, _>>(),
                        )
                        .keep(
                            senv.keep
                                .into_iter()
                                .map(|v| v.to_string())
                                .collect::<Vec<_>>(),
                        )
                        .unwrap()
                        .check(
                            senv.check
                                .into_iter()
                                .map(|v| v.to_string())
                                .collect::<Vec<_>>(),
                        )
                        .unwrap()
                        .delete(
                            senv.delete
                                .into_iter()
                                .map(|v| v.to_string())
                                .collect::<Vec<_>>(),
                        )
                        .unwrap()
                        .build(),
                )
            } else {
                None
            })
            .maybe_root(val.root)
            .maybe_bounding(val.bounding)
            .maybe_authentication(val.authentication)
            .maybe_timeout(val.timeout)
            .build()
    }
}

impl From<DPathOptions<'_>> for SPathOptions {
    fn from(val: DPathOptions<'_>) -> Self {
        SPathOptions::builder(val.default_behavior)
            .maybe_add(
                val.add
                    .map(|v| v.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            )
            .maybe_sub(
                val.sub
                    .map(|v| v.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            )
            .build()
    }
}

impl DPathOptions<'_> {
    pub fn default_path<'a>() -> DPathOptions<'a> {
        DPathOptions::builder(ENV_PATH_BEHAVIOR)
            .add(ENV_PATH_ADD_LIST_SLICE.iter().copied())
            .sub(ENV_PATH_REMOVE_LIST_SLICE.iter().copied())
            .build()
    }
    pub fn calc_path<'a>(&'a self, path_var: &'a [&'a str]) -> Vec<&'a str> {
        let default = Default::default();
        match self.default_behavior {
            PathBehavior::Inherit | PathBehavior::Delete => {
                if let Some(add) = &self.add {
                    let sub = self.sub.as_ref().unwrap_or(&default);
                    add.iter()
                        .filter(|item| !sub.contains(*item))
                        .map(|s| s.as_ref())
                        .collect()
                } else {
                    Vec::new()
                }
            }
            is_safe => {
                let sub = self.sub.as_ref();
                self.add
                    .as_ref()
                    .map(|cow| cow.iter())
                    .into_iter()
                    .flatten()
                    .map(|s| s.as_ref())
                    .chain(path_var.iter().copied())
                    .filter(move |s| {
                        let not_in_sub = !sub.is_some_and(|set| set.iter().any(|p| *s == p));
                        not_in_sub && (!is_safe.is_keep_safe() || !s.starts_with('/'))
                    })
                    .collect()
            }
        }
    }
}

impl<'a> DPathOptions<'a> {
    pub fn union(&mut self, path_options: DPathOptions<'a>) {
        match path_options.default_behavior {
            PathBehavior::Inherit => {
                if let Some(add) = &path_options.add {
                    self.add
                        .get_or_insert_with(Default::default)
                        .to_mut()
                        .extend_from_slice(add);
                }
                if let Some(sub) = &path_options.sub {
                    self.sub
                        .get_or_insert_with(Default::default)
                        .to_mut()
                        .extend_from_slice(sub);
                }
            }
            behaviors => {
                self.add = path_options.add.clone();
                self.sub = path_options.sub.clone();
                self.default_behavior = behaviors;
            }
        }
    }
}

fn check_env(key: impl AsRef<str>, value: impl AsRef<str>) -> bool {
    debug!("Checking env: {}={}", key.as_ref(), value.as_ref());
    match key.as_ref() {
        "TZ" => tz_is_safe(value.as_ref()),
        _ => !value.as_ref().chars().any(|c| c == '/' || c == '%'),
    }
}

fn env_matches<K>(set: &HashSet<K>, needle: &K) -> bool
where
    K: AsRef<str> + Eq + Hash,
{
    set.contains(needle) || set.iter().any(|key| test_pattern(needle, key.as_ref()))
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
fn is_regex(s: impl AsRef<str>) -> bool {
    Regex::new(s.as_ref()).is_ok()
}

#[cfg(not(feature = "pcre2"))]
fn is_regex(_s: impl AsRef<str>) -> bool {
    false // Always return false if regex feature is disabled
}

#[cfg(feature = "pcre2")]
fn test_pattern(pattern: impl AsRef<str>, subject: impl AsRef<str>) -> bool {
    Regex::new(&format!("^{}$", pattern.as_ref())) // convert to regex
        .and_then(|r| r.is_match(subject.as_ref().as_bytes()))
        .is_ok_and(|m| m)
}

#[cfg(not(feature = "pcre2"))]
fn test_pattern(_: impl AsRef<str>, _: impl AsRef<str>) -> bool {
    false
}

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
    if tzval.len() >= <i32 as TryInto<usize>>::try_into(PATH_MAX).unwrap() {
        return false;
    }

    true
}

pub fn is_default<T: PartialEq + Default>(t: &T) -> bool {
    t == &T::default()
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
    let parts = string::split(s, ':');
    let (hours, parts) = match parts.next() {
        Some(h) => h,
        None => return Err(DurationParseError),
    };
    let (minutes, parts) = match parts.next() {
        Some(m) => m,
        None => return Err(DurationParseError),
    };
    let (seconds, _) = match parts.next() {
        Some(sec) => sec,
        None => return Err(DurationParseError),
    };

    let hours: i64 = unwrap_ctx!(parse_i64(hours));
    let minutes: i64 = unwrap_ctx!(parse_i64(minutes));
    let seconds: i64 = unwrap_ctx!(parse_i64(seconds));
    Ok(Some(Duration::seconds(
        hours * 3600 + minutes * 60 + seconds,
    )))
}

pub struct BorrowedOptStack<'a> {
    config: Option<Opt<'a>>,
    role: Option<Opt<'a>>,
    task: Option<Opt<'a>>,
}

impl<'a, 'c, 't> BorrowedOptStack<'a> {
    pub fn new(config: Option<Opt<'a>>) -> Self {
        Self {
            config,
            role: None,
            task: None,
        }
    }
    fn _set_role(&mut self, role: Option<Opt<'a>>) {
        self.role = role;
    }
    fn _set_task(&mut self, task: Option<Opt<'a>>) {
        self.task = task;
    }
    pub fn from_task(task: &DLinkedTask<'t, 'c, 'a>) -> Self {
        let config = task.role().config().options.clone();
        let role = task.role().role().options.clone();
        let task_opt = task.task().options.clone();
        Self {
            config,
            role,
            task: task_opt,
        }
    }
    pub fn set_role(&mut self, role: &DLinkedTask<'t, 'c, 'a>) {
        self.role = role.role().role().options.clone();
    }
    pub fn set_task(&mut self, task: &DLinkedTask<'t, 'c, 'a>) {
        self.task = task.task.options.clone();
    }
    pub fn calc_path(&self, path_var: &[&str]) -> Vec<String> {
        // Preallocate with a reasonable guess, but will only allocate once.
        let mut combined_paths: Vec<String> = Vec::with_capacity(path_var.len());

        // Stack of options in order: default, config, role, task
        let stack = [
            self.config.as_ref().and_then(|c| c.path.as_ref()),
            self.role.as_ref().and_then(|c| c.path.as_ref()),
            self.task.as_ref().and_then(|c| c.path.as_ref()),
        ];

        calculate_combined_paths(
            path_var,
            &mut combined_paths,
            &ENV_PATH_BEHAVIOR,
            &Some(ENV_PATH_ADD_LIST_SLICE),
            &Some(ENV_PATH_REMOVE_LIST_SLICE),
        );

        for path_opt in stack.iter().flatten() {
            calculate_combined_paths(
                path_var,
                &mut combined_paths,
                &path_opt.default_behavior,
                &path_opt.add.as_ref().map(|v| v.iter()),
                &path_opt.sub.as_ref().map(|v| v.iter()),
            );
        }
        combined_paths
    }

    pub fn calc_security_min(&self) -> SecurityMin {
        let mut security_min = SecurityMin::default();
        [self.task.as_ref(), self.role.as_ref(), self.config.as_ref()]
            .iter()
            .flatten()
            .for_each(|o| {
                update_security_min()
                    .security_min(&mut security_min)
                    .bounding(&o.bounding)
                    .root(&o.root)
                    .authentication(&o.authentication)
                    .env_behavior(&o.env.as_ref().map(|e| e.default_behavior))
                    .override_env(&o.env.as_ref().and_then(|e| e.override_behavior))
                    .path_behavior(&o.path.as_ref().map(|p| p.default_behavior))
                    .call();
            });
        update_security_min()
            .security_min(&mut security_min)
            .bounding(&Some(BOUNDING))
            .root(&Some(PRIVILEGED))
            .authentication(&Some(AUTHENTICATION))
            .env_behavior(&Some(ENV_DEFAULT_BEHAVIOR))
            .override_env(&Some(ENV_OVERRIDE_BEHAVIOR))
            .path_behavior(&Some(ENV_PATH_BEHAVIOR))
            .call();
        security_min
    }

    pub fn calc_override_behavior(&self) -> bool {
        [self.task.as_ref(), self.role.as_ref(), self.config.as_ref()]
            .iter()
            .flatten()
            .filter_map(|o| o.env.as_ref())
            .find_map(|o| o.override_behavior)
            .unwrap_or(ENV_OVERRIDE_BEHAVIOR)
    }
    pub fn calc_temp_env(
        &self,
        override_behavior: bool,
        opt_filter: &Option<FilterMatcher>,
    ) -> DEnvOptions<'_> {
        let mut result = DEnvOptions::default();
        fn determine_final_behavior(
            override_behavior: bool,
            opt_filter: &Option<FilterMatcher>,
            final_behavior: &mut EnvBehavior,
            overriden: &mut bool,
            env_behavior: &EnvBehavior,
        ) {
            if !*overriden {
                if let Some(behavior) = opt_filter
                    .as_ref()
                    .and_then(|f| {
                        if override_behavior {
                            *overriden = true;
                            f.env_behavior
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        if env_behavior.is_inherit() {
                            None
                        } else {
                            Some(*env_behavior)
                        }
                    })
                {
                    *final_behavior = behavior;
                }
            }
        }
        #[builder]
        fn assign_env_settings(
            override_behavior: bool,
            opt_filter: &Option<FilterMatcher>,
            result: &mut DEnvOptions<'_>,
            overriden: &mut bool,
            default_behavior: &EnvBehavior,
            keep: &(impl IntoIterator<Item = impl AsRef<str>> + Clone),
            delete: &(impl IntoIterator<Item = impl AsRef<str>> + Clone),
            check: &(impl IntoIterator<Item = impl AsRef<str>> + Clone),
            set: &(impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)> + Clone),
        ) {
            determine_final_behavior(
                override_behavior,
                opt_filter,
                &mut result.default_behavior,
                overriden,
                default_behavior,
            );
            if default_behavior.is_keep() || default_behavior.is_delete() {
                result.set.clear();
                result.keep.clear();
                result.delete.clear();
                result.check.clear();
            }
            result.set.extend(
                set.clone()
                    .into_iter()
                    .filter(|(k, _)| is_valid_env_name(k.as_ref()))
                    .map(|(k, v)| (k.as_ref().to_string().into(), v.as_ref().to_string().into())),
            );
            result.keep.extend(
                keep.clone()
                    .into_iter()
                    .filter(|p| is_valid_env_name(p.as_ref()) || is_regex(p.as_ref()))
                    .map(|k| k.as_ref().to_string().into()),
            );
            result.delete.extend(
                delete
                    .clone()
                    .into_iter()
                    .filter(|p| is_valid_env_name(p.as_ref()) || is_regex(p.as_ref()))
                    .map(|k| k.as_ref().to_string().into()),
            );
            result.check.extend(
                check
                    .clone()
                    .into_iter()
                    .filter(|p| is_valid_env_name(p.as_ref()) || is_regex(p.as_ref()))
                    .map(|k| k.as_ref().to_string().into()),
            );
        }
        let mut overriden = false;
        assign_env_settings()
            .override_behavior(override_behavior)
            .opt_filter(opt_filter)
            .result(&mut result)
            .overriden(&mut overriden)
            .default_behavior(&ENV_DEFAULT_BEHAVIOR)
            .keep(&ENV_KEEP_LIST)
            .check(&ENV_CHECK_LIST)
            .delete(&ENV_DELETE_LIST)
            .set(&ENV_SET_LIST)
            .call();
        [self.config.as_ref(), self.role.as_ref(), self.task.as_ref()]
            .iter()
            .flatten()
            .filter_map(|o| o.env.as_ref())
            .for_each(|o| {
                assign_env_settings()
                    .override_behavior(override_behavior)
                    .opt_filter(opt_filter)
                    .result(&mut result)
                    .overriden(&mut overriden)
                    .default_behavior(&o.default_behavior)
                    .keep(&o.keep)
                    .check(&o.check)
                    .delete(&o.delete)
                    .set(&o.set)
                    .call();
            });
        result
    }

    pub fn calc_bounding(&self) -> SBounding {
        [self.task.as_ref(), self.role.as_ref(), self.config.as_ref()]
            .iter()
            .flatten()
            .filter_map(|o| o.bounding)
            .next()
            .unwrap_or(BOUNDING)
    }
    pub fn calc_timeout(&self) -> STimeout {
        [self.task.as_ref(), self.role.as_ref(), self.config.as_ref()]
            .iter()
            .flatten()
            .filter_map(|o| o.timeout.clone())
            .next()
            .unwrap_or(STimeout {
                type_field: Some(TIMEOUT_TYPE),
                duration: Some(TIMEOUT_DURATION),
                max_usage: Some(TIMEOUT_MAX_USAGE),
                _extra_fields: Map::new(),
            })
    }
    pub fn calc_info(&self) -> SInfo {
        [self.task.as_ref(), self.role.as_ref(), self.config.as_ref()]
            .iter()
            .flatten()
            .filter_map(|o| o.execinfo)
            .next()
            .unwrap_or(INFO)
    }
    pub fn calc_authentication(&self) -> SAuthentication {
        [self.task.as_ref(), self.role.as_ref(), self.config.as_ref()]
            .iter()
            .flatten()
            .filter_map(|o| o.authentication)
            .next()
            .unwrap_or(AUTHENTICATION)
    }
    pub fn calc_privileged(&self) -> SPrivileged {
        [self.task.as_ref(), self.role.as_ref(), self.config.as_ref()]
            .iter()
            .flatten()
            .filter_map(|o| o.root)
            .next()
            .unwrap_or(PRIVILEGED)
    }
}

#[bon::builder]
fn update_security_min(
    security_min: &mut SecurityMin,
    bounding: &Option<SBounding>,
    root: &Option<SPrivileged>,
    authentication: &Option<SAuthentication>,
    env_behavior: &Option<EnvBehavior>,
    override_env: &Option<bool>,
    path_behavior: &Option<PathBehavior>,
) {
    if !security_min.contains(SecurityMin::DisableBounding)
        && bounding.is_some_and(|b| b.is_ignore())
    {
        *security_min |= SecurityMin::DisableBounding;
    }
    if !security_min.contains(SecurityMin::EnableRoot)
        && root.is_some_and(|r| r == SPrivileged::Privileged)
    {
        *security_min |= SecurityMin::EnableRoot;
    }
    if !security_min.contains(SecurityMin::SkipAuth)
        && authentication.is_some_and(|a| a == SAuthentication::Skip)
    {
        *security_min |= SecurityMin::SkipAuth;
    }
    if !security_min.contains(SecurityMin::KeepEnv)
        && env_behavior
            .as_ref()
            .is_some_and(|e| e.is_keep() || override_env.as_ref().is_some_and(|o| *o))
    {
        *security_min |= SecurityMin::KeepEnv;
    }
    if !security_min.contains(SecurityMin::KeepPath)
        && path_behavior.as_ref().is_some_and(|p| p.is_keep_safe())
    {
        *security_min |= SecurityMin::KeepPath;
    }
    if !security_min.contains(SecurityMin::KeepUnsafePath)
        && path_behavior.as_ref().is_some_and(|p| p.is_keep_unsafe())
    {
        *security_min |= SecurityMin::KeepUnsafePath;
    }
}

fn calculate_combined_paths(
    path_var: &[&str],
    combined_paths: &mut Vec<String>,
    default_behavior: &PathBehavior,
    add: &Option<impl IntoIterator<Item = impl AsRef<str> + ToString> + Clone>,
    sub: &Option<impl IntoIterator<Item = impl AsRef<str> + ToString> + Clone>,
) {
    match default_behavior {
        PathBehavior::Inherit => {
            if let Some(ref add_paths) = add {
                combined_paths.extend(add_paths.clone().into_iter().map(|p| p.to_string()));
            }
            if let Some(ref sub_paths) = sub {
                // Avoid allocation by using retain and Cow::Borrowed
                combined_paths.retain(|path| {
                    !sub_paths
                        .clone()
                        .into_iter()
                        .any(|p| path.as_str() == p.as_ref())
                });
            }
        }
        PathBehavior::Delete => {
            combined_paths.clear();
            if let Some(ref add_paths) = add {
                combined_paths.extend(add_paths.clone().into_iter().map(|p| p.to_string()));
            }
        }
        is_safe => {
            combined_paths.clear();
            combined_paths.extend(
                path_var
                    .iter()
                    .map(|s| s.to_string())
                    .filter(|path| is_safe.is_keep_unsafe() || path.starts_with('/')),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_is_valid_env_name() {
        assert!(is_valid_env_name("VAR_NAME"));
        assert!(is_valid_env_name("_VAR_NAME"));
        assert!(!is_valid_env_name("1_VAR_NAME"));
        assert!(!is_valid_env_name("VAR-NAME"));
        assert!(!is_valid_env_name("VAR NAME"));
        assert!(!is_valid_env_name(""));
    }
    #[test]
    fn test_is_regex() {
        #[cfg(feature = "pcre2")]
        assert!(is_regex("^[a-zA-Z0-9_]+$"));
        #[cfg(not(feature = "pcre2"))]
        assert!(!is_regex("^[a-zA-Z0-9_]+$"));
        assert!(!is_regex("[a-z"));
    }

    #[test]
    fn test_test_pattern() {
        #[cfg(feature = "pcre2")]
        assert!(test_pattern("^[a-zA-Z0-9_]+$", "test"));
        #[cfg(not(feature = "pcre2"))]
        assert!(!test_pattern("^[a-zA-Z0-9_]+$", "test"));
        assert!(!test_pattern("[a-z", "test"));
    }

    #[test]
    fn test_check_env() {
        assert!(check_env("TZ", "America/New_York"));
        assert!(!check_env("TZ", "/America/New_York"));
        assert!(!check_env("TZ", "America/New_York/.."));
        assert!(!check_env("VAR_NAME", "VAR%NAME"));
        assert!(check_env("VAR_NAME", "VAR_NAME"));
    }

    #[test]
    fn test_env_matches() {
        let set: HashSet<String> = ["VAR1", "VAR2"].iter().map(|s| s.to_string()).collect();
        assert!(env_matches(&set, &"VAR1".to_string()));
        assert!(!env_matches(&set, &"VAR3".to_string()));
    }

    #[test]
    fn test_calc_path() {
        let path_options = DPathOptions::builder(PathBehavior::Inherit)
            .add(vec!["/usr/local/bin", "/usr/bin"])
            .sub(vec!["/usr/bin"])
            .build();
        let path_var = ["/bin", "/usr/bin"];
        let result = path_options.calc_path(&path_var);
        assert_eq!(result, vec!["/usr/local/bin"]);
    }

    #[test]
    fn test_calc_env() {
        let env_options = DEnvOptions::builder(EnvBehavior::Delete)
            .set(vec![("VAR1", "VALUE1"), ("VAR2", "VALUE2")])
            .keep(vec!["VAR3"])
            .unwrap()
            .delete(vec!["VAR4"])
            .unwrap()
            .check(vec!["VAR5"])
            .unwrap()
            .build();
        let env_vars = vec![
            ("VAR1", "AAAA"),
            ("VAR3", "VALUE3"),
            ("VAR4", "VALUE4"),
            ("VAR5", "VALUE5"),
        ];
        let env_path = vec!["/usr/local/bin", "/usr/bin"];
        let target = Cred::builder().build();
        let result = env_options.calc_final_env(env_vars, &env_path, &target, &None, String::new());
        assert!(
            result.is_ok(),
            "Failed to calculate final env {}",
            result.unwrap_err()
        );
        let final_env = result.unwrap();
        assert_eq!(final_env.get("PATH").unwrap(), "/usr/local/bin:/usr/bin");
        assert_eq!(*final_env.get("RAR_USER").unwrap(), target.user.name);
        assert_eq!(
            *final_env.get("HOME").unwrap(),
            target.user.dir.to_string_lossy()
        );
        assert_eq!(final_env.get("TERM").unwrap(), "unknown");
        assert_eq!(
            *final_env.get("SHELL").unwrap(),
            target.user.shell.to_string_lossy()
        );
        assert_eq!(final_env.get("VAR1").unwrap(), "VALUE1");
        assert_eq!(final_env.get("VAR2").unwrap(), "VALUE2");
        assert_eq!(final_env.get("VAR3").unwrap(), "VALUE3");
        assert!(!final_env.contains_key("VAR4"));
        assert!(final_env.get("VAR5").unwrap() == "VALUE5");

        let env_options = DEnvOptions::builder(EnvBehavior::Keep)
            .set(vec![("VAR1", "VALUE1"), ("VAR2", "VALUE2")])
            .keep(vec!["VAR3"])
            .unwrap()
            .delete(vec!["VAR4"])
            .unwrap()
            .check(vec!["VAR5"])
            .unwrap()
            .build();
        let env_vars = vec![
            ("VAR1", "AAAA"),
            ("VAR3", "VALUE3"),
            ("VAR4", "VALUE4"),
            ("VAR5", "VALUE5"),
        ];
        let env_path = vec!["/usr/local/bin", "/usr/bin"];
        let target = Cred::builder().build();
        let result = env_options.calc_final_env(env_vars, &env_path, &target, &None, String::new());
        assert!(
            result.is_ok(),
            "Failed to calculate final env {}",
            result.unwrap_err()
        );
        let final_env = result.unwrap();
        assert_eq!(final_env.get("PATH").unwrap(), "/usr/local/bin:/usr/bin");
        assert_eq!(*final_env.get("LOGNAME").unwrap(), target.user.name);
        assert_eq!(*final_env.get("USER").unwrap(), target.user.name);
        assert_eq!(
            *final_env.get("HOME").unwrap(),
            target.user.dir.to_string_lossy()
        );
        assert_eq!(final_env.get("TERM").unwrap(), "unknown");
        assert_eq!(
            *final_env.get("SHELL").unwrap(),
            target.user.shell.to_string_lossy()
        );
        assert_eq!(final_env.get("VAR1").unwrap(), "VALUE1");
        assert_eq!(final_env.get("VAR2").unwrap(), "VALUE2");
        assert_eq!(final_env.get("VAR3").unwrap(), "VALUE3");
        assert!(!final_env.contains_key("VAR4"));
        assert!(final_env.get("VAR5").unwrap() == "VALUE5");

        let env_options = DEnvOptions::builder(EnvBehavior::Inherit)
            .set(vec![("VAR1", "VALUE1"), ("VAR2", "VALUE2")])
            .keep(vec!["VAR3"])
            .unwrap()
            .delete(vec!["VAR4"])
            .unwrap()
            .check(vec!["VAR5"])
            .unwrap()
            .build();
        let env_vars = vec![
            ("VAR1", "AAAA"),
            ("VAR3", "VALUE3"),
            ("VAR4", "VALUE4"),
            ("VAR5", "VALUE5"),
        ];
        let env_path = vec!["/usr/local/bin", "/usr/bin"];
        let target = Cred::builder().build();
        let result = env_options.calc_final_env(env_vars, &env_path, &target, &None, String::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_is_default() {
        let default = Opt::default();
        assert!(is_default(&default));
        let non_default = Opt::builder(Level::Default).build();
        assert!(!is_default(&non_default));
    }

    #[test]
    fn test_convert_string_to_duration() {
        let duration = convert_string_to_duration("01:30:00");
        assert!(duration.is_ok());
        assert_eq!(
            duration.unwrap(),
            Some(Duration::hours(1) + Duration::minutes(30))
        );
        let invalid_duration = convert_string_to_duration("invalid");
        assert!(invalid_duration.is_err());
    }

    #[test]
    fn test_borrowed_opt_stack() {
        let config = Some(
            Opt::builder(Level::Global)
                .env(
                    DEnvOptions::builder(EnvBehavior::Delete)
                        .check(["CHECKME"])
                        .unwrap()
                        .set([("VAR1", "VALUE1"), ("VAR2", "VALUE2")])
                        .build(),
                )
                .build(),
        );
        let role = Some(
            Opt::builder(Level::Role)
                .env(
                    DEnvOptions::builder(EnvBehavior::Inherit)
                        .delete(["DELETEME"])
                        .unwrap()
                        .build(),
                )
                .build(),
        );
        let task = Some(
            Opt::builder(Level::Task)
                .env(
                    DEnvOptions::builder(EnvBehavior::Inherit)
                        .keep(["KEEPME"])
                        .unwrap()
                        .build(),
                )
                .build(),
        );
        let mut stack = BorrowedOptStack::new(config);
        stack._set_role(role);
        stack._set_task(task);
        assert_eq!(
            stack.calc_path(&["/test"]),
            env!("RAR_PATH_ADD_LIST").split(':').collect::<Vec<&str>>()
        );
        let env = stack.calc_temp_env(false, &None);
        assert_eq!(env.delete, HashSet::from(["DELETEME".into()]));
        assert_eq!(env.keep, HashSet::from(["KEEPME".into()]));
        assert_eq!(env.check, HashSet::from(["CHECKME".into()]));
        assert_eq!(
            env.set,
            HashMap::from([
                ("VAR1".into(), "VALUE1".into()),
                ("VAR2".into(), "VALUE2".into())
            ])
        );
    }

    #[test]
    fn test_opt_into_opt() {
        let opt = Opt::builder(Level::Default)
            .path(
                DPathOptions::builder(PathBehavior::Inherit)
                    .add(["/usr/local/bin"])
                    .build(),
            )
            .env(
                DEnvOptions::builder(EnvBehavior::Keep)
                    .set([("VAR1", "VALUE1")])
                    .build(),
            )
            .build();
        let rar_opt: rar_common::database::options::Opt = opt.clone().into();
        assert_eq!(rar_opt.level, Level::Default);
        assert_eq!(
            rar_opt.path.unwrap().default_behavior,
            PathBehavior::Inherit
        );
        assert_eq!(rar_opt.env.unwrap().default_behavior, EnvBehavior::Keep);
    }
}
