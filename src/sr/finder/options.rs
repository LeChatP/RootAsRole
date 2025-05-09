use std::collections::HashSet;
use std::error::Error;
use std::{borrow::Cow, collections::HashMap};

use bon::{bon, builder, Builder};
use chrono::Duration;

use libc::PATH_MAX;
use rar_common::database::options::{
    EnvBehavior, Level, PathBehavior, SAuthentication, SBounding, SPathOptions, SPrivileged,
    STimeout,
};
use rar_common::database::score::SecurityMin;
use rar_common::database::FilterMatcher;
use std::hash::Hash;

#[cfg(feature = "pcre2")]
use pcre2::bytes::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use log::debug;

use crate::Cred;

use super::de::DLinkedTask;

//#[cfg(feature = "finder")]
//use super::finder::Cred;
//#[cfg(feature = "finder")]
//use super::finder::SecurityMin;
fn default<'a>() -> Opt<'a> {
    Opt::builder(Level::Default)
        .maybe_root(env!("RAR_USER_CONSIDERED").parse().ok())
        .maybe_bounding(env!("RAR_BOUNDING").parse().ok())
        .path(DPathOptions::default_path())
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
        .wildcard_denied(env!("RAR_WILDCARD_DENIED"))
        .build()
}

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
pub struct SEnvOptions<'a> {
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
    #[serde(borrow, skip_serializing_if = "HashSet::is_empty")]
    #[builder(default, with = |v : impl IntoIterator<Item = impl Into<Cow<'a,str>>>| -> Result<_,Cow<'a,str>> { let mut res = HashSet::new(); for s in v { res.insert(s.into()); } Ok(res)})]
    pub check: HashSet<Cow<'a, str>>,
    #[serde(borrow, skip_serializing_if = "HashSet::is_empty")]
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
    pub env: Option<SEnvOptions<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<SPrivileged>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bounding: Option<SBounding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SAuthentication>,
    #[serde(borrow, skip_serializing_if = "Option::is_none")]
    pub wildcard_denied: Option<Cow<'a, str>>,
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
        env: Option<SEnvOptions<'a>>,
        root: Option<SPrivileged>,
        bounding: Option<SBounding>,
        authentication: Option<SAuthentication>,
        #[builder(into)] wildcard_denied: Option<Cow<'a, str>>,
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
            wildcard_denied,
            timeout,
            _extra_fields,
        }
    }
}

impl<'a> SEnvOptions<'a> {
    pub fn calc_final_env(
        &self,
        env_vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
        env_path: &[&str],
        target: &Cred,
    ) -> Result<HashMap<String, String>, Box<dyn Error>> {
        let mut final_set = match self.default_behavior {
            EnvBehavior::Inherit => Err("Internal Error with environment behavior".to_string()),
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
            env_path.iter().fold(String::new(), |acc, path| {
                if acc.is_empty() {
                    path.to_string()
                } else {
                    format!("{}:{}", acc, path)
                }
            }),
        );
        final_set.insert("LOGNAME".into(), target.user.name.clone());
        final_set.insert("USER".into(), target.user.name.clone());
        final_set.insert("HOME".into(), target.user.dir.to_string_lossy().to_string());
        final_set
            .entry("TERM".into())
            .or_insert_with(|| "unknown".into());
        final_set.insert(
            "SHELL".into(),
            target.user.shell.to_string_lossy().to_string(),
        );
        Ok(final_set)
    }
}

impl Into<rar_common::database::options::Opt> for Opt<'_> {
    fn into(self) -> rar_common::database::options::Opt {
        rar_common::database::options::Opt::builder(self.level)
            .maybe_path(if let Some(spath) = self.path {
                Some(
                    rar_common::database::options::SPathOptions::builder(spath.default_behavior)
                        .maybe_add(
                            spath
                                .add
                                .map(|v| v.into_iter().map(|s| s.to_string()).collect::<Vec<_>>()),
                        )
                        .maybe_sub(
                            spath
                                .sub
                                .map(|v| v.into_iter().map(|s| s.to_string()).collect::<Vec<_>>()),
                        )
                        .build(),
                )
            } else {
                None
            })
            .maybe_env(if let Some(senv) = self.env {
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
            .maybe_root(self.root)
            .maybe_bounding(self.bounding)
            .maybe_authentication(self.authentication)
            .maybe_wildcard_denied(self.wildcard_denied)
            .maybe_timeout(self.timeout)
            .build()
    }
}

impl Into<SPathOptions> for DPathOptions<'_> {
    fn into(self) -> SPathOptions {
        SPathOptions::builder(self.default_behavior)
            .maybe_add(
                self.add
                    .map(|v| v.into_iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            )
            .maybe_sub(
                self.sub
                    .map(|v| v.into_iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            )
            .build()
    }
}

impl DPathOptions<'_> {
    pub fn default_path<'a>() -> DPathOptions<'a> {
        DPathOptions::builder(
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
                        .extend_from_slice(&add);
                }
                if let Some(sub) = &path_options.sub {
                    self.sub
                        .get_or_insert_with(Default::default)
                        .to_mut()
                        .extend_from_slice(&sub);
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
    set.contains(&needle) || set.iter().any(|key| test_pattern(&needle, key.as_ref()))
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
    true // Always return true if regex feature is disabled
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

fn convert_string_to_duration(s: &String) -> Result<Option<chrono::TimeDelta>, Box<dyn Error>> {
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

pub struct BorrowedOptStack<'a> {
    default_opt: Opt<'a>,
    config: Option<Opt<'a>>,
    role: Option<Opt<'a>>,
    task: Option<Opt<'a>>,
}

impl<'a, 'b, 'c, 't> BorrowedOptStack<'a> {
    pub fn new(config: Option<Opt<'a>>) -> Self {
        Self {
            default_opt: default(),
            config,
            role: None,
            task: None,
        }
    }
    pub fn set_role(&mut self, role: Option<Opt<'a>>) {
        self.role = role;
    }
    pub fn set_task(&mut self, task: Option<Opt<'a>>) {
        self.task = task;
    }
    pub fn from_task(task: &DLinkedTask<'t, 'c, 'a>) -> Self {
        let default_opt = default();
        let config = task.role().config().options.clone();
        let role = task.role().role().options.clone();
        let task_opt = task.task.options.clone();
        Self {
            default_opt,
            config,
            role,
            task: task_opt,
        }
    }
    pub fn calc_path(&self, path_var: &[&str]) -> Vec<String> {
        // Preallocate with a reasonable guess, but will only allocate once.
        let mut combined_paths: Vec<String> = Vec::with_capacity(path_var.len());

        // Stack of options in order: default, config, role, task
        let stack = [
            Some(&self.default_opt),
            self.config.as_ref(),
            self.role.as_ref(),
            self.task.as_ref(),
        ];

        for opt in stack.iter().flatten() {
            if let Some(ref path_opt) = opt.path {
                match path_opt.default_behavior {
                    PathBehavior::Inherit => {
                        if let Some(ref add_paths) = path_opt.add {
                            combined_paths.extend(add_paths.iter().map(|p| p.to_string()));
                        }
                        if let Some(ref sub_paths) = path_opt.sub {
                            // Avoid allocation by using retain and Cow::Borrowed
                            combined_paths.retain(|path| !sub_paths.contains(&Cow::Borrowed(path)));
                        }
                    }
                    PathBehavior::Delete => {
                        combined_paths.clear();
                        if let Some(ref add_paths) = path_opt.add {
                            combined_paths.extend(add_paths.iter().map(|p| p.to_string()));
                        }
                    }
                    ref is_safe => {
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
        }
        combined_paths
    }

    pub fn calc_security_min(&self) -> SecurityMin {
        let mut security_min = SecurityMin::default();
        // todo: fix the algorithm
        [
            self.task.as_ref(),
            self.role.as_ref(),
            self.config.as_ref(),
            Some(&self.default_opt),
        ]
        .iter()
        .flatten()
        .for_each(|o| {
            if !security_min.contains(SecurityMin::DisableBounding)
                && o.bounding.is_some_and(|b| b.is_ignore())
            {
                security_min |= SecurityMin::DisableBounding;
            }
            if !security_min.contains(SecurityMin::EnableRoot)
                && o.root.is_some_and(|r| r == SPrivileged::Privileged)
            {
                security_min |= SecurityMin::EnableRoot;
            }
            if !security_min.contains(SecurityMin::SkipAuth)
                && o.authentication.is_some_and(|a| a == SAuthentication::Skip)
            {
                security_min |= SecurityMin::SkipAuth;
            }
            if !security_min.contains(SecurityMin::KeepEnv)
                && o.env.as_ref().is_some_and(|e| {
                    e.default_behavior.is_keep() || e.override_behavior.as_ref().is_some_and(|o| *o)
                })
            {
                security_min |= SecurityMin::KeepEnv;
            }
            if !security_min.contains(SecurityMin::KeepPath)
                && o.path
                    .as_ref()
                    .is_some_and(|p| p.default_behavior.is_keep_safe())
            {
                security_min |= SecurityMin::KeepPath;
            }
            if !security_min.contains(SecurityMin::KeepUnsafePath)
                && o.path
                    .as_ref()
                    .is_some_and(|p| p.default_behavior.is_keep_unsafe())
            {
                security_min |= SecurityMin::KeepUnsafePath;
            }
        });
        security_min
    }

    pub fn calc_override_behavior(&self) -> Option<bool> {
        [
            self.task.as_ref(),
            self.role.as_ref(),
            self.config.as_ref(),
            Some(&self.default_opt),
        ]
        .iter()
        .flatten()
        .filter_map(|o| o.env.as_ref())
        .find_map(|o| o.override_behavior)
    }
    pub fn calc_temp_env(
        &self,
        override_behavior: &Option<bool>,
        opt_filter: &Option<FilterMatcher>,
    ) -> SEnvOptions<'_> {
        let mut result = SEnvOptions::default();
        fn determine_final_behavior<'a>(
            override_behavior: &Option<bool>,
            opt_filter: &Option<FilterMatcher>,
            final_behavior: &mut EnvBehavior,
            overriden: &mut bool,
            o: &SEnvOptions<'_>,
        ) {
            if !*overriden {
                if let Some(behavior) = opt_filter
                    .as_ref()
                    .and_then(|f| {
                        if override_behavior.is_some_and(|o| o) {
                            *overriden = true;
                            f.env_behavior
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        if o.default_behavior.is_inherit() {
                            None
                        } else {
                            Some(o.default_behavior)
                        }
                    })
                {
                    *final_behavior = behavior;
                }
            }
        }
        let mut overriden = false;
        [
            Some(&self.default_opt),
            self.config.as_ref(),
            self.role.as_ref(),
            self.task.as_ref(),
        ]
        .iter()
        .flatten()
        .filter_map(|o| o.env.as_ref())
        .for_each(|o| {
            determine_final_behavior(
                &override_behavior,
                &opt_filter,
                &mut result.default_behavior,
                &mut overriden,
                o,
            );
            if o.default_behavior.is_keep() || o.default_behavior.is_delete() {
                result.set.clear();
                result.keep.clear();
                result.delete.clear();
                result.check.clear();
            }
            result.set.extend(
                o.set
                    .iter()
                    .filter(|(k, _)| is_valid_env_name(k.as_ref()))
                    .map(|(k, v)| (k.to_string().into(), v.to_string().into())),
            );
            result.keep.extend(
                o.keep
                    .iter()
                    .cloned()
                    .filter(|p| is_valid_env_name(p.as_ref()) || is_regex(p.as_ref()))
                    .map(|k| k.to_string().into()),
            );
            result.delete.extend(
                o.delete
                    .iter()
                    .cloned()
                    .filter(|p| is_valid_env_name(p.as_ref()) || is_regex(p.as_ref()))
                    .map(|k| k.to_string().into()),
            );
            result.check.extend(
                o.check
                    .iter()
                    .cloned()
                    .filter(|p| is_valid_env_name(p.as_ref()) || is_regex(p.as_ref()))
                    .map(|k| k.to_string().into()),
            );
        });
        result
    }

    pub fn calc_bounding(&self) -> SBounding {
        [
            self.task.as_ref(),
            self.role.as_ref(),
            self.config.as_ref(),
            Some(&self.default_opt),
        ]
        .iter()
        .flatten()
        .filter_map(|o| o.bounding)
        .next()
        .unwrap_or(SBounding::default())
    }
    pub fn calc_timeout(&self) -> STimeout {
        [
            self.task.as_ref(),
            self.role.as_ref(),
            self.config.as_ref(),
            Some(&self.default_opt),
        ]
        .iter()
        .flatten()
        .filter_map(|o| o.timeout.clone())
        .next()
        .unwrap_or(STimeout::default())
    }
    pub fn calc_authentication(&self) -> SAuthentication {
        [
            self.task.as_ref(),
            self.role.as_ref(),
            self.config.as_ref(),
            Some(&self.default_opt),
        ]
        .iter()
        .flatten()
        .filter_map(|o| o.authentication)
        .next()
        .unwrap_or(SAuthentication::default())
    }
    pub fn calc_privileged(&self) -> SPrivileged {
        [
            self.task.as_ref(),
            self.role.as_ref(),
            self.config.as_ref(),
            Some(&self.default_opt),
        ]
        .iter()
        .flatten()
        .filter_map(|o| o.root)
        .next()
        .unwrap_or(SPrivileged::default())
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
}
