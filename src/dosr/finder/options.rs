use std::collections::HashSet;
use std::path::PathBuf;
use std::{
    borrow::{Borrow, Cow},
    collections::HashMap,
};

use bon::{Builder, bon, builder};

use libc::PATH_MAX;
use nix::unistd::User;
use rootasrole_core::database::FilterMatcher;
use rootasrole_core::database::options::{
    EnvBehavior, Level, PathBehavior, SAuthentication, SBounding, SInfo, SPathOptions, SPrivileged,
    STimeout, SUMask, WorkdirBehavior,
};
use rootasrole_core::database::score::SecurityMin;
use rootasrole_core::util::{
    AUTHENTICATION, BOUNDING, ENV_CHECK_LIST, ENV_DEFAULT_BEHAVIOR, ENV_DELETE_LIST, ENV_KEEP_LIST,
    ENV_OVERRIDE_BEHAVIOR, ENV_PATH_ADD_LIST_SLICE, ENV_PATH_BEHAVIOR, ENV_PATH_REMOVE_LIST_SLICE,
    ENV_SET_LIST, INFO, PRIVILEGED, TIMEOUT_DURATION, TIMEOUT_MAX_USAGE, TIMEOUT_TYPE, UMASK,
    WORKDIR_ADD_LIST, WORKDIR_BEHAVIOR, WORKDIR_FALLBACK, WORKDIR_REMOVE_LIST, is_shell_function,
    is_valid_env_name, is_valid_env_pattern, wildcard_match,
};
use std::hash::Hash;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use log::{debug, error};

use crate::Cred;
use crate::error::{SrError, SrResult};

use super::de::DLinkedTask;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Builder, Default)]
pub struct DPathOptions<'a> {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default_behavior: PathBehavior,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    #[builder(with = |v : impl IntoIterator<Item = impl Into<Cow<'a, str>>>| { v.into_iter().map(std::convert::Into::into).collect() })]
    pub add: Option<Cow<'a, [Cow<'a, str>]>>,
    #[serde(
        borrow,
        default,
        skip_serializing_if = "Option::is_none",
        alias = "del"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl Into<Cow<'a, str>>>| { v.into_iter().map(std::convert::Into::into).collect() })]
    pub sub: Option<Cow<'a, [Cow<'a, str>]>>,
}

/// Environment options of a level, borrowed from the policy (see `SEnvOptions` in
/// rootasrole-core). A list that the level does not define is `None`, and is inherited.
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone, Default, Builder)]
pub struct DEnvOptions<'a> {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default_behavior: EnvBehavior,
    #[serde(alias = "override", default, skip_serializing_if = "Option::is_none")]
    pub override_behavior: Option<bool>,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    #[builder(with = |iter: impl IntoIterator<Item = (impl Into<Cow<'a,str>>, impl Into<Cow<'a,str>>)>| {
        let mut map = HashMap::with_hasher(Default::default());
        map.extend(iter.into_iter().map(|(k, v)| (k.into(), v.into())));
        map
    })]
    pub set: Option<HashMap<Cow<'a, str>, Cow<'a, str>>>,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    #[builder(with = |v : impl IntoIterator<Item = impl Into<Cow<'a,str>>>| -> Result<_,Cow<'a,str>> { let mut res = HashSet::new(); for s in v { res.insert(s.into()); } Ok(res)})]
    pub keep: Option<HashSet<Cow<'a, str>>>,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    #[builder(with = |v : impl IntoIterator<Item = impl Into<Cow<'a,str>>>| -> Result<_,Cow<'a,str>> { let mut res = HashSet::new(); for s in v { res.insert(s.into()); } Ok(res)})]
    pub check: Option<HashSet<Cow<'a, str>>>,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    #[builder(with = |v : impl IntoIterator<Item = impl Into<Cow<'a,str>>>| -> Result<_,Cow<'a,str>> { let mut res = HashSet::new(); for s in v { res.insert(s.into()); } Ok(res)})]
    pub delete: Option<HashSet<Cow<'a, str>>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(untagged)]
pub enum DWorkdirEither<'a> {
    /// This is the equivalent of deny all and fallback to the specified path.
    #[serde(borrow)]
    Path(Cow<'a, str>),
    #[serde(borrow)]
    Struct(DWorkdirSet<'a>),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default, Builder)]
pub struct DWorkdirSet<'a> {
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
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<Cow<'a, str>>,

    #[serde(borrow, default, skip_serializing_if = "HashSet::is_empty")]
    #[builder(with = |v : impl IntoIterator<Item = impl Into<Cow<'a, str>>>| { v.into_iter().map(std::convert::Into::into).collect() })]
    pub add: HashSet<Cow<'a, str>>,
    #[serde(
        borrow,
        default,
        skip_serializing_if = "HashSet::is_empty",
        alias = "del"
    )]
    #[builder(with = |v : impl IntoIterator<Item = impl Into<Cow<'a, str>>>| { v.into_iter().map(std::convert::Into::into).collect() })]
    pub sub: HashSet<Cow<'a, str>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct Opt<'a> {
    #[serde(skip)]
    pub level: Level,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub path: Option<DPathOptions<'a>>,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub env: Option<DEnvOptions<'a>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<SPrivileged>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounding: Option<SBounding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SAuthentication>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execinfo: Option<SInfo>,
    #[serde(borrow, default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<DWorkdirEither<'a>>, // we only need to store the enforced workdir, if existing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<STimeout>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub umask: Option<SUMask>,
    #[serde(default, flatten)]
    pub extra_fields: Value,
}

#[bon]
impl<'a> Opt<'a> {
    #[builder]
    pub const fn new(
        #[builder(start_fn)] level: Level,
        path: Option<DPathOptions<'a>>,
        env: Option<DEnvOptions<'a>>,
        root: Option<SPrivileged>,
        bounding: Option<SBounding>,
        authentication: Option<SAuthentication>,
        execinfo: Option<SInfo>,
        workdir: Option<DWorkdirEither<'a>>,
        timeout: Option<STimeout>,
        umask: Option<SUMask>,
        #[builder(default)] extra_fields: Value,
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
            umask,
            extra_fields,
        }
    }
}

impl DEnvOptions<'_> {
    /// Whether a variable of the user's environment is passed to the command:
    /// - shell function definitions are never passed (`is_shell_function`, in rootasrole-core),
    /// - in delete mode, only the variables of the keep and check lists are passed,
    /// - in keep mode, every variable is passed except those of the delete list,
    /// - in both modes, a variable of the check list is passed only if its value is safe.
    fn keep_user_var(&self, key: &str, value: &str) -> bool {
        if is_shell_function(value) {
            return false;
        }
        let checked = || !env_matches(self.check.as_ref(), key) || check_env(key, value);
        match self.default_behavior {
            EnvBehavior::Delete => {
                if env_matches(self.check.as_ref(), key) {
                    check_env(key, value)
                } else {
                    env_matches(self.keep.as_ref(), key)
                }
            }
            EnvBehavior::Keep => !env_matches(self.delete.as_ref(), key) && checked(),
            EnvBehavior::Inherit => false,
        }
    }

    pub fn calc_final_env(
        &self,
        env_vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
        env_path: impl IntoIterator<Item = impl AsRef<str>>,
        current_user: &Cred,
        target: Option<&User>,
        command: String,
    ) -> SrResult<HashMap<String, String>> {
        if self.default_behavior == EnvBehavior::Inherit {
            error!("Internal Error with environment behavior");
            return Err(SrError::ConfigurationError);
        }
        let mut final_set = env_vars
            .into_iter()
            .filter_map(|(key, value)| {
                let key: String = key.into();
                let value: String = value.into();
                self.keep_user_var(&key, &value).then_some((key, value))
            })
            .collect::<HashMap<String, String>>();
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
        let target_user = target.unwrap_or(&current_user.user);
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
        final_set.insert("RAR_COMMAND".into(), command.clone());
        final_set.insert("SUDO_UID".into(), current_user.user.uid.to_string());
        final_set.insert("SUDO_GID".into(), current_user.user.gid.to_string());
        final_set.insert("SUDO_USER".into(), current_user.user.name.clone());
        final_set.insert("SUDO_COMMAND".into(), command);
        final_set
            .entry("TERM".into())
            .or_insert_with(|| "unknown".into());
        final_set.extend(
            self.set
                .iter()
                .flatten()
                .map(|(key, value)| (key.to_string(), value.to_string())),
        );
        Ok(final_set)
    }
}

#[allow(clippy::fallible_impl_from)] // Not actually fallible, as long as the input is valid, which it should be since it's internal.
#[allow(clippy::unwrap_used)] // Input is a mirror of the internal opt.
impl From<Opt<'_>> for rootasrole_core::database::options::Opt {
    fn from(val: Opt<'_>) -> Self {
        Self::builder(val.level)
            .maybe_path(if let Some(spath) = val.path {
                Some(
                    rootasrole_core::database::options::SPathOptions::builder(
                        spath.default_behavior,
                    )
                    .maybe_add(spath.add.map(|v| {
                        v.iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                    }))
                    .maybe_sub(spath.sub.map(|v| {
                        v.iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<_>>()
                    }))
                    .build(),
                )
            } else {
                None
            })
            .maybe_env(val.env.map(|senv| {
                // an undefined list stays undefined, so that it is still inherited
                let keys = |list: Option<HashSet<Cow<'_, str>>>| {
                    list.map(|list| {
                        list.iter()
                            .map(|v| rootasrole_core::database::options::EnvKey::new(v.to_string()))
                            .collect::<Result<_, _>>()
                            .unwrap()
                    })
                };
                let mut env =
                    rootasrole_core::database::options::SEnvOptions::builder(senv.default_behavior)
                        .maybe_override_behavior(senv.override_behavior)
                        .build();
                env.set = senv.set.map(|set| {
                    set.into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect()
                });
                env.keep = keys(senv.keep);
                env.check = keys(senv.check);
                env.delete = keys(senv.delete);
                env
            }))
            .maybe_root(val.root)
            .maybe_bounding(val.bounding)
            .maybe_authentication(val.authentication)
            .maybe_timeout(val.timeout)
            .build()
    }
}

impl From<DPathOptions<'_>> for SPathOptions {
    fn from(val: DPathOptions<'_>) -> Self {
        Self::builder(val.default_behavior)
            .maybe_add(val.add.map(|v| {
                v.iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
            }))
            .maybe_sub(val.sub.map(|v| {
                v.iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
            }))
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
        let default = Cow::default();
        match self.default_behavior {
            PathBehavior::Inherit | PathBehavior::Delete => {
                self.add.as_ref().map_or_else(Vec::new, |add| {
                    let sub = self.sub.as_ref().unwrap_or(&default);
                    add.iter()
                        .filter(|item| !sub.contains(*item))
                        .map(std::convert::AsRef::as_ref)
                        .collect()
                })
            }
            is_safe => {
                let sub = self.sub.as_ref();
                self.add
                    .as_ref()
                    .map(|cow| cow.iter())
                    .into_iter()
                    .flatten()
                    .map(std::convert::AsRef::as_ref)
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

impl DPathOptions<'_> {
    pub fn union(&mut self, path_options: &Self) {
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
                self.add.clone_from(&path_options.add);
                self.sub.clone_from(&path_options.sub);
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

fn env_matches<K>(set: Option<&HashSet<K>>, needle: &str) -> bool
where
    K: AsRef<str> + Eq + Hash + Borrow<str>,
{
    // the policy entries are the patterns, never the user's variable name
    set.is_some_and(|set| {
        set.contains(needle) || set.iter().any(|key| wildcard_match(key.as_ref(), needle))
    })
}

fn tz_is_safe(tzval: &str) -> bool {
    // tzcode treats a value beginning with a ':' as a path.
    let tzval = tzval.strip_prefix(':').map_or(tzval, |val| val);

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
            && tzval.chars().nth({
                let Some(pos) = tzval.chars().position(|c| c == '.') else {
                    return false;
                };
                pos + 1
            }) == Some('.')
            && (tzval.chars().nth({
                let Some(pos) = tzval.chars().position(|c| c == '.') else {
                    return false;
                };
                pos + 2
            }) == Some('/')
                || tzval
                    .chars()
                    .nth({
                        let Some(pos) = tzval.chars().position(|c| c == '.') else {
                            return false;
                        };
                        pos + 2
                    })
                    .is_none())
        {
            return false;
        }
        lastch = cp;
    }

    // Reject extra long TZ values (even if not a path).
    let Ok(path_max) = <i32 as TryInto<usize>>::try_into(PATH_MAX) else {
        return false;
    };
    if tzval.len() >= path_max {
        return false;
    }

    true
}

pub fn is_default<T: PartialEq + Default>(t: &T) -> bool {
    t == &T::default()
}

pub struct BorrowedOptStack<'a> {
    config: Option<Opt<'a>>,
    role: Option<Opt<'a>>,
    task: Option<Opt<'a>>,
}

impl<'a, 'c, 't> BorrowedOptStack<'a> {
    pub const fn new(config: Option<Opt<'a>>) -> Self {
        Self {
            config,
            role: None,
            task: None,
        }
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
        self.role.clone_from(&role.role().role().options);
    }
    pub fn set_task(&mut self, task: &DLinkedTask<'t, 'c, 'a>) {
        self.task.clone_from(&task.task.options);
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
            ENV_PATH_BEHAVIOR,
            Some(ENV_PATH_ADD_LIST_SLICE),
            Some(ENV_PATH_REMOVE_LIST_SLICE),
        );

        for path_opt in stack.iter().flatten() {
            calculate_combined_paths(
                path_var,
                &mut combined_paths,
                path_opt.default_behavior,
                path_opt.add.as_ref().map(|v| v.iter()),
                path_opt.sub.as_ref().map(|v| v.iter()),
            );
        }
        combined_paths
    }

    pub fn calc_security_min(&self) -> SecurityMin {
        let mut security_min = SecurityMin::default();
        self.get_opt_iter_rev().for_each(|o| {
            update_security_min()
                .security_min(&mut security_min)
                .maybe_bounding(o.bounding.as_ref())
                .maybe_root(o.root.as_ref())
                .maybe_authentication(o.authentication.as_ref())
                .maybe_env_behavior(o.env.as_ref().map(|e| e.default_behavior).as_ref())
                .maybe_override_env(o.env.as_ref().and_then(|e| e.override_behavior).as_ref())
                .maybe_path_behavior(o.path.as_ref().map(|p| p.default_behavior).as_ref())
                .call();
        });
        update_security_min()
            .security_min(&mut security_min)
            .bounding(&BOUNDING)
            .root(&PRIVILEGED)
            .authentication(&AUTHENTICATION)
            .env_behavior(&ENV_DEFAULT_BEHAVIOR)
            .override_env(&ENV_OVERRIDE_BEHAVIOR)
            .path_behavior(&ENV_PATH_BEHAVIOR)
            .call();
        security_min
    }

    pub fn calc_override_behavior(&self) -> bool {
        self.get_opt_iter_rev()
            .filter_map(|o| o.env.as_ref())
            .find_map(|o| o.override_behavior)
            .unwrap_or(ENV_OVERRIDE_BEHAVIOR)
    }
    #[allow(clippy::too_many_lines)]
    pub fn calc_temp_env(
        &self,
        override_behavior: bool,
        opt_filter: Option<&FilterMatcher>,
    ) -> DEnvOptions<'_> {
        fn determine_final_behavior(
            override_behavior: bool,
            opt_filter: Option<&FilterMatcher>,
            final_behavior: &mut EnvBehavior,
            overriden: &mut bool,
            env_behavior: EnvBehavior,
        ) {
            if !*overriden
                && let Some(behavior) = opt_filter
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
                            Some(env_behavior)
                        }
                    })
            {
                *final_behavior = behavior;
            }
        }
        /// Merge a list of one level into the lists of the upper levels. A list that the level
        /// does not define is inherited, even when the level sets its own behavior; a defined
        /// list replaces the inherited one when the level sets its behavior, and extends it
        /// otherwise. Only an empty list (`[]`) removes an inherited list: see `SEnvOptions` in
        /// rootasrole-core for why this is the fail-safe choice.
        fn merge_list(
            result: &mut Option<HashSet<Cow<'_, str>>>,
            list: Option<impl IntoIterator<Item = impl AsRef<str>>>,
            replace: bool,
        ) {
            let Some(list) = list else {
                return;
            };
            let result = result.get_or_insert_default();
            if replace {
                result.clear();
            }
            result.extend(list.into_iter().map(|k| k.as_ref().to_string().into()));
        }
        /// Same as `merge_list`, for the variables set by the policy.
        fn merge_set(
            result: &mut Option<HashMap<Cow<'_, str>, Cow<'_, str>>>,
            set: Option<impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>>,
            replace: bool,
        ) {
            let Some(set) = set else {
                return;
            };
            let result = result.get_or_insert_default();
            if replace {
                result.clear();
            }
            result.extend(
                set.into_iter()
                    .map(|(k, v)| (k.as_ref().to_string().into(), v.as_ref().to_string().into())),
            );
        }
        #[builder]
        fn assign_env_settings(
            override_behavior: bool,
            opt_filter: Option<&FilterMatcher>,
            result: &mut DEnvOptions<'_>,
            overriden: &mut bool,
            default_behavior: EnvBehavior,
            keep: Option<impl IntoIterator<Item = impl AsRef<str>>>,
            delete: Option<impl IntoIterator<Item = impl AsRef<str>>>,
            check: Option<impl IntoIterator<Item = impl AsRef<str>>>,
            set: Option<impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>>,
        ) {
            determine_final_behavior(
                override_behavior,
                opt_filter,
                &mut result.default_behavior,
                overriden,
                default_behavior,
            );
            let replace = !default_behavior.is_inherit();
            merge_set(&mut result.set, set, replace);
            merge_list(&mut result.keep, keep, replace);
            merge_list(&mut result.delete, delete, replace);
            merge_list(&mut result.check, check, replace);
        }
        let mut result = DEnvOptions::default();
        let mut overriden = false;
        assign_env_settings()
            .override_behavior(override_behavior)
            .maybe_opt_filter(opt_filter)
            .result(&mut result)
            .overriden(&mut overriden)
            .default_behavior(ENV_DEFAULT_BEHAVIOR)
            .keep(ENV_KEEP_LIST.iter().copied())
            .check(ENV_CHECK_LIST.iter().copied())
            .delete(ENV_DELETE_LIST.iter().copied())
            .set(ENV_SET_LIST.iter().copied())
            .call();
        self.get_opt_iter()
            .filter_map(|o| o.env.as_ref())
            .for_each(|o| {
                assign_env_settings()
                    .override_behavior(override_behavior)
                    .maybe_opt_filter(opt_filter)
                    .result(&mut result)
                    .overriden(&mut overriden)
                    .default_behavior(o.default_behavior)
                    .maybe_keep(o.keep.as_ref())
                    .maybe_check(o.check.as_ref())
                    .maybe_delete(o.delete.as_ref())
                    .maybe_set(o.set.as_ref())
                    .call();
            });
        result
    }

    pub fn calc_bounding(&self) -> SBounding {
        self.get_opt_iter_rev()
            .find_map(|o| o.bounding)
            .unwrap_or(BOUNDING)
    }

    /// First env entry, at any level, that is not a variable name (`*` allowed as a wildcard,
    /// except in the names of the `set` list). Tasks inheriting such an entry are denied.
    pub fn invalid_env_entry(&self) -> Option<&str> {
        self.get_opt_iter()
            .filter_map(|o| o.env.as_ref())
            .find_map(|env| {
                [&env.keep, &env.check, &env.delete]
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(AsRef::as_ref)
                    .find(|entry| !is_valid_env_pattern(entry))
                    .or_else(|| {
                        env.set
                            .iter()
                            .flat_map(HashMap::keys)
                            .map(AsRef::as_ref)
                            .find(|name| !is_valid_env_name(name))
                    })
            })
    }

    pub fn get_opt_iter(&self) -> impl Iterator<Item = &Opt<'a>> {
        [self.config.as_ref(), self.role.as_ref(), self.task.as_ref()]
            .into_iter()
            .flatten()
    }

    pub fn get_opt_iter_rev(&self) -> impl Iterator<Item = &Opt<'a>> {
        [self.task.as_ref(), self.role.as_ref(), self.config.as_ref()]
            .into_iter()
            .flatten()
    }

    pub fn calc_timeout(&self) -> STimeout {
        self.get_opt_iter_rev()
            .find_map(|o| o.timeout.clone())
            .unwrap_or_else(|| STimeout {
                type_field: Some(TIMEOUT_TYPE),
                duration: TIMEOUT_DURATION,
                max_usage: TIMEOUT_MAX_USAGE,
                extra_fields: Map::new(),
            })
    }
    pub fn calc_info(&self) -> SInfo {
        self.get_opt_iter_rev()
            .find_map(|o| o.execinfo)
            .unwrap_or(INFO)
    }
    pub fn calc_authentication(&self) -> SAuthentication {
        self.get_opt_iter_rev()
            .find_map(|o| o.authentication)
            .unwrap_or(AUTHENTICATION)
    }
    pub fn calc_privileged(&self) -> SPrivileged {
        self.get_opt_iter_rev()
            .find_map(|o| o.root)
            .unwrap_or(PRIVILEGED)
    }
    pub fn calc_umask(&self) -> SUMask {
        self.get_opt_iter_rev()
            .find_map(|o| o.umask)
            .unwrap_or(UMASK)
    }
    pub fn calc_workdir(&self) -> Option<PathBuf> {
        self.get_opt_iter_rev()
            .filter_map(|o| o.workdir.as_ref())
            .find_map(|w| match w {
                DWorkdirEither::Path(p) => Some(p.as_ref().into()),
                DWorkdirEither::Struct(s) => s.fallback.as_ref().map(|f| f.to_string().into()),
            })
    }
    pub fn get_workdir_temp(&self) -> DWorkdirSet<'_> {
        #[builder]
        #[allow(clippy::ref_option)] // Because builder do not handle it well.
        fn assign_workdir_settings(
            result: &mut DWorkdirSet<'_>,
            default_behavior: WorkdirBehavior,
            add: &(impl IntoIterator<Item = impl AsRef<str>> + Clone),
            del: &(impl IntoIterator<Item = impl AsRef<str>> + Clone),
            fallback: &Option<impl AsRef<str>>,
        ) {
            // we reset as long there is a new default behavior, we don't inherit
            if default_behavior.is_allowlist() || default_behavior.is_blacklist() {
                result.add.clear();
                result.sub.clear();
                result.fallback.take();
            }
            result.add.extend(
                add.clone()
                    .into_iter()
                    .map(|k| k.as_ref().to_string().into()),
            );
            result.sub.extend(
                del.clone()
                    .into_iter()
                    .map(|k| k.as_ref().to_string().into()),
            );
            if let Some(fallback) = fallback.as_ref() {
                result
                    .fallback
                    .replace(fallback.as_ref().to_string().into());
            }
        }
        let mut result = DWorkdirSet::default();
        assign_workdir_settings()
            .result(&mut result)
            .default_behavior(WORKDIR_BEHAVIOR)
            .add(&WORKDIR_ADD_LIST)
            .del(&WORKDIR_REMOVE_LIST)
            .fallback(&WORKDIR_FALLBACK)
            .call();
        self.get_opt_iter()
            .filter_map(|o| o.workdir.as_ref())
            .for_each(|o| match o {
                DWorkdirEither::Struct(s) => assign_workdir_settings()
                    .result(&mut result)
                    .default_behavior(s.default_behavior)
                    .add(&s.add)
                    .del(&s.sub)
                    .fallback(&s.fallback)
                    .call(),
                DWorkdirEither::Path(p) => {
                    let array: [String; 0] = [];
                    assign_workdir_settings()
                        .result(&mut result)
                        .default_behavior(WorkdirBehavior::Allowlist)
                        .fallback(&Some(p))
                        .add(&array)
                        .del(&array)
                        .call();
                }
            });
        result
    }
}

#[bon::builder]
fn update_security_min(
    security_min: &mut SecurityMin,
    bounding: Option<&SBounding>,
    root: Option<&SPrivileged>,
    authentication: Option<&SAuthentication>,
    env_behavior: Option<&EnvBehavior>,
    override_env: Option<&bool>,
    path_behavior: Option<&PathBehavior>,
) {
    if !security_min.contains(SecurityMin::DisableBounding)
        && bounding.is_some_and(SBounding::is_ignore)
    {
        *security_min |= SecurityMin::DisableBounding;
    }
    if !security_min.contains(SecurityMin::EnableRoot)
        && root.is_some_and(|r| *r == SPrivileged::Privileged)
    {
        *security_min |= SecurityMin::EnableRoot;
    }
    if !security_min.contains(SecurityMin::SkipAuth)
        && authentication.is_some_and(|a| *a == SAuthentication::Skip)
    {
        *security_min |= SecurityMin::SkipAuth;
    }
    if !security_min.contains(SecurityMin::KeepEnv)
        && env_behavior
            .as_ref()
            .is_some_and(|e| e.is_keep() || override_env.as_ref().is_some_and(|o| **o))
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
    default_behavior: PathBehavior,
    add: Option<impl IntoIterator<Item = impl AsRef<str> + ToString> + Clone>,
    sub: Option<impl IntoIterator<Item = impl AsRef<str> + ToString> + Clone>,
) {
    match default_behavior {
        PathBehavior::Inherit => {
            if let Some(add_paths) = add {
                combined_paths.extend(add_paths.into_iter().map(|p| p.to_string()));
            }
            if let Some(sub_paths) = sub {
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
            if let Some(add_paths) = add {
                combined_paths.extend(add_paths.into_iter().map(|p| p.to_string()));
            }
        }
        is_safe => {
            combined_paths.clear();
            combined_paths.extend(
                path_var
                    .iter()
                    .map(std::string::ToString::to_string)
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
    fn test_check_env() {
        assert!(check_env("TZ", "America/New_York"));
        assert!(!check_env("TZ", "/America/New_York"));
        assert!(!check_env("TZ", "America/New_York/.."));
        assert!(!check_env("VAR_NAME", "VAR%NAME"));
        assert!(check_env("VAR_NAME", "VAR_NAME"));
    }

    #[test]
    fn test_env_matches() {
        let set: HashSet<String> = ["VAR1", "VAR2"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert!(env_matches(Some(&set), "VAR1"));
        assert!(!env_matches(Some(&set), "VAR3"));
        assert!(!env_matches(None::<&HashSet<String>>, "VAR1"));
    }

    #[test]
    fn test_env_matches_policy_patterns() {
        let set: HashSet<String> = ["LC_*".to_string(), "HOME".to_string()].into();
        assert!(env_matches(Some(&set), "LC_ALL"));
        assert!(env_matches(Some(&set), "HOME"));
        assert!(!env_matches(Some(&set), "LANG"));
        // the user's variable name is never used as a pattern
        assert!(!env_matches(Some(&set), "*"));
        assert!(!env_matches(Some(&set), "HOME|X"));
    }

    fn final_user_env(
        behavior: EnvBehavior,
        keep: &[&str],
        check: &[&str],
        delete: &[&str],
        env_vars: &[(&str, &str)],
    ) -> HashMap<String, String> {
        let env_options = DEnvOptions::builder(behavior)
            .keep(keep.iter().copied())
            .unwrap()
            .check(check.iter().copied())
            .unwrap()
            .delete(delete.iter().copied())
            .unwrap()
            .build();
        let target = Cred::builder()
            .curdir()
            .unwrap()
            .groups()
            .unwrap()
            .user()
            .unwrap()
            .build();
        env_options
            .calc_final_env(
                env_vars.iter().copied(),
                ["/usr/bin"],
                &target,
                None,
                String::new(),
            )
            .unwrap()
    }

    #[test]
    fn test_calc_env_delete_list() {
        let vars = [
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("LD_LIBRARY_PATH", "/tmp"),
            ("BASH_ENV", "/tmp/evil.sh"),
            ("BASH_FUNC_ls%%", "() { evil; }"),
            ("FOO", "bar"),
        ];
        // keep mode passes every variable except those of the delete list
        let env = final_user_env(
            EnvBehavior::Keep,
            &[],
            &[],
            &["LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV"],
            &vars,
        );
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("LD_LIBRARY_PATH"));
        assert!(!env.contains_key("BASH_ENV"));
        assert_eq!(env.get("FOO").unwrap(), "bar");
        let env = final_user_env(EnvBehavior::Keep, &[], &[], &["LD_*"], &vars);
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("LD_LIBRARY_PATH"));
        // the keep list is not used in keep mode
        let env = final_user_env(
            EnvBehavior::Keep,
            &["LD_PRELOAD"],
            &[],
            &["LD_PRELOAD"],
            &vars,
        );
        assert!(!env.contains_key("LD_PRELOAD"));
        // without a delete list, the policy passes everything
        let env = final_user_env(EnvBehavior::Keep, &[], &[], &[], &vars);
        assert_eq!(env.get("LD_PRELOAD").unwrap(), "/tmp/evil.so");
    }

    #[test]
    fn test_calc_env_shell_functions() {
        let vars = [
            ("BASH_FUNC_ls%%", "() { evil; }"),
            ("FOO", "() not a function"),
        ];
        // never passed, even when kept by name
        let env = final_user_env(
            EnvBehavior::Delete,
            &["BASH_FUNC_ls%%", "FOO"],
            &[],
            &[],
            &vars,
        );
        assert!(!env.contains_key("BASH_FUNC_ls%%"));
        assert!(!env.contains_key("FOO"));
        let env = final_user_env(EnvBehavior::Keep, &[], &[], &[], &vars);
        assert!(!env.contains_key("BASH_FUNC_ls%%"));
    }

    #[test]
    fn test_calc_env_check_precedence() {
        let vars = [
            ("CHECKED", "/unsafe"),
            ("SAFE", "ok"),
            ("TZ", "../../etc/x"),
        ];
        // a variable in both keep and check lists is still checked
        let env = final_user_env(
            EnvBehavior::Delete,
            &["CHECKED", "SAFE", "TZ"],
            &["CHECKED", "SAFE", "TZ"],
            &[],
            &vars,
        );
        assert!(!env.contains_key("CHECKED"));
        assert_eq!(env.get("SAFE").unwrap(), "ok");
        assert!(!env.contains_key("TZ"));
        // in keep mode, the delete list wins over the check list
        let env = final_user_env(EnvBehavior::Keep, &[], &["SAFE"], &["SAFE"], &vars);
        assert!(!env.contains_key("SAFE"));
        let env = final_user_env(EnvBehavior::Keep, &[], &["CHECKED"], &[], &vars);
        assert!(!env.contains_key("CHECKED"));
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
    #[allow(clippy::too_many_lines)]
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
        let target = Cred::builder()
            .curdir()
            .unwrap()
            .groups()
            .unwrap()
            .user()
            .unwrap()
            .build();
        let result = env_options.calc_final_env(env_vars, &env_path, &target, None, String::new());
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
        let target = Cred::builder()
            .curdir()
            .unwrap()
            .groups()
            .unwrap()
            .user()
            .unwrap()
            .build();
        let result = env_options.calc_final_env(env_vars, &env_path, &target, None, String::new());
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
        let target = Cred::builder()
            .curdir()
            .unwrap()
            .groups()
            .unwrap()
            .user()
            .unwrap()
            .build();
        let result = env_options.calc_final_env(env_vars, &env_path, &target, None, String::new());
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
        stack.role = role;
        stack.task = task;
        assert_eq!(
            stack.calc_path(&["/test"]),
            env!("RAR_PATH_ADD_LIST").split(':').collect::<Vec<&str>>()
        );
        let env = stack.calc_temp_env(false, None);
        // the global level does not define its keep and delete lists: the defaults are inherited
        let with_defaults = |defaults: &[&'static str], entry: &'static str| {
            let mut list: HashSet<Cow<'static, str>> =
                defaults.iter().copied().map(Into::into).collect();
            list.insert(entry.into());
            Some(list)
        };
        assert_eq!(env.delete, with_defaults(ENV_DELETE_LIST, "DELETEME"));
        assert_eq!(env.keep, with_defaults(ENV_KEEP_LIST, "KEEPME"));
        // the check and set lists it defines replace the defaults
        assert_eq!(env.check, Some(HashSet::from(["CHECKME".into()])));
        assert_eq!(
            env.set,
            Some(HashMap::from([
                ("VAR1".into(), "VALUE1".into()),
                ("VAR2".into(), "VALUE2".into())
            ]))
        );
    }

    #[test]
    fn test_env_lists_undefined_or_empty() {
        let env: DEnvOptions<'_> =
            serde_json::from_str(r#"{"default": "keep", "delete": [], "set": {}}"#).unwrap();
        assert_eq!(env.delete, Some(HashSet::new()));
        assert_eq!(env.set, Some(HashMap::new()));
        assert_eq!(env.check, None);
        assert_eq!(env.keep, None);
    }

    #[test]
    fn test_calc_temp_env_inherits_undefined_lists() {
        let config = Some(
            Opt::builder(Level::Global)
                .env(
                    DEnvOptions::builder(EnvBehavior::Delete)
                        .keep(["KEEPME"])
                        .unwrap()
                        .check(["CHECKME"])
                        .unwrap()
                        .delete(["LD_*"])
                        .unwrap()
                        .set([("GLOBAL", "one")])
                        .build(),
                )
                .build(),
        );
        let mut stack = BorrowedOptStack::new(config);
        // a task that switches to keep mode without restating its lists inherits them
        stack.task = Some(
            Opt::builder(Level::Task)
                .env(DEnvOptions::builder(EnvBehavior::Keep).build())
                .build(),
        );
        let env = stack.calc_temp_env(false, None);
        assert_eq!(env.default_behavior, EnvBehavior::Keep);
        assert_eq!(env.delete, Some(HashSet::from(["LD_*".into()])));
        assert_eq!(env.check, Some(HashSet::from(["CHECKME".into()])));
        assert_eq!(env.keep, Some(HashSet::from(["KEEPME".into()])));
        assert_eq!(
            env.set,
            Some(HashMap::from([("GLOBAL".into(), "one".into())]))
        );
        let vars = [("LD_PRELOAD", "/tmp/evil.so"), ("CHECKME", "/unsafe")];
        let target = Cred::builder()
            .curdir()
            .unwrap()
            .groups()
            .unwrap()
            .user()
            .unwrap()
            .build();
        let final_env = env
            .calc_final_env(vars, ["/usr/bin"], &target, None, String::new())
            .unwrap();
        assert!(!final_env.contains_key("LD_PRELOAD"));
        assert!(!final_env.contains_key("CHECKME"));

        // a defined list replaces the inherited one, only an empty list removes it
        stack.task = Some(
            Opt::builder(Level::Task)
                .env(
                    DEnvOptions::builder(EnvBehavior::Keep)
                        .delete(Vec::<&str>::new())
                        .unwrap()
                        .check(["OTHER"])
                        .unwrap()
                        .build(),
                )
                .build(),
        );
        let env = stack.calc_temp_env(false, None);
        assert_eq!(env.delete, Some(HashSet::new()));
        assert_eq!(env.check, Some(HashSet::from(["OTHER".into()])));
    }

    #[test]
    fn test_invalid_env_entry() {
        let opt = |env: DEnvOptions<'static>| Some(Opt::builder(Level::Task).env(env).build());
        let mut stack = BorrowedOptStack::new(None);
        stack.task = opt(DEnvOptions::builder(EnvBehavior::Delete)
            .keep(["HOME", "LC_*", "*_PROXY"])
            .unwrap()
            .set([("TASK", "value")])
            .build());
        assert_eq!(stack.invalid_env_entry(), None);
        // a regex is not a pattern anymore
        stack.task = opt(DEnvOptions::builder(EnvBehavior::Delete)
            .check(["LC_.*"])
            .unwrap()
            .build());
        assert_eq!(stack.invalid_env_entry(), Some("LC_.*"));
        // names set by the policy cannot be patterns
        stack.task = opt(DEnvOptions::builder(EnvBehavior::Delete)
            .set([("A*", "value")])
            .build());
        assert_eq!(stack.invalid_env_entry(), Some("A*"));
    }

    #[test]
    fn test_calc_temp_env_override_behavior() {
        let config = Some(
            Opt::builder(Level::Global)
                .env(
                    DEnvOptions::builder(EnvBehavior::Delete)
                        .set([("GLOBAL", "one")])
                        .build(),
                )
                .build(),
        );
        let task = Some(
            Opt::builder(Level::Task)
                .env(
                    DEnvOptions::builder(EnvBehavior::Inherit)
                        .set([("TASK", "two")])
                        .build(),
                )
                .build(),
        );

        let mut stack = BorrowedOptStack::new(config);
        stack.task = task;
        let filter = FilterMatcher::builder()
            .env_behavior(EnvBehavior::Keep)
            .build();

        let overridden = stack.calc_temp_env(true, Some(&filter));
        assert_eq!(overridden.default_behavior, EnvBehavior::Keep);
        let set = overridden.set.as_ref().unwrap();
        assert!(set.contains_key("GLOBAL"));
        assert!(set.contains_key("TASK"));

        let not_overridden = stack.calc_temp_env(false, Some(&filter));
        assert_eq!(not_overridden.default_behavior, EnvBehavior::Delete);
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
        let rar_opt: rootasrole_core::database::options::Opt = opt.clone().into();
        assert_eq!(rar_opt.level, Level::Default);
        assert_eq!(
            rar_opt.path.unwrap().default_behavior,
            PathBehavior::Inherit
        );
        assert_eq!(rar_opt.env.unwrap().default_behavior, EnvBehavior::Keep);
    }
}
