use std::collections::HashSet;
use std::path::PathBuf;
use std::{borrow::Cow, collections::HashMap};

use bon::{Builder, bon, builder};

use rootasrole_core::database::FilterMatcher;
use rootasrole_core::database::env::{EnvLevel, ResolvedEnv};
use rootasrole_core::database::options::{
    EnvBehavior, Level, PathBehavior, SAuthentication, SBounding, SInfo, SPathOptions, SPrivileged,
    STimeout, SUMask, WorkdirBehavior,
};
use rootasrole_core::database::path::{PathLevel, ResolvedPath};
use rootasrole_core::database::score::SecurityMin;
use rootasrole_core::util::{
    AUTHENTICATION, BOUNDING, ENV_DEFAULT_BEHAVIOR, ENV_OVERRIDE_BEHAVIOR, ENV_PATH_BEHAVIOR, INFO,
    PRIVILEGED, TIMEOUT_DURATION, TIMEOUT_MAX_USAGE, TIMEOUT_TYPE, UMASK, WORKDIR_ADD_LIST,
    WORKDIR_BEHAVIOR, WORKDIR_FALLBACK, WORKDIR_REMOVE_LIST, is_valid_env_name,
    is_valid_env_pattern,
};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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

impl PathLevel for DPathOptions<'_> {
    fn behavior(&self) -> PathBehavior {
        self.default_behavior
    }
    fn add(&self) -> Option<impl Iterator<Item = &str>> {
        self.add.as_ref().map(|l| l.iter().map(AsRef::as_ref))
    }
    fn sub(&self) -> Option<impl Iterator<Item = &str>> {
        self.sub.as_ref().map(|l| l.iter().map(AsRef::as_ref))
    }
}

impl EnvLevel for DEnvOptions<'_> {
    fn behavior(&self) -> EnvBehavior {
        self.default_behavior
    }
    fn keep(&self) -> Option<impl Iterator<Item = &str>> {
        self.keep.as_ref().map(|l| l.iter().map(AsRef::as_ref))
    }
    fn check(&self) -> Option<impl Iterator<Item = &str>> {
        self.check.as_ref().map(|l| l.iter().map(AsRef::as_ref))
    }
    fn delete(&self) -> Option<impl Iterator<Item = &str>> {
        self.delete.as_ref().map(|l| l.iter().map(AsRef::as_ref))
    }
    fn set(&self) -> Option<impl Iterator<Item = (&str, &str)>> {
        self.set
            .as_ref()
            .map(|s| s.iter().map(|(k, v)| (k.as_ref(), v.as_ref())))
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

pub fn is_default<T: PartialEq + Default>(t: &T) -> bool {
    t == &T::default()
}

/// The options of the global, role and task levels, borrowed from the policy: building or
/// updating a stack never copies the options. `'c` is how long the policy is borrowed, `'a`
/// the lifetime of the policy itself: `Opt<'a>` is invariant (`Cow<'a, [Cow<'a, str>]>` in
/// `DPathOptions`), so they cannot be merged into one lifetime.
pub struct BorrowedOptStack<'c, 'a> {
    config: Option<&'c Opt<'a>>,
    role: Option<&'c Opt<'a>>,
    task: Option<&'c Opt<'a>>,
}

impl<'c, 'a> BorrowedOptStack<'c, 'a> {
    pub const fn new(config: Option<&'c Opt<'a>>) -> Self {
        Self {
            config,
            role: None,
            task: None,
        }
    }
    pub const fn from_task(task: &DLinkedTask<'_, 'c, 'a>) -> Self {
        Self {
            config: task.role().config().options.as_ref(),
            role: task.role().role().options.as_ref(),
            task: task.task().options.as_ref(),
        }
    }
    pub const fn set_role(&mut self, role: &DLinkedTask<'_, 'c, 'a>) {
        self.role = role.role().role().options.as_ref();
    }
    pub const fn set_task(&mut self, task: &DLinkedTask<'_, 'c, 'a>) {
        self.task = task.task().options.as_ref();
    }
    /// The `PATH` of the command, resolved by rootasrole-core (`database::path`) from the
    /// options of the stack and the `PATH` of the user.
    pub fn calc_path(&self, path_var: &[&str]) -> Vec<String> {
        let mut path: ResolvedPath<'c> = ResolvedPath::defaults();
        for level in self.get_opt_iter().filter_map(|o| o.path.as_ref()) {
            path.apply(level);
        }
        path.final_path(path_var)
            .into_iter()
            .map(ToString::to_string)
            .collect()
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
    /// The env options of the stack, resolved by rootasrole-core (`database::env`), with the
    /// behavior that the user asked for if the policy allows to override it.
    pub fn calc_temp_env(
        &self,
        override_behavior: bool,
        opt_filter: Option<&FilterMatcher>,
    ) -> ResolvedEnv<'c> {
        let mut env: ResolvedEnv<'c> = ResolvedEnv::defaults();
        for level in self.get_opt_iter().filter_map(|o| o.env.as_ref()) {
            env.apply(level);
        }
        env.with_requested_behavior(
            opt_filter.and_then(|filter| filter.env_behavior),
            override_behavior,
        )
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

    pub fn get_opt_iter(&self) -> impl Iterator<Item = &'c Opt<'a>> + use<'c, 'a> {
        [self.config, self.role, self.task].into_iter().flatten()
    }

    pub fn get_opt_iter_rev(&self) -> impl Iterator<Item = &'c Opt<'a>> + use<'c, 'a> {
        [self.task, self.role, self.config].into_iter().flatten()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cred;
    use indexmap::{IndexMap, IndexSet};
    use rootasrole_core::util::{ENV_DELETE_LIST, ENV_KEEP_LIST};

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
        let mut stack = BorrowedOptStack::new(config.as_ref());
        stack.role = role.as_ref();
        stack.task = task.as_ref();
        assert_eq!(
            stack.calc_path(&["/test"]),
            env!("RAR_PATH_ADD_LIST").split(':').collect::<Vec<&str>>()
        );
        let env = stack.calc_temp_env(false, None);
        // the global level does not define its keep and delete lists: the defaults are inherited
        let with_defaults = |defaults: &[&'static str], entry: &'static str| {
            let mut list: IndexSet<&str> = defaults.iter().copied().collect();
            list.insert(entry);
            list
        };
        assert_eq!(env.delete, with_defaults(ENV_DELETE_LIST, "DELETEME"));
        assert_eq!(env.keep, with_defaults(ENV_KEEP_LIST, "KEEPME"));
        // the check and set lists it defines replace the defaults
        assert_eq!(env.check, IndexSet::from(["CHECKME"]));
        assert_eq!(env.set.get("VAR1"), Some(&"VALUE1"));
        assert_eq!(env.set.get("VAR2"), Some(&"VALUE2"));
        assert_eq!(env.set.len(), 2);
    }

    #[test]
    fn test_calc_path_follows_the_shared_rules() {
        let config = Opt::builder(Level::Global)
            .path(
                DPathOptions::builder(PathBehavior::Delete)
                    .add(["/usr/bin"])
                    .build(),
            )
            .build();
        let mut stack = BorrowedOptStack::new(Some(&config));
        // a level that sets the delete mode without directories inherits them
        let delete_task = Opt::builder(Level::Task)
            .path(DPathOptions::builder(PathBehavior::Delete).build())
            .build();
        stack.task = Some(&delete_task);
        assert_eq!(stack.calc_path(&["/home/user/bin"]), ["/usr/bin"]);
        // a keep-safe level applies its own lists, the directories of the policy come first
        let keep_task = Opt::builder(Level::Task)
            .path(
                DPathOptions::builder(PathBehavior::KeepSafe)
                    .add(["/sbin"])
                    .sub(["/opt/bin"])
                    .build(),
            )
            .build();
        stack.task = Some(&keep_task);
        assert_eq!(
            stack.calc_path(&["/home/user/bin", ".", "/opt/bin"]),
            ["/sbin", "/home/user/bin"]
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
        let mut stack = BorrowedOptStack::new(config.as_ref());
        // a task that switches to keep mode without restating its lists inherits them
        let keep_task = Opt::builder(Level::Task)
            .env(DEnvOptions::builder(EnvBehavior::Keep).build())
            .build();
        stack.task = Some(&keep_task);
        let env = stack.calc_temp_env(false, None);
        assert_eq!(env.behavior, EnvBehavior::Keep);
        assert_eq!(env.delete, IndexSet::from(["LD_*"]));
        assert_eq!(env.check, IndexSet::from(["CHECKME"]));
        assert_eq!(env.keep, IndexSet::from(["KEEPME"]));
        assert_eq!(env.set, IndexMap::from([("GLOBAL", "one")]));
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
            .final_env(vars, ["/usr/bin"], &target, None, String::new())
            .unwrap();
        assert!(!final_env.contains_key("LD_PRELOAD"));
        assert!(!final_env.contains_key("CHECKME"));

        // a defined list replaces the inherited one, only an empty list removes it
        let replacing_task = Opt::builder(Level::Task)
            .env(
                DEnvOptions::builder(EnvBehavior::Keep)
                    .delete(Vec::<&str>::new())
                    .unwrap()
                    .check(["OTHER"])
                    .unwrap()
                    .build(),
            )
            .build();
        stack.task = Some(&replacing_task);
        let env = stack.calc_temp_env(false, None);
        assert!(env.delete.is_empty());
        assert_eq!(env.check, IndexSet::from(["OTHER"]));
    }

    #[test]
    fn test_invalid_env_entry() {
        let invalid_entry = |env: DEnvOptions<'static>| {
            let task = Opt::builder(Level::Task).env(env).build();
            let mut stack = BorrowedOptStack::new(None);
            stack.task = Some(&task);
            stack.invalid_env_entry().map(ToString::to_string)
        };
        assert_eq!(
            invalid_entry(
                DEnvOptions::builder(EnvBehavior::Delete)
                    .keep(["HOME", "LC_*", "*_PROXY"])
                    .unwrap()
                    .set([("TASK", "value")])
                    .build()
            ),
            None
        );
        // a regex is not a pattern anymore
        assert_eq!(
            invalid_entry(
                DEnvOptions::builder(EnvBehavior::Delete)
                    .check(["LC_.*"])
                    .unwrap()
                    .build()
            )
            .as_deref(),
            Some("LC_.*")
        );
        // names set by the policy cannot be patterns
        assert_eq!(
            invalid_entry(
                DEnvOptions::builder(EnvBehavior::Delete)
                    .set([("A*", "value")])
                    .build()
            )
            .as_deref(),
            Some("A*")
        );
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

        let mut stack = BorrowedOptStack::new(config.as_ref());
        stack.task = task.as_ref();
        let filter = FilterMatcher::builder()
            .env_behavior(EnvBehavior::Keep)
            .build();

        let overridden = stack.calc_temp_env(true, Some(&filter));
        assert_eq!(overridden.behavior, EnvBehavior::Keep);
        let set = &overridden.set;
        assert!(set.contains_key("GLOBAL"));
        assert!(set.contains_key("TASK"));

        let not_overridden = stack.calc_temp_env(false, Some(&filter));
        assert_eq!(not_overridden.behavior, EnvBehavior::Delete);

        // a filter that does not ask for a behavior (e.g. `dosr -r role`) changes nothing,
        // the behavior of every level is still applied
        let keep_task = Opt::builder(Level::Task)
            .env(DEnvOptions::builder(EnvBehavior::Keep).build())
            .build();
        stack.task = Some(&keep_task);
        let role_filter = FilterMatcher::builder().role("r".to_string()).build();
        assert_eq!(
            stack.calc_temp_env(true, Some(&role_filter)).behavior,
            EnvBehavior::Keep
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
        let rar_opt: rootasrole_core::database::options::Opt = opt.clone().into();
        assert_eq!(rar_opt.level, Level::Default);
        assert_eq!(
            rar_opt.path.unwrap().default_behavior,
            PathBehavior::Inherit
        );
        assert_eq!(rar_opt.env.unwrap().default_behavior, EnvBehavior::Keep);
    }
}
