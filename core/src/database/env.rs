//! How the environment of a command is decided, for dosr and chsr alike.
//!
//! The env options of the default, global, role and task levels are merged into one set of
//! lists ([`ResolvedEnv`]), then the variables of the user are filtered with them. The same
//! filter ([`EnvFilter`]) applies to the variables that PAM modules set, such as `pam_env`.
//! See [`SEnvOptions`](super::options::SEnvOptions) for the meaning of each list.

use std::{
    borrow::Borrow,
    collections::{HashMap, hash_map::Entry},
    hash::Hash,
};

use indexmap::{IndexMap, IndexSet};
use libc::PATH_MAX;
use log::debug;
use nix::unistd::User;

use crate::{
    Cred,
    database::options::EnvBehavior,
    util::{
        ENV_CHECK_LIST, ENV_DEFAULT_BEHAVIOR, ENV_DELETE_LIST, ENV_KEEP_LIST, ENV_SET_LIST,
        is_shell_function, wildcard_match,
    },
};

/// The env options of one level, whatever their representation: owned by chsr, or borrowed
/// from the policy file by dosr. A list that the level does not define is `None`.
pub trait EnvLevel {
    fn behavior(&self) -> EnvBehavior;
    fn keep(&self) -> Option<impl Iterator<Item = &str>>;
    fn check(&self) -> Option<impl Iterator<Item = &str>>;
    fn delete(&self) -> Option<impl Iterator<Item = &str>>;
    fn set(&self) -> Option<impl Iterator<Item = (&str, &str)>>;
}

/// The env options of every level, merged from the most general to the most specific.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedEnv<'a> {
    pub behavior: EnvBehavior,
    pub keep: IndexSet<&'a str>,
    pub check: IndexSet<&'a str>,
    pub delete: IndexSet<&'a str>,
    pub set: IndexMap<&'a str, &'a str>,
}

impl ResolvedEnv<'static> {
    /// The built-in defaults (`RAR_ENV_*` at build time), below the global level.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            behavior: ENV_DEFAULT_BEHAVIOR,
            keep: ENV_KEEP_LIST.iter().copied().collect(),
            check: ENV_CHECK_LIST.iter().copied().collect(),
            delete: ENV_DELETE_LIST.iter().copied().collect(),
            set: ENV_SET_LIST.iter().copied().collect(),
        }
    }
}

/// Merge a list of one level into the inherited one. A list that the level does not define is
/// inherited, even when the level sets its own behavior; a defined list replaces the inherited
/// one when the level sets its behavior, and extends it otherwise.
fn merge<T: std::hash::Hash + Eq>(
    inherited: &mut IndexSet<T>,
    level: Option<impl Iterator<Item = T>>,
    replace: bool,
) {
    let Some(level) = level else {
        return;
    };
    if replace {
        inherited.clear();
    }
    inherited.extend(level);
}

impl<'a> ResolvedEnv<'a> {
    /// Merge the options of a more specific level. Only an explicitly empty list (`[]`) removes
    /// an inherited list: see [`SEnvOptions`](super::options::SEnvOptions) for why this is the
    /// fail-safe choice.
    pub fn apply(&mut self, level: &'a impl EnvLevel) {
        let behavior = level.behavior();
        let replace = !behavior.is_inherit();
        if replace {
            self.behavior = behavior;
        }
        merge(&mut self.keep, level.keep(), replace);
        merge(&mut self.check, level.check(), replace);
        merge(&mut self.delete, level.delete(), replace);
        if let Some(set) = level.set() {
            if replace {
                self.set.clear();
            }
            self.set.extend(set);
        }
    }

    /// Use the behavior that the user asked for (`dosr -E`), if the policy allows to override it.
    #[must_use]
    pub fn with_requested_behavior(
        mut self,
        requested: Option<EnvBehavior>,
        allowed: bool,
    ) -> Self {
        if allowed && let Some(requested) = requested.filter(|b| !b.is_inherit()) {
            self.behavior = requested;
        }
        self
    }

    /// Whether a variable of the user's environment is passed to the command:
    /// - shell function definitions are never passed ([`is_shell_function`]),
    /// - in delete mode, only the variables of the keep and check lists are passed,
    /// - in keep mode, every variable is passed except those of the delete list,
    /// - in both modes, a variable of the check list is passed only if its value is safe.
    #[must_use]
    pub fn keep_user_var(&self, key: &str, value: &str) -> bool {
        keeps_var(
            self.behavior,
            &self.keep,
            &self.check,
            &self.delete,
            key,
            value,
        )
    }

    /// The same filter as [`ResolvedEnv::keep_user_var`], owned: it outlives the policy.
    #[must_use]
    pub fn filter(&self) -> EnvFilter {
        let owned = |list: &IndexSet<&str>| list.iter().map(|entry| (*entry).to_string()).collect();
        EnvFilter {
            behavior: self.behavior,
            keep: owned(&self.keep),
            check: owned(&self.check),
            delete: owned(&self.delete),
        }
    }

    /// The environment of the command: the variables of the user that are kept, the variables
    /// set by dosr (`PATH`, the target user, `RAR_*` and `SUDO_*`), then the `set` list.
    /// Returns `None` if no level decides the behavior (`inherit` everywhere).
    pub fn final_env(
        &self,
        user_env: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
        path: impl IntoIterator<Item = impl AsRef<str>>,
        current_user: &Cred,
        target: Option<&User>,
        command: String,
    ) -> Option<HashMap<String, String>> {
        if self.behavior.is_inherit() {
            return None;
        }
        let mut final_env = user_env
            .into_iter()
            .filter_map(|(key, value)| {
                let key: String = key.into();
                let value: String = value.into();
                self.keep_user_var(&key, &value).then_some((key, value))
            })
            .collect::<HashMap<String, String>>();
        let path: Vec<_> = path.into_iter().collect();
        final_env.insert(
            "PATH".into(),
            path.iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&str>>()
                .join(":"),
        );
        let target_user = target.unwrap_or(&current_user.user);
        final_env.insert("LOGNAME".into(), target_user.name.clone());
        final_env.insert("USER".into(), target_user.name.clone());
        final_env.insert("HOME".into(), target_user.dir.to_string_lossy().to_string());
        final_env.insert(
            "SHELL".into(),
            target_user.shell.to_string_lossy().to_string(),
        );
        final_env.insert("RAR_UID".into(), current_user.user.uid.to_string());
        final_env.insert("RAR_GID".into(), current_user.user.gid.to_string());
        final_env.insert("RAR_USER".into(), current_user.user.name.clone());
        final_env.insert("RAR_COMMAND".into(), command.clone());
        final_env.insert("SUDO_UID".into(), current_user.user.uid.to_string());
        final_env.insert("SUDO_GID".into(), current_user.user.gid.to_string());
        final_env.insert("SUDO_USER".into(), current_user.user.name.clone());
        final_env.insert("SUDO_COMMAND".into(), command);
        final_env
            .entry("TERM".into())
            .or_insert_with(|| "unknown".into());
        final_env.extend(
            self.set
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string())),
        );
        Some(final_env)
    }
}

/// The filter of the policy on the variables passed to the command, once the policy is gone.
///
/// dosr decides the environment of the command before the PAM session is open; the variables
/// that PAM modules set then (`pam_env`, `pam_systemd`, `pam_getenvlist(3)`) go through this
/// filter, like the variables of the user: they may come from files that the user writes, such
/// as `~/.pam_environment` with `pam_env user_readenv=1`. The default filter keeps nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvFilter {
    behavior: EnvBehavior,
    keep: IndexSet<String>,
    check: IndexSet<String>,
    delete: IndexSet<String>,
}

impl EnvFilter {
    /// Whether a variable is passed to the command, see [`ResolvedEnv::keep_user_var`].
    #[must_use]
    pub fn keeps(&self, key: &str, value: &str) -> bool {
        keeps_var(
            self.behavior,
            &self.keep,
            &self.check,
            &self.delete,
            key,
            value,
        )
    }

    /// Add to the environment of the command the variables that the filter keeps, unless the
    /// environment already has them: the kept variables of the user, the variables set by dosr
    /// and the `set` list of the policy take precedence.
    pub fn add_vars(
        &self,
        env: &mut HashMap<String, String>,
        vars: impl IntoIterator<Item = (String, String)>,
    ) {
        for (key, value) in vars {
            match env.entry(key) {
                Entry::Occupied(var) => {
                    debug!("{} is already set, its other value is left out", var.key());
                }
                Entry::Vacant(var) if self.keeps(var.key(), &value) => {
                    var.insert(value);
                }
                Entry::Vacant(var) => debug!("{} is left out by the policy", var.key()),
            }
        }
    }
}

/// The rule of [`ResolvedEnv::keep_user_var`] and [`EnvFilter::keeps`], whether the lists are
/// borrowed from the policy or owned.
fn keeps_var<S: Borrow<str> + Hash + Eq>(
    behavior: EnvBehavior,
    keep: &IndexSet<S>,
    check: &IndexSet<S>,
    delete: &IndexSet<S>,
    key: &str,
    value: &str,
) -> bool {
    if is_shell_function(value) {
        return false;
    }
    let checked = env_matches(check, key);
    match behavior {
        EnvBehavior::Delete => {
            if checked {
                check_env(key, value)
            } else {
                env_matches(keep, key)
            }
        }
        EnvBehavior::Keep => !env_matches(delete, key) && (!checked || check_env(key, value)),
        EnvBehavior::Inherit => false,
    }
}

/// Whether the value of a variable of the check list is safe: no `/` nor `%`, except for `TZ`
/// which must be a relative time zone name.
#[must_use]
pub fn check_env(key: &str, value: &str) -> bool {
    debug!("Checking env: {key}={value}");
    match key {
        "TZ" => tz_is_safe(value),
        _ => !value.chars().any(|c| c == '/' || c == '%'),
    }
}

/// The policy entries are the patterns, never the user's variable name.
fn env_matches<S: Borrow<str> + Hash + Eq>(list: &IndexSet<S>, name: &str) -> bool {
    list.contains(name)
        || list
            .iter()
            .any(|pattern| wildcard_match(pattern.borrow(), name))
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
    if tzval
        .chars()
        .any(|c| c.is_ascii_whitespace() || !c.is_ascii_graphic())
    {
        return false;
    }
    if tzval.split('/').any(|element| element == "..") {
        return false;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(
        behavior: EnvBehavior,
        keep: &[&'static str],
        check: &[&'static str],
        delete: &[&'static str],
    ) -> ResolvedEnv<'static> {
        ResolvedEnv {
            behavior,
            keep: keep.iter().copied().collect(),
            check: check.iter().copied().collect(),
            delete: delete.iter().copied().collect(),
            set: IndexMap::new(),
        }
    }

    fn cred() -> Cred {
        Cred::builder()
            .curdir()
            .unwrap()
            .groups()
            .unwrap()
            .user()
            .unwrap()
            .build()
    }

    fn final_user_env(env: &ResolvedEnv<'_>, user_env: &[(&str, &str)]) -> HashMap<String, String> {
        env.final_env(
            user_env.iter().copied(),
            ["/usr/bin"],
            &cred(),
            None,
            String::new(),
        )
        .unwrap()
    }

    /// One level of options, as a test fixture.
    struct Level {
        behavior: EnvBehavior,
        keep: Option<Vec<&'static str>>,
        check: Option<Vec<&'static str>>,
        delete: Option<Vec<&'static str>>,
        set: Option<Vec<(&'static str, &'static str)>>,
    }

    impl EnvLevel for Level {
        fn behavior(&self) -> EnvBehavior {
            self.behavior
        }
        fn keep(&self) -> Option<impl Iterator<Item = &str>> {
            self.keep.as_ref().map(|l| l.iter().copied())
        }
        fn check(&self) -> Option<impl Iterator<Item = &str>> {
            self.check.as_ref().map(|l| l.iter().copied())
        }
        fn delete(&self) -> Option<impl Iterator<Item = &str>> {
            self.delete.as_ref().map(|l| l.iter().copied())
        }
        fn set(&self) -> Option<impl Iterator<Item = (&str, &str)>> {
            self.set.as_ref().map(|l| l.iter().copied())
        }
    }

    #[test]
    fn test_apply_inherits_undefined_lists() {
        let global = Level {
            behavior: EnvBehavior::Delete,
            keep: Some(vec!["KEEPME"]),
            check: Some(vec!["CHECKME"]),
            delete: Some(vec!["LD_*"]),
            set: Some(vec![("GLOBAL", "one")]),
        };
        // switches to keep mode without restating its lists
        let task = Level {
            behavior: EnvBehavior::Keep,
            keep: None,
            check: None,
            delete: None,
            set: None,
        };
        let mut env = ResolvedEnv::defaults();
        env.apply(&global);
        env.apply(&task);
        assert_eq!(env.behavior, EnvBehavior::Keep);
        assert_eq!(env.delete, IndexSet::from(["LD_*"]));
        assert_eq!(env.check, IndexSet::from(["CHECKME"]));
        assert_eq!(env.keep, IndexSet::from(["KEEPME"]));
        assert_eq!(env.set, IndexMap::from([("GLOBAL", "one")]));
        // a defined list replaces the inherited one, only an empty list removes it
        let task = Level {
            behavior: EnvBehavior::Keep,
            keep: None,
            check: Some(vec!["OTHER"]),
            delete: Some(vec![]),
            set: None,
        };
        env.apply(&task);
        assert!(env.delete.is_empty());
        assert_eq!(env.check, IndexSet::from(["OTHER"]));
        // an inheriting level extends the lists
        let task = Level {
            behavior: EnvBehavior::Inherit,
            keep: Some(vec!["MORE"]),
            check: None,
            delete: None,
            set: None,
        };
        env.apply(&task);
        assert_eq!(env.behavior, EnvBehavior::Keep);
        assert_eq!(env.keep, IndexSet::from(["KEEPME", "MORE"]));
    }

    #[test]
    fn test_with_requested_behavior() {
        let env = resolved(EnvBehavior::Delete, &[], &[], &[]);
        let overridden = env
            .clone()
            .with_requested_behavior(Some(EnvBehavior::Keep), true);
        assert_eq!(overridden.behavior, EnvBehavior::Keep);
        let refused = env
            .clone()
            .with_requested_behavior(Some(EnvBehavior::Keep), false);
        assert_eq!(refused.behavior, EnvBehavior::Delete);
        assert_eq!(env.clone().with_requested_behavior(None, true), env);
    }

    #[test]
    fn test_tz_is_safe() {
        assert!(tz_is_safe("America/New_York"));
        assert!(!tz_is_safe("/America/New_York"));
        assert!(!tz_is_safe("America/New_York/.."));
        // a '..' element is refused wherever it is, even after another dot
        assert!(!tz_is_safe("Etc.x/../../etc/shadow"));
        assert!(!tz_is_safe("../zoneinfo/UTC"));
        assert!(!tz_is_safe(":Europe/../../etc/x"));
        // a name that only contains dots is fine
        assert!(tz_is_safe("Etc/a..b"));
        assert!(tz_is_safe(":Europe/Paris"));
        //assert path max
        assert!(!tz_is_safe(
            String::from_utf8(vec![b'a'; (PATH_MAX + 1).try_into().unwrap()])
                .unwrap()
                .as_str()
        ));
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
    fn test_env_matches_policy_patterns() {
        let list = IndexSet::from(["LC_*", "HOME"]);
        assert!(env_matches(&list, "LC_ALL"));
        assert!(env_matches(&list, "HOME"));
        assert!(!env_matches(&list, "LANG"));
        // the user's variable name is never used as a pattern
        assert!(!env_matches(&list, "*"));
        assert!(!env_matches(&list, "HOME|X"));
    }

    #[test]
    fn test_final_env_delete_list() {
        let vars = [
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("LD_LIBRARY_PATH", "/tmp"),
            ("BASH_ENV", "/tmp/evil.sh"),
            ("FOO", "bar"),
        ];
        // keep mode passes every variable except those of the delete list
        let env = final_user_env(
            &resolved(EnvBehavior::Keep, &[], &[], &["LD_*", "BASH_ENV"]),
            &vars,
        );
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("LD_LIBRARY_PATH"));
        assert!(!env.contains_key("BASH_ENV"));
        assert_eq!(env.get("FOO").unwrap(), "bar");
        // the keep list is not used in keep mode
        let env = final_user_env(
            &resolved(EnvBehavior::Keep, &["LD_PRELOAD"], &[], &["LD_PRELOAD"]),
            &vars,
        );
        assert!(!env.contains_key("LD_PRELOAD"));
        // without a delete list, the policy passes everything
        let env = final_user_env(&resolved(EnvBehavior::Keep, &[], &[], &[]), &vars);
        assert_eq!(env.get("LD_PRELOAD").unwrap(), "/tmp/evil.so");
    }

    #[test]
    fn test_final_env_shell_functions() {
        let vars = [
            ("BASH_FUNC_ls%%", "() { evil; }"),
            ("FOO", "() not a function"),
        ];
        // never passed, even when kept by name
        let env = final_user_env(
            &resolved(EnvBehavior::Delete, &["BASH_FUNC_ls%%", "FOO"], &[], &[]),
            &vars,
        );
        assert!(!env.contains_key("BASH_FUNC_ls%%"));
        assert!(!env.contains_key("FOO"));
        let env = final_user_env(&resolved(EnvBehavior::Keep, &[], &[], &[]), &vars);
        assert!(!env.contains_key("BASH_FUNC_ls%%"));
    }

    #[test]
    fn test_final_env_check_precedence() {
        let vars = [
            ("CHECKED", "/unsafe"),
            ("SAFE", "ok"),
            ("TZ", "../../etc/x"),
        ];
        // a variable in both keep and check lists is still checked
        let env = final_user_env(
            &resolved(
                EnvBehavior::Delete,
                &["CHECKED", "SAFE", "TZ"],
                &["CHECKED", "SAFE", "TZ"],
                &[],
            ),
            &vars,
        );
        assert!(!env.contains_key("CHECKED"));
        assert_eq!(env.get("SAFE").unwrap(), "ok");
        assert!(!env.contains_key("TZ"));
        // in keep mode, the delete list wins over the check list
        let env = final_user_env(
            &resolved(EnvBehavior::Keep, &[], &["SAFE"], &["SAFE"]),
            &vars,
        );
        assert!(!env.contains_key("SAFE"));
        let env = final_user_env(&resolved(EnvBehavior::Keep, &[], &["CHECKED"], &[]), &vars);
        assert!(!env.contains_key("CHECKED"));
    }

    #[test]
    fn test_final_env() {
        let target = cred();
        let user_env = [
            ("VAR1", "AAAA"),
            ("VAR3", "VALUE3"),
            ("VAR4", "VALUE4"),
            ("VAR5", "VALUE5"),
        ];
        for behavior in [EnvBehavior::Delete, EnvBehavior::Keep] {
            let mut env = resolved(behavior, &["VAR3"], &["VAR5"], &["VAR4"]);
            env.set = IndexMap::from([("VAR1", "VALUE1"), ("VAR2", "VALUE2")]);
            let final_env = env
                .final_env(
                    user_env,
                    ["/usr/local/bin", "/usr/bin"],
                    &target,
                    None,
                    String::new(),
                )
                .unwrap();
            assert_eq!(final_env.get("PATH").unwrap(), "/usr/local/bin:/usr/bin");
            assert_eq!(*final_env.get("RAR_USER").unwrap(), target.user.name);
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
            assert_eq!(final_env.get("VAR5").unwrap(), "VALUE5");
        }
        // no level decides the behavior
        let env = resolved(EnvBehavior::Inherit, &[], &[], &[]);
        assert!(
            env.final_env(user_env, ["/usr/bin"], &target, None, String::new())
                .is_none()
        );
    }

    #[test]
    fn test_env_filter_is_the_policy_filter() {
        let vars = [
            ("LC_ALL", "C"),
            ("KEPT", "value"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("CHECKED", "/unsafe"),
            ("CHECKED", "safe"),
            ("TZ", "../../etc/x"),
            ("TZ", "Europe/Paris"),
            ("BASH_FUNC_ls%%", "() { evil; }"),
            ("OTHER", "value"),
        ];
        for behavior in [EnvBehavior::Delete, EnvBehavior::Keep, EnvBehavior::Inherit] {
            let env = resolved(behavior, &["LC_*", "KEPT"], &["CHECKED", "TZ"], &["LD_*"]);
            let filter = env.filter();
            for (key, value) in vars {
                assert_eq!(
                    filter.keeps(key, value),
                    env.keep_user_var(key, value),
                    "{behavior:?} {key}={value}"
                );
            }
        }
        // a filter that no policy decided keeps nothing
        assert!(!EnvFilter::default().keeps("LC_ALL", "C"));
    }

    #[test]
    fn test_env_filter_add_vars() {
        let target = cred();
        let mut env = resolved(EnvBehavior::Delete, &["KEPT", "PAM_*"], &["CHECKED"], &[]);
        env.set = IndexMap::from([("SET", "policy")]);
        let mut final_env = env
            .final_env(
                [("KEPT", "user")],
                ["/usr/bin"],
                &target,
                None,
                String::new(),
            )
            .unwrap();
        let pam_vars = [
            ("PATH", "/tmp/evil"),
            ("HOME", "/tmp"),
            ("SET", "pam"),
            ("KEPT", "pam"),
            ("PAM_NEW", "pam"),
            ("CHECKED", "/unsafe"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("PAM_FUNC", "() { evil; }"),
        ]
        .map(|(key, value)| (key.to_string(), value.to_string()));
        env.filter().add_vars(&mut final_env, pam_vars);
        // the variables of dosr, of the set list and the kept ones of the user take precedence
        assert_eq!(final_env.get("PATH").unwrap(), "/usr/bin");
        assert_eq!(
            *final_env.get("HOME").unwrap(),
            target.user.dir.to_string_lossy()
        );
        assert_eq!(final_env.get("SET").unwrap(), "policy");
        assert_eq!(final_env.get("KEPT").unwrap(), "user");
        // a new variable goes through the filter of the policy
        assert_eq!(final_env.get("PAM_NEW").unwrap(), "pam");
        assert!(!final_env.contains_key("CHECKED"));
        assert!(!final_env.contains_key("LD_PRELOAD"));
        assert!(!final_env.contains_key("PAM_FUNC"));
    }
}
