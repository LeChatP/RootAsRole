//! Which working directories a task allows, for dosr and chsr alike.
//!
//! The workdir options of the default, global, role and task levels are merged into one set of
//! lists ([`ResolvedWorkdir`]), with the same inheritance rule as the env and path lists.

use indexmap::IndexSet;

use crate::{
    database::options::WorkdirBehavior,
    util::{WORKDIR_ADD_LIST, WORKDIR_BEHAVIOR, WORKDIR_FALLBACK, WORKDIR_REMOVE_LIST},
};

/// The workdir options of one level, whatever their representation. A list or a fallback that
/// the level does not define is `None`.
pub trait WorkdirLevel {
    fn behavior(&self) -> WorkdirBehavior;
    fn add(&self) -> Option<impl Iterator<Item = &str>>;
    fn sub(&self) -> Option<impl Iterator<Item = &str>>;
    fn fallback(&self) -> Option<&str>;
}

/// The workdir options of every level, merged from the most general to the most specific.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedWorkdir<'a> {
    pub behavior: WorkdirBehavior,
    pub add: IndexSet<&'a str>,
    pub sub: IndexSet<&'a str>,
    /// The working directory of the command, instead of the current directory of the user.
    pub fallback: Option<&'a str>,
}

impl ResolvedWorkdir<'static> {
    /// The built-in defaults (`RAR_WORKDIR_*` at build time), below the global level.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            behavior: WORKDIR_BEHAVIOR,
            add: WORKDIR_ADD_LIST.iter().copied().collect(),
            sub: WORKDIR_REMOVE_LIST.iter().copied().collect(),
            fallback: WORKDIR_FALLBACK,
        }
    }
}

impl<'a> ResolvedWorkdir<'a> {
    /// Merge the options of a more specific level, like the env lists (see
    /// [`ResolvedEnv::apply`](super::env::ResolvedEnv::apply)). A fallback that the level
    /// defines replaces the inherited one.
    pub fn apply(&mut self, level: &'a impl WorkdirLevel) {
        let behavior = level.behavior();
        let replace = !behavior.is_inherit();
        if replace {
            self.behavior = behavior;
        }
        merge(&mut self.add, level.add(), replace);
        merge(&mut self.sub, level.sub(), replace);
        if let Some(fallback) = level.fallback() {
            self.fallback = Some(fallback);
        }
    }

    /// Whether the command may run in `workdir`: in allowlist mode (`none`) only the directories
    /// of the `add` list, in blacklist mode (`all`) every directory, never those of the `sub`
    /// list. No level deciding the behavior refuses every directory.
    #[must_use]
    pub fn allows(&self, workdir: &str) -> bool {
        let removed = self.sub.contains(workdir);
        match self.behavior {
            WorkdirBehavior::Allowlist => self.add.contains(workdir) && !removed,
            WorkdirBehavior::Blacklist => !removed,
            WorkdirBehavior::Inherit => false,
        }
    }
}

fn merge<'a>(
    inherited: &mut IndexSet<&'a str>,
    level: Option<impl Iterator<Item = &'a str>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Level {
        behavior: WorkdirBehavior,
        add: Option<Vec<&'static str>>,
        sub: Option<Vec<&'static str>>,
        fallback: Option<&'static str>,
    }

    impl WorkdirLevel for Level {
        fn behavior(&self) -> WorkdirBehavior {
            self.behavior
        }
        fn add(&self) -> Option<impl Iterator<Item = &str>> {
            self.add.as_ref().map(|l| l.iter().copied())
        }
        fn sub(&self) -> Option<impl Iterator<Item = &str>> {
            self.sub.as_ref().map(|l| l.iter().copied())
        }
        fn fallback(&self) -> Option<&str> {
            self.fallback
        }
    }

    /// Whether `/tmp` and `/root` are allowed, and the fallback, after the levels.
    fn resolved(levels: &[Level]) -> (bool, bool, Option<String>) {
        let mut workdir = ResolvedWorkdir {
            behavior: WorkdirBehavior::Blacklist,
            add: IndexSet::new(),
            sub: IndexSet::from(["/root"]),
            fallback: None,
        };
        for level in levels {
            workdir.apply(level);
        }
        (
            workdir.allows("/tmp"),
            workdir.allows("/root"),
            workdir.fallback.map(ToString::to_string),
        )
    }

    #[test]
    fn test_allowlist_level_inherits_undefined_lists() {
        // the inherited sub list still applies to a level that switches to the allowlist mode
        let levels = [Level {
            behavior: WorkdirBehavior::Allowlist,
            add: Some(vec!["/tmp", "/root"]),
            sub: None,
            fallback: None,
        }];
        assert_eq!(resolved(&levels), (true, false, None));
        // only an empty list removes it
        let levels = [Level {
            behavior: WorkdirBehavior::Allowlist,
            add: Some(vec!["/tmp", "/root"]),
            sub: Some(vec![]),
            fallback: None,
        }];
        assert_eq!(resolved(&levels), (true, true, None));
    }

    #[test]
    fn test_fallback_is_inherited() {
        let levels = [
            Level {
                behavior: WorkdirBehavior::Inherit,
                add: None,
                sub: None,
                fallback: Some("/srv"),
            },
            Level {
                behavior: WorkdirBehavior::Allowlist,
                add: Some(vec!["/tmp"]),
                sub: None,
                fallback: None,
            },
        ];
        assert_eq!(resolved(&levels), (true, false, Some("/srv".to_string())));
    }

    #[test]
    fn test_no_decided_behavior_refuses_every_directory() {
        let workdir = ResolvedWorkdir::default();
        assert!(!workdir.allows("/tmp"));
    }
}
