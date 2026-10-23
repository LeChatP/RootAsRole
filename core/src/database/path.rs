//! How the `PATH` of a command is decided, for dosr and chsr alike.
//!
//! The path options of the default, global, role and task levels are merged into one set of
//! lists ([`ResolvedPath`]), then the `PATH` of the command is computed from them and from the
//! `PATH` of the user.

use indexmap::IndexSet;
use log::warn;

use crate::{
    database::options::PathBehavior,
    util::{ENV_PATH_ADD_LIST_SLICE, ENV_PATH_BEHAVIOR, ENV_PATH_REMOVE_LIST_SLICE},
};

/// The path options of one level, whatever their representation: owned by chsr, or borrowed
/// from the policy file by dosr. A list that the level does not define is `None`.
pub trait PathLevel {
    fn behavior(&self) -> PathBehavior;
    fn add(&self) -> Option<impl Iterator<Item = &str>>;
    fn sub(&self) -> Option<impl Iterator<Item = &str>>;
}

/// The path options of every level, merged from the most general to the most specific.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedPath<'a> {
    pub behavior: PathBehavior,
    pub add: IndexSet<&'a str>,
    pub sub: IndexSet<&'a str>,
}

impl ResolvedPath<'static> {
    /// The built-in defaults (`RAR_PATH_*` at build time), below the global level.
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            behavior: ENV_PATH_BEHAVIOR,
            add: ENV_PATH_ADD_LIST_SLICE.iter().copied().collect(),
            sub: ENV_PATH_REMOVE_LIST_SLICE.iter().copied().collect(),
        }
    }
}

impl<'a> ResolvedPath<'a> {
    /// Merge the options of a more specific level, like the env lists (see
    /// [`ResolvedEnv::apply`](super::env::ResolvedEnv::apply)): a list that the level does not
    /// define is inherited, even when the level sets its behavior; a defined list replaces the
    /// inherited one when the level sets its behavior, and extends it otherwise.
    pub fn apply(&mut self, level: &'a impl PathLevel) {
        let behavior = level.behavior();
        let replace = !behavior.is_inherit();
        if replace {
            self.behavior = behavior;
        }
        merge(&mut self.add, level.add(), replace);
        merge(&mut self.sub, level.sub(), replace);
    }

    /// The `PATH` of the command, from the `PATH` of the user:
    /// - in delete mode, the directories of the `add` list,
    /// - in keep-safe mode, the directories of the `add` list then those of the user's `PATH`,
    ///   in keep-unsafe mode every directory of the user's `PATH`,
    /// - a relative directory (`.`, an empty one, `bin`) is the working directory of the command,
    ///   which the user chooses: only the keep-unsafe mode keeps it, from the policy as from the
    ///   user, and a relative directory of the policy that is left out is logged,
    /// - the directories of the `sub` list are always removed, and each directory appears once.
    ///
    /// The directories of the policy come first, so they win over those of the user.
    /// No level deciding the behavior (`inherit` everywhere) is the delete mode.
    #[must_use]
    pub fn final_path<'b>(&'b self, user_path: &[&'b str]) -> Vec<&'b str> {
        let user_path: &[&str] = match self.behavior {
            PathBehavior::Delete | PathBehavior::Inherit => &[],
            PathBehavior::KeepSafe | PathBehavior::KeepUnsafe => user_path,
        };
        let keep_relative = self.behavior.is_keep_unsafe();
        let mut path: IndexSet<&str> = IndexSet::new();
        path.extend(self.add.iter().copied().filter(|dir| {
            let kept = keep_relative || dir.starts_with('/');
            if !kept {
                warn!("The directory {dir:?} of the path option is relative, it is left out");
            }
            kept
        }));
        path.extend(
            user_path
                .iter()
                .copied()
                .filter(|dir| keep_relative || dir.starts_with('/')),
        );
        path.retain(|dir| !self.sub.contains(dir));
        path.into_iter().collect()
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
        behavior: PathBehavior,
        add: Option<Vec<&'static str>>,
        sub: Option<Vec<&'static str>>,
    }

    impl PathLevel for Level {
        fn behavior(&self) -> PathBehavior {
            self.behavior
        }
        fn add(&self) -> Option<impl Iterator<Item = &str>> {
            self.add.as_ref().map(|l| l.iter().copied())
        }
        fn sub(&self) -> Option<impl Iterator<Item = &str>> {
            self.sub.as_ref().map(|l| l.iter().copied())
        }
    }

    const USER_PATH: &[&str] = &["/home/user/bin", ".", "/usr/bin", "/opt/bin"];

    /// The behavior and the PATH of the command, after the levels.
    fn final_path(levels: &[Level]) -> (PathBehavior, Vec<String>) {
        let mut path = ResolvedPath {
            behavior: PathBehavior::Delete,
            add: IndexSet::from(["/usr/bin", "/bin"]),
            sub: IndexSet::new(),
        };
        for level in levels {
            path.apply(level);
        }
        let dirs = path.final_path(USER_PATH);
        (path.behavior, dirs.into_iter().map(String::from).collect())
    }

    #[test]
    fn test_delete_mode_inherits_undefined_lists() {
        // a level that sets the delete mode without a list keeps the inherited directories
        let levels = [Level {
            behavior: PathBehavior::Delete,
            add: None,
            sub: Some(vec!["/bin"]),
        }];
        assert_eq!(final_path(&levels).1, ["/usr/bin"]);
        // only an empty list removes them
        let levels = [Level {
            behavior: PathBehavior::Delete,
            add: Some(vec![]),
            sub: None,
        }];
        assert!(final_path(&levels).1.is_empty());
    }

    #[test]
    fn test_keep_modes() {
        let level = |behavior| Level {
            behavior,
            add: Some(vec!["/sbin"]),
            sub: Some(vec!["/opt/bin"]),
        };
        // the directories of the policy come first, relative ones are dropped in keep-safe
        assert_eq!(
            final_path(&[level(PathBehavior::KeepSafe)]).1,
            ["/sbin", "/home/user/bin", "/usr/bin"]
        );
        assert_eq!(
            final_path(&[level(PathBehavior::KeepUnsafe)]).1,
            ["/sbin", "/home/user/bin", ".", "/usr/bin"]
        );
    }

    #[test]
    fn test_relative_directories_only_in_keep_unsafe() {
        let path = |behavior| ResolvedPath {
            behavior,
            add: IndexSet::from(["/sbin", ".", "", "bin"]),
            sub: IndexSet::new(),
        };
        let user_path = ["/usr/bin", "", ".", "tools"];
        // the relative directories of the policy and of the user are left out, the empty one
        // (the working directory too) included
        assert_eq!(path(PathBehavior::Delete).final_path(&user_path), ["/sbin"]);
        assert_eq!(
            path(PathBehavior::KeepSafe).final_path(&user_path),
            ["/sbin", "/usr/bin"]
        );
        assert_eq!(
            path(PathBehavior::KeepUnsafe).final_path(&user_path),
            ["/sbin", ".", "", "bin", "/usr/bin", "tools"]
        );
    }

    #[test]
    fn test_inheriting_level_extends_the_lists() {
        let levels = [
            Level {
                behavior: PathBehavior::KeepSafe,
                add: Some(vec!["/sbin"]),
                sub: None,
            },
            Level {
                behavior: PathBehavior::Inherit,
                add: Some(vec!["/usr/local/bin"]),
                sub: Some(vec!["/home/user/bin"]),
            },
        ];
        let (behavior, dirs) = final_path(&levels);
        assert_eq!(behavior, PathBehavior::KeepSafe);
        assert_eq!(dirs, ["/sbin", "/usr/local/bin", "/usr/bin", "/opt/bin"]);
    }

    #[test]
    fn test_no_decided_behavior_is_the_delete_mode() {
        let path = ResolvedPath {
            behavior: PathBehavior::Inherit,
            add: IndexSet::from(["/usr/bin"]),
            sub: IndexSet::new(),
        };
        assert_eq!(path.final_path(USER_PATH), ["/usr/bin"]);
    }
}
