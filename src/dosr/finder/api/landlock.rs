use std::{
    cell::RefCell,
    collections::HashMap,
    io,
    path::{Path, PathBuf},
};

use bitflags::bitflags;
use landlock::{
    ABI, Access, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr,
};
use rootasrole_exec::orchestrator::{PreExecContext, PreExecStep, Stage};
use serde::{Deserialize, Serialize};

use crate::{
    error::{SrError, SrResult},
    finder::api::{Api, ApiEvent, EventKey},
};

const VERSION: ABI = ABI::V6;

bitflags! {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct FAccess: u8 {
        const R   = 0b100;
        const W   = 0b010;
        const X   = 0b001;
        const RW  = 0b110;
        const RX  = 0b101;
        const WX  = 0b011;
        const RWX = 0b111;
    }
}

impl Serialize for FAccess {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let mut s = String::new();
            if self.contains(Self::R) {
                s.push('R');
            }
            if self.contains(Self::W) {
                s.push('W');
            }
            if self.contains(Self::X) {
                s.push('X');
            }
            serializer.serialize_str(&s)
        } else {
            serializer.serialize_u8(self.bits())
        }
    }
}

impl<'de> Deserialize<'de> for FAccess {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AccessVisitor;

        impl serde::de::Visitor<'_> for AccessVisitor {
            type Value = FAccess;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string like 'RWX' or an integer bitmask")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut access = FAccess::empty();
                for c in v.chars() {
                    match c {
                        'R' => access |= FAccess::R,
                        'W' => access |= FAccess::W,
                        'X' => access |= FAccess::X,
                        _ => return Err(E::custom(format!("invalid access character: {c}"))),
                    }
                }
                Ok(access)
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                FAccess::from_bits(v)
                    .ok_or_else(|| E::custom(format!("invalid access bitmask: {v}")))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(AccessVisitor)
        } else {
            deserializer.deserialize_u8(AccessVisitor)
        }
    }
}

fn get_landlock_access(access: FAccess) -> BitFlags<AccessFs> {
    match access {
        FAccess::RWX | FAccess::RX => AccessFs::from_all(VERSION),
        FAccess::WX => AccessFs::from_write(VERSION) | AccessFs::Execute,
        FAccess::RW => {
            AccessFs::from_read(VERSION) | AccessFs::from_write(VERSION) & !AccessFs::Execute
        }
        FAccess::R => AccessFs::from_read(VERSION) & !AccessFs::Execute,
        FAccess::W => AccessFs::from_write(VERSION),
        FAccess::X => AccessFs::from_read(VERSION),
        _ => !AccessFs::from_all(VERSION),
    }
}

fn pre_exec(event: &mut ApiEvent) -> SrResult<()> {
    if let ApiEvent::PreExec(_, settings) = event {
        LANDLOCK_RULESET.with(|rs| *rs.borrow_mut() = None);
        if let Some(fileset) = settings.cred.extra_values.get("files") {
            let mut whitelist = HashMap::<PathBuf, FAccess>::new();
            if let Some(obj) = fileset.as_object() {
                for (key, value) in obj {
                    let access: FAccess = serde_json::from_value(value.clone())
                        .map_err(|_| SrError::ConfigurationError)?;
                    whitelist.insert(PathBuf::from(key), access);
                }
            }

            let mut ruleset = Ruleset::default()
                .handle_access(AccessFs::from_all(VERSION))
                .map_err(|_| SrError::ConfigurationError)?
                .create()
                .map_err(|_| SrError::ConfigurationError)?;

            for (path, access) in &whitelist {
                let landlock_access = get_landlock_access(*access);
                for path in expand(path) {
                    let path_fd = PathFd::new(path).map_err(|_| SrError::ConfigurationError)?;
                    ruleset = ruleset
                        .add_rule(PathBeneath::new(path_fd, landlock_access))
                        .map_err(|_| SrError::ConfigurationError)?;
                }
            }
            LANDLOCK_RULESET.with(|rs| {
                *rs.borrow_mut() = Some(ruleset);
            });
        }
    }
    Ok(())
}

/// The existing paths that match a path of the policy, one component at a time: a component
/// with `*`, `?`, `[` or `{` is matched against the names of the directory (globset syntax), the
/// others are taken as they are. A rule applies to the whole hierarchy beneath a directory, so
/// `**` is not needed: it only matches one component.
fn expand(pattern: &Path) -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::new()];
    for component in pattern.components() {
        let name = component.as_os_str();
        let matcher = name
            .to_str()
            .filter(|name| name.contains(['*', '?', '[', '{']))
            .and_then(|name| globset::Glob::new(name).ok())
            .map(|glob| glob.compile_matcher());
        paths = match matcher {
            None => paths.into_iter().map(|path| path.join(name)).collect(),
            Some(matcher) => paths
                .iter()
                .flat_map(|dir| {
                    std::fs::read_dir(dir)
                        .into_iter()
                        .flatten()
                        .flatten()
                        .filter(|entry| matcher.is_match(entry.file_name()))
                        .map(|entry| entry.path())
                })
                .collect(),
        };
    }
    paths.retain(|path| path.exists());
    paths
}

thread_local! {
    static LANDLOCK_RULESET: RefCell<Option<RulesetCreated>> = const { RefCell::new(None) };
}

pub unsafe fn apply_landlock_step(_: PreExecContext) -> io::Result<()> {
    LANDLOCK_RULESET.with(|ruleset| {
        if let Some(ruleset) = ruleset.borrow_mut().take() {
            ruleset
                .restrict_self()
                .map_err(|e| io::Error::other(format!("Failed to apply Landlock ruleset: {e}")))?;
        }
        Ok(())
    })
}

pub const LANDLOCK_STEP: PreExecStep = PreExecStep {
    stage: Stage::LOCKDOWN,
    run: apply_landlock_step,
};

pub fn register() {
    Api::register(EventKey::PreExec, pre_exec);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::from_str;

    #[test]
    fn test_faccess_serde() {
        assert_eq!(from_str::<FAccess>("\"R\"").unwrap(), FAccess::R);
        assert_eq!(from_str::<FAccess>("\"W\"").unwrap(), FAccess::W);
        assert_eq!(from_str::<FAccess>("\"X\"").unwrap(), FAccess::X);
        assert_eq!(from_str::<FAccess>("\"RW\"").unwrap(), FAccess::RW);
        assert_eq!(from_str::<FAccess>("\"RWX\"").unwrap(), FAccess::RWX);

        // Test invalid char
        assert!(from_str::<FAccess>("\"Z\"").is_err());
    }

    #[test]
    fn test_expand() {
        let dir = std::env::temp_dir().join(format!("rar-landlock-expand-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("a1/sub")).unwrap();
        std::fs::create_dir_all(dir.join("a2")).unwrap();
        std::fs::create_dir_all(dir.join("b")).unwrap();
        let expand_sorted = |pattern: PathBuf| {
            let mut paths = expand(&pattern);
            paths.sort();
            paths
        };
        assert_eq!(
            expand_sorted(dir.join("a*")),
            [dir.join("a1"), dir.join("a2")]
        );
        assert_eq!(expand_sorted(dir.join("*/sub")), [dir.join("a1/sub")]);
        assert_eq!(expand_sorted(dir.join("{b,c}")), [dir.join("b")]);
        // a path without pattern is kept if it exists, as before
        assert_eq!(expand_sorted(dir.join("b")), [dir.join("b")]);
        assert!(expand(&dir.join("missing")).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_get_landlock_access() {
        assert_eq!(
            get_landlock_access(FAccess::R),
            AccessFs::from_read(VERSION) & !AccessFs::Execute
        );
        assert_eq!(
            get_landlock_access(FAccess::W),
            AccessFs::from_write(VERSION)
        );
        assert_eq!(
            get_landlock_access(FAccess::RWX),
            AccessFs::from_all(VERSION)
        );
    }
}
