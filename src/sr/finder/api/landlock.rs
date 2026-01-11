use std::{collections::HashMap, path::PathBuf};

use bitflags::bitflags;
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI, BitFlags,
};
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
            if self.contains(FAccess::R) {
                s.push('R');
            }
            if self.contains(FAccess::W) {
                s.push('W');
            }
            if self.contains(FAccess::X) {
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

        impl<'de> serde::de::Visitor<'de> for AccessVisitor {
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
                        _ => return Err(E::custom(format!("invalid access character: {}", c))),
                    }
                }
                Ok(access)
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                FAccess::from_bits(v)
                    .ok_or_else(|| E::custom(format!("invalid access bitmask: {}", v)))
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
            AccessFs::from_read(VERSION)
                | AccessFs::from_write(VERSION) & !AccessFs::Execute
        }
        FAccess::R => AccessFs::from_read(VERSION) & !AccessFs::Execute,
        FAccess::W => AccessFs::from_write(VERSION),
        FAccess::X => AccessFs::from_read(VERSION),
        _ => !AccessFs::from_all(VERSION),
    }
}

fn pre_exec(event: &mut ApiEvent) -> SrResult<()> {
    if let ApiEvent::PreExec(_, settings) = event {
        if let Some(fileset) = settings.cred.extra_values.get("files") {
            let mut whitelist = HashMap::<PathBuf, FAccess>::new();
            if let Some(obj) = fileset.as_object() {
                for (key, value) in obj.iter() {
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

            for (path, access) in whitelist.iter() {
                let landlock_access = get_landlock_access(*access);
                let path_fd = PathFd::new(path).map_err(|_| SrError::ConfigurationError)?;
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, landlock_access))
                    .map_err(|_| SrError::ConfigurationError)?;
            }

            ruleset
                .restrict_self()
                .map_err(|_| SrError::ConfigurationError)?;
        }
    }
    Ok(())
}

pub(crate) fn register() {
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
