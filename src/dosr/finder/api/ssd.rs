use std::{
    collections::HashSet,
    hash::{DefaultHasher, Hash, Hasher},
};

use log::debug;
use serde_json::Value;

#[cfg(feature = "hierarchy")]
use crate::finder::de::DRoleFinder;
use crate::{
    error::{SrError, SrResult},
    finder::de::DLinkedRole,
};

use super::{Api, ApiEvent};

fn calculate_hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Whether the user holds `role`: as one of its actors, or through a role that it holds as an
/// actor and that names `role` in its parents, whose tasks the hierarchy plugin grants.
fn holds(role: &DLinkedRole) -> bool {
    if role.role().user_min.matching() {
        return true;
    }
    #[cfg(feature = "hierarchy")]
    {
        let name = role.role().role.as_ref();
        role.config().roles().any(|senior| {
            senior.role().user_min.matching() && parents(senior.role()).any(|parent| parent == name)
        })
    }
    #[cfg(not(feature = "hierarchy"))]
    false
}

/// The parents that `role` names, one or a list.
#[cfg(feature = "hierarchy")]
fn parents<'r>(role: &'r DRoleFinder<'_>) -> impl Iterator<Item = &'r str> {
    let parents: &[Value] = match role.extra_values.get("parents") {
        Some(Value::Array(parents)) => parents,
        Some(parent @ Value::String(_)) => std::slice::from_ref(parent),
        _ => &[],
    };
    parents.iter().filter_map(Value::as_str)
}

/// Whether the separation of duty excludes `role` for the user: a role that it names in `ssd`
/// is held by the user, even through the hierarchy.
#[cfg(feature = "hierarchy")]
pub(super) fn excludes(role: &DLinkedRole) -> SrResult<bool> {
    check_ssd_recursive(role, &mut HashSet::new())
}

fn check_ssd_recursive(role: &DLinkedRole, visited: &mut HashSet<u64>) -> SrResult<bool> {
    if let Some(Value::Array(ssd)) = role.role().extra_values.get("ssd") {
        for ssd in ssd {
            if let Value::String(ssd) = ssd {
                if visited.contains(&calculate_hash(ssd)) {
                    continue; // Avoid infinite recursion
                }
                visited.insert(calculate_hash(ssd));
                if let Some(r) = role.config().role(ssd) {
                    if holds(&r) {
                        return Ok(true);
                    }
                    if check_ssd_recursive(&r, visited)? {
                        return Ok(true);
                    }
                }
            }
        }
    } else if let Some(Value::String(ssd)) = role.role().extra_values.get("ssd") {
        if visited.contains(&calculate_hash(ssd)) {
            return Ok(false); // Avoid infinite recursion
        }
        visited.insert(calculate_hash(ssd));
        if let Some(r) = role.config().role(ssd) {
            if holds(&r) {
                return Ok(true);
            }
            if check_ssd_recursive(&r, visited)? {
                return Ok(true);
            }
        }
    } else if let Some(e) = role.role().extra_values.get("ssd") {
        debug!("Invalid SSD value: {e:?}");
        return Err(SrError::ConfigurationError);
    }
    Ok(false)
}

fn check_ssd(event: &mut ApiEvent) -> SrResult<()> {
    if let ApiEvent::ActorMatching(role, _settings, matching) = event
        && role.role().user_min.matching()
    {
        let mut visited: HashSet<u64> = HashSet::new();
        if check_ssd_recursive(role, &mut visited)? {
            **matching = false;
            return Ok(());
        }
    }
    Ok(())
}

pub fn register() {
    Api::register(super::EventKey::ActorMatching, check_ssd);
}
