use std::{
    collections::HashSet,
    hash::{DefaultHasher, Hash, Hasher},
};

use log::debug;
use serde_json::Value;

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

fn check_ssd_recursive(role: &DLinkedRole, visited: &mut HashSet<u64>) -> SrResult<bool> {
    if let Some(Value::Array(ssd)) = role.role()._extra_values.get("ssd") {
        for ssd in ssd.iter() {
            if let Value::String(ssd) = ssd {
                if visited.contains(&calculate_hash(ssd)) {
                    continue; // Avoid infinite recursion
                }
                visited.insert(calculate_hash(ssd));
                if let Some(r) = role.config().role(ssd) {
                    if r.role().user_min.matching() {
                        return Ok(true);
                    }
                    if check_ssd_recursive(&r, visited)? {
                        return Ok(true);
                    }
                }
            }
        }
    } else if let Some(Value::String(ssd)) = role.role()._extra_values.get("ssd") {
        if visited.contains(&calculate_hash(ssd)) {
            return Ok(false); // Avoid infinite recursion
        }
        visited.insert(calculate_hash(ssd));
        if let Some(r) = role.config().role(ssd) {
            if r.role().user_min.matching() {
                return Ok(true);
            }
            if check_ssd_recursive(&r, visited)? {
                return Ok(true);
            }
        }
    } else if let Some(e) = role.role()._extra_values.get("ssd") {
        debug!("Invalid SSD value: {:?}", e);
        return Err(SrError::ConfigurationError);
    }
    Ok(false)
}

fn check_ssd(event: &mut ApiEvent) -> SrResult<()> {
    if let ApiEvent::ActorMatching(role, _settings, matching) = event {
        if role.role().user_min.matching() {
            let mut visited: HashSet<u64> = HashSet::new();
            if check_ssd_recursive(role, &mut visited)? {
                **matching = false;
                return Ok(());
            }
        }
    }
    Ok(())
}

pub fn register() {
    Api::register(super::EventKey::ActorMatching, check_ssd);
}
