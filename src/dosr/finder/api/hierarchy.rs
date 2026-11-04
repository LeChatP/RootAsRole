use std::collections::HashSet;

use log::{debug, error};
use serde_json::Value;

use crate::{
    error::{SrError, SrResult},
    finder::de::DRoleFinder,
};

/// This module is not thread-safe.
use super::{Api, ApiEvent, EventKey};

/// The parents that `role` names, one or a list; another value is a configuration error.
pub(super) fn parents<'r>(role: &'r DRoleFinder<'_>) -> SrResult<Vec<&'r str>> {
    match role.extra_values.get("parents") {
        None => Ok(Vec::new()),
        Some(Value::String(parent)) => Ok(vec![parent.as_str()]),
        Some(Value::Array(parents)) => Ok(parents.iter().filter_map(Value::as_str).collect()),
        Some(value) => {
            error!(
                "The parents of the role {} are neither a role nor a list of roles: {value}",
                role.role
            );
            Err(SrError::ConfigurationError)
        }
    }
}

/// A role inherits the tasks of its ancestors: its parents, their parents, and so on, each once
/// even when the parents form a cycle. The tasks are scored with the actors of the role that the
/// user holds, not with those of the ancestor. An ancestor that the separation of duty excludes
/// gives no task, and neither do the ancestors that the role only reaches through it.
fn find_in_parents(event: &mut ApiEvent) -> SrResult<()> {
    if let ApiEvent::BestRoleSettingsFound(
        cli,
        cred,
        role,
        opt_stack,
        env_path,
        settings,
        matching,
    ) = event
    {
        let held_through = role.role().user_min;
        let mut visited: HashSet<&str> = HashSet::from([role.role().role.as_ref()]);
        let mut pending = parents(role.role())?;
        while let Some(name) = pending.pop() {
            if !visited.insert(name) {
                continue;
            }
            let Some(ancestor) = role.config().role(name) else {
                continue;
            };
            #[cfg(feature = "ssd")]
            if super::ssd::excludes(&ancestor)? {
                debug!(
                    "The ancestor role {} is excluded by the separation of duty",
                    ancestor.role().role
                );
                continue;
            }
            for task in ancestor.tasks() {
                **matching |= settings.task_settings_as(
                    cli,
                    cred,
                    &task,
                    held_through,
                    opt_stack,
                    env_path,
                )?;
            }
            pending.extend(parents(ancestor.role())?);
        }
    }
    Ok(())
}

pub fn register() {
    Api::register(EventKey::BestRoleSettings, find_in_parents);
}
