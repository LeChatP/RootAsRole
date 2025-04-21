use std::error::Error;

use serde_json_borrow::Value;

/// This module is not thread-safe.


use super::{Api, ApiEvent, EventKey};




fn find_in_parents(event: &mut ApiEvent) -> Result<(), Box<dyn Error>> {
    if let ApiEvent::BestRoleSettingsFound(cli, role, settings, matching) = event {
        return match role.role()._extra_values.get("parents") {
            Some(Value::Array(parents)) => {
                let mut parents = parents.iter();
                while let Some(Value::Str(parent)) = parents.next() {
                    evaluate_parent_role(parent.as_ref(), cli, role, settings, matching)?;
                }
                Ok(())
            },
            Some(Value::Str(parent)) => {
                evaluate_parent_role(parent, cli, role, settings, matching)
            },
            Some(_) => {
                Err("Invalid parent value".into())
            },
            None => {
                Ok(())
            }
        };
    }
    Ok(())
}

fn evaluate_parent_role(parent: &str, cli: &mut &crate::Cli, role: &mut &crate::finder::de::DLinkedRole<'_>, settings: &mut &mut crate::finder::BestExecSettings, matching: &mut &mut bool) -> Result<(), Box<dyn Error>> {
    Ok(if let Some(role)= role.config().role(parent) {
        for task in role.tasks() {
            **matching |= settings.task_settings(cli, task)?;
        }
    })
}

pub fn register() {
    Api::register(EventKey::BestRoleSettings, find_in_parents);
}