use std::error::Error;

use bon::builder;
use serde_json_borrow::Value;

use crate::{finder::{de::DLinkedRole, options::BorrowedOptStack, BestExecSettings}, Cli};

/// This module is not thread-safe.


use super::{Api, ApiEvent, EventKey};




fn find_in_parents(event: &mut ApiEvent) -> Result<(), Box<dyn Error>> {
    if let ApiEvent::BestRoleSettingsFound(cli, role, opt_stack, env_path, settings, matching) = event {
        return match role.role()._extra_values.get("parents") {
            Some(Value::Array(parents)) => {
                let mut parents = parents.iter();
                while let Some(Value::Str(parent)) = parents.next() {
                    evaluate_parent_role().parent(parent.as_ref()).cli(cli).role(role).opt_stack(opt_stack).settings(settings).matching(matching).env_path(&env_path).call()?;
                }
                Ok(())
            },
            Some(Value::Str(parent)) => {
                evaluate_parent_role().parent(parent.as_ref()).cli(cli).role(role).opt_stack(opt_stack).settings(settings).matching(matching).env_path(&env_path).call()
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

#[builder]
fn evaluate_parent_role<'a>(parent: &str, cli: &mut &Cli, role: &mut &DLinkedRole<'_,'a>, opt_stack : &mut BorrowedOptStack<'a>, settings: &mut &mut BestExecSettings, matching: &mut &mut bool, env_path: &[&str]) -> Result<(), Box<dyn Error>> {
    Ok(if let Some(role)= role.config().role(parent) {
        for task in role.tasks() {
            **matching |= settings.task_settings(cli, &task, opt_stack, env_path)?;
        }
    })
}

pub fn register() {
    Api::register(EventKey::BestRoleSettings, find_in_parents);
}