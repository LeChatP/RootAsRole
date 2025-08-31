use bon::builder;
use log::debug;
use serde_json::Value;

use crate::{
    error::SrResult,
    finder::{de::DLinkedRole, options::BorrowedOptStack, BestExecSettings},
    Cli,
};

/// This module is not thread-safe.
use super::{Api, ApiEvent, EventKey};

fn find_in_parents(event: &mut ApiEvent) -> SrResult<()> {
    if let ApiEvent::BestRoleSettingsFound(cli, role, opt_stack, env_path, settings, matching) =
        event
    {
        return match role.role()._extra_values.get("parents") {
            Some(Value::Array(parents)) => {
                let mut parents = parents.iter();
                while let Some(Value::String(parent)) = parents.next() {
                    evaluate_parent_role()
                        .parent(parent.as_ref())
                        .cli(cli)
                        .role(role)
                        .opt_stack(opt_stack)
                        .settings(settings)
                        .matching(matching)
                        .env_path(env_path)
                        .call()?;
                }
                Ok(())
            }
            Some(Value::String(parent)) => evaluate_parent_role()
                .parent(parent.as_ref())
                .cli(cli)
                .role(role)
                .opt_stack(opt_stack)
                .settings(settings)
                .matching(matching)
                .env_path(env_path)
                .call(),
            Some(v) => {
                debug!("Invalid parent value: {:?}", v);
                Err(crate::error::SrError::ConfigurationError)
            }
            None => Ok(()),
        };
    }
    Ok(())
}

#[builder]
fn evaluate_parent_role<'a>(
    parent: &str,
    cli: &mut &Cli,
    role: &mut &DLinkedRole<'_, 'a>,
    opt_stack: &mut BorrowedOptStack<'a>,
    settings: &mut &mut BestExecSettings,
    matching: &mut &mut bool,
    env_path: &[&str],
) -> SrResult<()> {
    if let Some(role) = role.config().role(parent) {
        for task in role.tasks() {
            **matching |= settings.task_settings(cli, &task, opt_stack, env_path)?;
        }
    };
    Ok(())
}

pub fn register() {
    Api::register(EventKey::BestRoleSettings, find_in_parents);
}
