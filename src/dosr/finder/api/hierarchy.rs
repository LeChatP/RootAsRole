use bon::builder;
use log::debug;
use rootasrole_core::Cred;
use serde_json::Value;

use crate::{
    Cli,
    error::SrResult,
    finder::{BestExecSettings, de::DLinkedRole, options::BorrowedOptStack},
};

/// This module is not thread-safe.
use super::{Api, ApiEvent, EventKey};

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
        return match role.role().extra_values.get("parents") {
            Some(Value::Array(parents)) => {
                let mut parents = parents.iter();
                while let Some(Value::String(parent)) = parents.next() {
                    evaluate_parent_role()
                        .parent(parent.as_ref())
                        .cli(cli)
                        .cred(cred)
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
                .cred(cred)
                .role(role)
                .opt_stack(opt_stack)
                .settings(settings)
                .matching(matching)
                .env_path(env_path)
                .call(),
            Some(v) => {
                debug!("Invalid parent value: {v:?}");
                Err(crate::error::SrError::ConfigurationError)
            }
            None => Ok(()),
        };
    }
    Ok(())
}

#[builder]
fn evaluate_parent_role<'c, 'a>(
    parent: &str,
    cli: &Cli,
    cred: &Cred,
    role: &DLinkedRole<'c, 'a>,
    opt_stack: &mut BorrowedOptStack<'c, 'a>,
    settings: &mut BestExecSettings,
    matching: &mut bool,
    env_path: &[&str],
) -> SrResult<()> {
    // the event is only sent for roles that the user holds: the tasks of their parents are
    // scored with the actors of the senior role, not with those of the parent
    let held_through = role.role().user_min;
    if let Some(parent) = role.config().role(parent) {
        // a parent that the separation of duty excludes gives no task, even when the user
        // holds it through this role
        #[cfg(feature = "ssd")]
        if super::ssd::excludes(&parent)? {
            debug!(
                "The parent role {} is excluded by the separation of duty",
                parent.role().role
            );
            return Ok(());
        }
        for task in parent.tasks() {
            *matching |=
                settings.task_settings_as(cli, cred, &task, held_through, opt_stack, env_path)?;
        }
    }
    Ok(())
}

pub fn register() {
    Api::register(EventKey::BestRoleSettings, find_in_parents);
}
