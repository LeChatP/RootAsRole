use serde::Deserialize;

use crate::{error::{SrError, SrResult}, finder::api::{Api, ApiEvent, EventKey}};

/**
 * "seccomp": {
        // Default behavior for unspecified syscalls
        // "allow" to allow all unspecified syscalls
        // "deny" to deny all unspecified syscalls
        "default": "allow",

        // Action to take for denied syscalls
        // Can be a string like "SCMP_ACT_KILL_PROCESS" or an object like {"SCMP_ACT_ERRNO": 1}
        // If not specified, defaults to "SCMP_ACT_KILL_PROCESS"
        "deny_action": "SCMP_ACT_KILL_PROCESS",

        // List of syscalls to explicitly allow
        "allow": [
            "read",
            "write",
            "exit",
            "exit_group"
        ],
        // List of syscalls to explicitly deny
        "deny": [
            "ptrace",
            "fork",
            "vfork"
        ]
    }
 */

#[derive(Deserialize)]
enum DefaultAction {
    Allow,
    Deny,
}
fn pre_exec(event: &mut ApiEvent) -> SrResult<()> {
    if let ApiEvent::PreExec(_, settings) = event {
        if let Some(map) = settings.cred.extra_values.get("seccomp").map(|v| v.as_object()).flatten() {
            let default: DefaultAction = map.get("default")
                .and_then(|v| v.as_str())
                .map(|s| match s {
                    "allow" => DefaultAction::Allow,
                    _ => DefaultAction::Deny, // Fallback to deny
                })
                .unwrap_or(DefaultAction::Deny); 
            let deny_action = map.get("deny_action").and_then(|v| {
                if v.is_string() {
                    v.as_str().map(|s| (s.to_string(), None))
                } else if v.is_object() {
                    let obj = v.as_object().unwrap();
                    if obj.len() == 1 {
                        let (k, v) = obj.iter().next().unwrap();
                        if v.is_i64() {
                            Some((k.to_string(), v.as_i64().map(|i| i as i32)))
                        } else {
                            Some((k.to_string(), None))
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }).unwrap_or(("SCMP_ACT_KILL_PROCESS".to_string(), None));

            let allow = map.get("allow").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let deny = map.get("deny").and_then(|v| v.as_array()).cloned().unwrap_or_default();

            use libseccomp::*;
            let default_action = match default {
                DefaultAction::Allow => ScmpAction::Allow,
                DefaultAction::Deny => ScmpAction::from_str(&deny_action.0, deny_action.1)
                    .map_err(|_| SrError::ConfigurationError)?,
            };
            let mut ctx = ScmpFilterContext::new_filter(default_action)
                .map_err(|_| SrError::ConfigurationError)?;

            for syscall in deny.iter().filter_map(|v| v.as_str()) {
                let num = ScmpSyscall::from_name(syscall)
                    .map_err(|_| SrError::ConfigurationError)?;
                let action = ScmpAction::from_str(&deny_action.0, deny_action.1)
                    .map_err(|_| SrError::ConfigurationError)?;
                ctx.add_rule(action, num)
                    .map_err(|_| SrError::ConfigurationError)?;
            }

            for syscall in allow.iter().filter_map(|v| v.as_str()) {
                let num = ScmpSyscall::from_name(syscall)
                    .map_err(|_| SrError::ConfigurationError)?;
                ctx.add_rule(ScmpAction::Allow, num)
                    .map_err(|_| SrError::ConfigurationError)?;
            }

            
            ctx.load().map_err(|_| SrError::ConfigurationError)?;            
        }
    }
    Ok(())
}

pub(crate) fn register() {
    Api::register(EventKey::PreExec,pre_exec);
}