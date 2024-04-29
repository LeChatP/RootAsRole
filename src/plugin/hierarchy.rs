use std::cmp::Ordering;

use crate::common::{
    api::{PluginManager, PluginResultAction},
    database::{
        finder::{Cred, TaskMatch, TaskMatcher},
        structs::SRole,
    },
};

use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Deserialize)]
pub struct Parents(Vec<String>);

fn get_parents(role: &SRole) -> Option<Result<Parents, serde_json::Error>> {
    role._extra_fields
        .get("parents").map(|parents| serde_json::from_value::<Parents>(parents.clone()))
}

fn find_in_parents(
    role: &SRole,
    user: &Cred,
    command: &[String],
    matcher: &mut TaskMatch,
) -> PluginResultAction {
    //precondition matcher user matches
    if !matcher.user_matching() {
        return PluginResultAction::Ignore;
    }
    let mut result = PluginResultAction::Ignore;
    let config = role._config.as_ref().unwrap().upgrade().unwrap();
    match get_parents(role) {
        Some(Ok(parents)) => {
            debug!("Found parents {:?}", parents.0);
            for parent in parents.0.iter() {
                if let Some(role) = config.as_ref().borrow().role(parent) {
                    debug!("Checking parent role {}", parent);
                    match role.as_ref().borrow().tasks.matches(user, command) {
                        Ok(matches) => {
                            if !matcher.command_matching()
                                || (matches.command_matching()
                                    && matches.score.cmd_cmp(&matcher.score) == Ordering::Less)
                            {
                                matcher.score = matches.score;
                                matcher.settings = matches.settings;
                                result = PluginResultAction::Edit;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to match parent role {}", e);
                        }
                    }
                } else {
                    warn!("Parent role {} not found", parent);
                }
            }
        }
        _ => {
            warn!("No parents found for role {}", role.name);
            return PluginResultAction::Ignore;
        }
    };
    result
}

pub fn register() {
    PluginManager::subscribe_role_matcher(find_in_parents);
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use nix::unistd::{Pid, User};

    use super::*;
    use crate::{
        common::database::{
            finder::UserMin,
            structs::{IdTask, SActor, SCommand, SCommands, SConfig, STask},
        },
        rc_refcell,
    };

    #[test]
    fn test_find_in_parents() {
        let config = rc_refcell!(SConfig::default());
        let role1 = rc_refcell!(SRole::default());
        role1.as_ref().borrow_mut()._config = Some(Rc::downgrade(&config));
        role1.as_ref().borrow_mut().name = "role1".to_string();
        let task1 = rc_refcell!(STask::default());
        task1.as_ref().borrow_mut()._role = Some(Rc::downgrade(&role1));
        task1.as_ref().borrow_mut().name = IdTask::Name("task1".to_string());
        let mut command = SCommands::default();
        command.add.push(SCommand::Simple("ls".to_string()));
        task1.as_ref().borrow_mut().commands = command;
        role1.as_ref().borrow_mut().tasks.push(task1);

        config.as_ref().borrow_mut().roles.push(role1);
        let role1 = rc_refcell!(SRole::default());
        let task1 = rc_refcell!(STask::default());
        task1.as_ref().borrow_mut()._role = Some(Rc::downgrade(&role1));
        role1.as_ref().borrow_mut()._config = Some(Rc::downgrade(&config));
        role1.as_ref().borrow_mut().name = "role2".to_string();
        role1
            .as_ref()
            .borrow_mut()
            .actors
            .push(SActor::from_user_id(0));
        role1.as_ref().borrow_mut()._extra_fields.insert(
            "parents".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::String("role1".to_string())]),
        );
        task1.as_ref().borrow_mut().name = IdTask::Name("task2".to_string());
        role1.as_ref().borrow_mut().tasks.push(task1);
        config.as_ref().borrow_mut().roles.push(role1);

        let cred = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            groups: vec![],
            ppid: Pid::parent(),
            tty: None,
        };
        let mut matcher = TaskMatch::default();
        matcher.score.user_min = UserMin::UserMatch;
        let res = find_in_parents(
            &config.as_ref().borrow().roles[1].as_ref().borrow(),
            &cred,
            &["ls".to_string()],
            &mut matcher,
        );
        assert_eq!(res, PluginResultAction::Edit);
    }

    #[test]
    fn test_plugin_implemented() {
        register();
        let config = rc_refcell!(SConfig::default());
        let role1 = rc_refcell!(SRole::default());
        role1.as_ref().borrow_mut()._config = Some(Rc::downgrade(&config));
        role1.as_ref().borrow_mut().name = "role1".to_string();
        let task1 = rc_refcell!(STask::default());
        task1.as_ref().borrow_mut()._role = Some(Rc::downgrade(&role1));
        task1.as_ref().borrow_mut().name = IdTask::Name("task1".to_string());
        let mut command = SCommands::default();
        command.add.push(SCommand::Simple("ls".to_string()));
        task1.as_ref().borrow_mut().commands = command;
        role1.as_ref().borrow_mut().tasks.push(task1);

        config.as_ref().borrow_mut().roles.push(role1);
        let role1 = rc_refcell!(SRole::default());
        let task1 = rc_refcell!(STask::default());
        task1.as_ref().borrow_mut()._role = Some(Rc::downgrade(&role1));
        role1.as_ref().borrow_mut()._config = Some(Rc::downgrade(&config));
        role1.as_ref().borrow_mut().name = "role2".to_string();
        role1
            .as_ref()
            .borrow_mut()
            .actors
            .push(SActor::from_user_id(0));
        role1.as_ref().borrow_mut()._extra_fields.insert(
            "parents".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::String("role1".to_string())]),
        );
        task1.as_ref().borrow_mut().name = IdTask::Name("task2".to_string());
        role1.as_ref().borrow_mut().tasks.push(task1);
        config.as_ref().borrow_mut().roles.push(role1);

        let cred = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            groups: vec![],
            ppid: Pid::parent(),
            tty: None,
        };
        let mut matcher = TaskMatch::default();
        matcher.score.user_min = UserMin::UserMatch;
        let matches = config.matches(&cred, &["ls".to_string()]).unwrap();
        assert_eq!(
            matches.settings.task.upgrade().unwrap(),
            config.as_ref().borrow().roles[0].as_ref().borrow().tasks[0].clone()
        );
    }
}
