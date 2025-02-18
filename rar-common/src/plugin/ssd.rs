use std::{cell::RefCell, ffi::CString, rc::Rc};

use ::serde::Deserialize;
use nix::unistd::{getgrouplist, Group, User};
use serde_json::Error;

use crate::{
    api::{PluginManager, PluginResult},
    as_borrow,
    database::{
        actor::{SActor, SGroups},
        finder::Cred,
        structs::{RoleGetter, SConfig, SRole},
    },
};

#[derive(Deserialize)]
pub struct Ssd(Vec<String>);

fn user_contained_in(user: &User, actors: &[SActor]) -> bool {
    for actor in actors.iter() {
        if let SActor::User { id, .. } = actor {
            if let Some(id) = id {
                if id == user {
                    return true;
                }
            } else {
                //TODO API call to verify if user is the described actor
                return false;
            }
        }
    }
    false
}

fn group_contained_in(pgroup: &Group, actors: &[SActor]) -> bool {
    for actor in actors.iter() {
        if let SActor::Group { groups, .. } = actor {
            if let Some(groups) = groups {
                match groups {
                    SGroups::Single(group) => {
                        if group == pgroup {
                            return true;
                        }
                    }
                    SGroups::Multiple(groups) => {
                        if groups.iter().any(|x| x == pgroup) {
                            return true;
                        }
                    }
                }
            } else {
                //TODO API call to verify if group is the described actor
                return false;
            }
        }
    }
    false
}

fn groups_subset_of(groups: &[Group], actors: &[SActor]) -> bool {
    for group in groups.iter() {
        if !group_contained_in(group, actors) {
            return false;
        }
    }
    true
}

// Check if user and its related groups are forbidden to use the role
fn user_is_forbidden(user: &User, ssd_roles: &[String], sconfig: Rc<RefCell<SConfig>>) -> bool {
    let mut groups_to_check = Vec::new();
    if let Ok(groups) = getgrouplist(
        CString::new(user.name.as_str()).unwrap().as_c_str(),
        user.gid,
    ) {
        for group in groups.iter() {
            let group = nix::unistd::Group::from_gid(group.to_owned());
            if let Ok(Some(group)) = group {
                groups_to_check.push(group);
            }
        }
    }
    for role in ssd_roles.iter() {
        if let Some(role) = sconfig.role(role) {
            if user_contained_in(user, &as_borrow!(role).actors)
                || groups_subset_of(&groups_to_check, &as_borrow!(role).actors)
            {
                return true;
            }
        }
    }
    false
}

fn groups_are_forbidden(
    groups: &[Group],
    ssd_roles: &[String],
    sconfig: Rc<RefCell<SConfig>>,
) -> bool {
    for role in ssd_roles.iter() {
        if let Some(role) = sconfig.role(role) {
            if groups_subset_of(groups, &as_borrow!(role).actors) {
                return true;
            }
        }
    }
    false
}

fn check_separation_of_duty(role: &SRole, actor: &Cred) -> PluginResult {
    let ssd = get_ssd_entry(role);
    if ssd.is_none() {
        return PluginResult::Neutral;
    }
    let sconfig = role
        ._config
        .as_ref()
        .expect("role should have its config")
        .upgrade()
        .expect("internal error");
    let roles = ssd.unwrap();
    if roles.is_err() {
        return PluginResult::Neutral;
    }
    let roles = roles.unwrap().0;
    if user_is_forbidden(&actor.user, &roles, sconfig.clone())
        || groups_are_forbidden(&actor.groups, &roles, sconfig.clone())
    {
        PluginResult::Deny
    } else {
        PluginResult::Neutral
    }
}

fn get_ssd_entry(role: &SRole) -> Option<Result<Ssd, Error>> {
    role._extra_fields
        .get("ssd")
        .map(|ssd| serde_json::from_value::<Ssd>(ssd.clone()))
}

pub fn register() {
    PluginManager::subscribe_duty_separation(check_separation_of_duty)
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::{
        database::structs::{SConfig, SRole},
        rc_refcell,
    };
    use nix::unistd::{Group, Pid};
    use serde_json::Value;

    #[test]
    fn test_user_contained_in() {
        let user = User::from_uid(0.into()).unwrap().unwrap();
        let actors = vec![SActor::user(0).build()];
        assert!(user_contained_in(&user, &actors));
    }

    #[test]
    fn test_group_contained_in() {
        let group = Group::from_gid(0.into()).unwrap().unwrap();
        let actors = vec![SActor::group(0).build()];
        assert!(group_contained_in(&group, &actors));
    }

    #[test]
    fn test_groups_subset_of() {
        let groups = vec![Group::from_gid(0.into()).unwrap().unwrap()];
        let actors = vec![SActor::group(0).build()];
        assert!(groups_subset_of(&groups, &actors));
    }

    #[test]
    fn test_user_is_forbidden() {
        let user = User::from_uid(0.into()).unwrap().unwrap();
        let sconfig = SConfig::builder().build();
        let roles = vec!["role1".to_string()];
        assert!(!user_is_forbidden(&user, &roles, sconfig));
    }

    #[test]
    fn test_groups_are_forbidden() {
        let groups = vec![Group::from_gid(0.into()).unwrap().unwrap()];
        let sconfig = SConfig::builder()
            .role(
                SRole::builder("role1".to_string())
                    .actor(SActor::group(0).build())
                    .build(),
            )
            .build();
        let roles = vec!["role1".to_string()];
        assert!(groups_are_forbidden(&groups, &roles, sconfig));
    }

    #[test]
    fn test_check_separation_of_duty() {
        let sconfig = rc_refcell!(SConfig::default());
        let role = rc_refcell!(SRole::default());
        role.as_ref().borrow_mut()._config = Some(Rc::downgrade(&sconfig));
        role.as_ref().borrow_mut().name = "role1".to_string();
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::group(0).build());
        role.as_ref().borrow_mut()._extra_fields.insert(
            "ssd".to_string(),
            serde_json::Value::Array(vec![Value::String("role1".to_string())]),
        );
        sconfig.as_ref().borrow_mut().roles.push(role.clone());
        let actor = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            groups: vec![Group::from_gid(0.into()).unwrap().unwrap()],
            tty: None,
            ppid: Pid::parent(),
        };
        assert_eq!(
            check_separation_of_duty(&role.as_ref().borrow(), &actor),
            PluginResult::Deny
        );
    }
}
