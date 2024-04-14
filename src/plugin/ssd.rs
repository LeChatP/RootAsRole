use std::ffi::CString;

use ::serde::Deserialize;
use nix::unistd::{getgrouplist, Group, User};

use crate::{
    as_borrow,
    common::{
        api::{PluginManager, PluginPosition, PluginResult},
        database::{structs::{SActor, SConfig, SGroups, SRole},
                    finder::Cred},
    },
};

#[derive(Deserialize)]
pub struct SSD(Vec<String>);

fn user_contained_in(user: &User, actors: &Vec<SActor>) -> bool {
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

fn group_contained_in(group: &Group, actors: &Vec<SActor>) -> bool {
    for actor in actors.iter() {
        if let SActor::Group { groups, .. } = actor {
            if let Some(groups) = groups {
                match groups {
                    SGroups::Single(group) => {
                        if group == group {
                            return true;
                        }
                    },
                    SGroups::Multiple(groups) => {
                        if groups.iter().any(|x| x == group){
                            return true;
                        }
                    },
                }
            } else {
                //TODO API call to verify if group is the described actor
                return false;
            }
        }
    }
    false
}

fn groups_subset_of(groups: &Vec<Group>, actors: &Vec<SActor>) -> bool {
    for group in groups.iter() {
        if !group_contained_in(group, actors) {
            return false;
        }
    }
    true
}

// Check if user and its related groups are forbidden to use the role
fn user_is_forbidden(user: &User, ssd_roles: &Vec<String>, sconfig: &SConfig) -> bool {
    
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
            if user_contained_in(user, &as_borrow!(role)
                .actors)
                || groups_subset_of(&groups_to_check, &as_borrow!(role).actors)
            {
                return true;
            }
        }
    }
    false
}

fn groups_are_forbidden(groups: &Vec<Group>, ssd_roles: &Vec<String>, sconfig: &SConfig) -> bool {
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
    let ssd = role._extra_fields.get("ssd");
    if ssd.is_none() {
        return PluginResult::Neutral;
    }
    let sconfig = role
        ._config
        .as_ref()
        .expect("role should have its config")
        .upgrade()
        .expect("internal error");
    let roles = serde_json::from_value::<SSD>(ssd.unwrap().clone());
    if roles.is_err() {
        return PluginResult::Neutral;
    }
    let roles = roles.unwrap().0;
    if user_is_forbidden(&actor.user, &roles, &as_borrow!(sconfig)) ||
        groups_are_forbidden(&actor.groups, &roles, &as_borrow!(sconfig)){
        PluginResult::Deny
    } else {
        PluginResult::Neutral
    }
}

pub fn register() {
    PluginManager::subscribe_duty_separation(check_separation_of_duty, PluginPosition::Beginning)
}
