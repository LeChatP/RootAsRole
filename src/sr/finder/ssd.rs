use std::{cell::UnsafeCell, collections::{HashMap, HashSet}, error::Error, ptr};

use log::error;
use once_cell::sync::Lazy;
use rar_common::database::finder::ActorMatchMin;

use super::api::{Api, ApiEvent};

struct Ssd {
    tmp: HashSet<String>,
    matching_roles: HashSet<String>,
    ssd: HashMap<String, HashSet<String>>,
}

thread_local! {
    static TEMP_SSD: Lazy<UnsafeCell<Ssd>> = Lazy::new(|| UnsafeCell::new(Ssd {
        tmp: HashSet::new(),
        matching_roles: HashSet::new(),
        ssd: HashMap::new(),
    }));
}

fn manage_tmp_ssd(event: &mut ApiEvent) -> Result<(), Box<dyn Error>>{
    if let ApiEvent::NewRoleKey(key, value) = event {
        if *key == "ssd" {
            let ssd: HashSet<String> = serde_json::from_value(unsafe { ptr::read(*value) }).unwrap_or_default();
            if ssd.is_empty() {
                error!("Failed to parse SSD");
                return Ok(());
            }
            unsafe {
                let temp_ssd = &mut *TEMP_SSD.with(|m| m.get());
                temp_ssd.tmp = ssd.clone();
            }
        }
    }
    Ok(())
}

fn set_ssd(event: &mut ApiEvent) -> Result<(), Box<dyn Error>>{
    if let ApiEvent::BestTaskSettingsFound(settings) = event {
        let settings = settings.clone();
        unsafe {
            let temp_ssd = &mut *TEMP_SSD.with(|m| m.get());
            temp_ssd.matching_roles.insert(settings.role.clone());
            temp_ssd.ssd.insert(settings.role.clone(), temp_ssd.tmp.clone());
            temp_ssd.tmp.clear();
        }
    }
    Ok(())
}

fn add_matching_role(event: &mut ApiEvent) -> Result<(), Box<dyn Error>> {
    if let ApiEvent::BestRoleSettingsFound(settings) = event {
        TEMP_SSD.with(|temp_ssd| {
            let temp_ssd = unsafe { &mut *temp_ssd.get() };
            temp_ssd.matching_roles.insert(settings.role.clone());
        });
    }
    Ok(())
}

fn check_ssd(event: &mut ApiEvent) -> Result<(), Box<dyn Error>> {
    if let ApiEvent::BestGlobalSettingsFound(settings) = event {
        TEMP_SSD.with(|temp_ssd| -> Result<(), Box<dyn Error>> {
            let temp_ssd = unsafe { &*temp_ssd.get() };

            // Helper function to recursively check for conflicts
            fn has_conflict(
                role: &String,
                visited: &mut HashSet<String>,
                ssd: &HashMap<String, HashSet<String>>,
                matching_roles: &HashSet<String>,
            ) -> bool {
                if !visited.insert(role.clone()) {
                    // If the role is already visited, we have a circular dependency
                    return true;
                }

                if let Some(conflicting_roles) = ssd.get(role) {
                    for conflicting_role in conflicting_roles {
                        if matching_roles.contains(conflicting_role) {
                            error!(
                                "Conflict detected: Role '{}' is in SSD of '{}'",
                                conflicting_role, role
                            );
                            return true;
                        }
                        // Recursively check the conflicting role
                        if has_conflict(conflicting_role, visited, ssd, matching_roles) {
                            return true;
                        }
                    }
                }

                visited.remove(role); // Backtrack
                false
            }

            // Iterate through all matching roles and check for conflicts
            for role in &temp_ssd.matching_roles {
                let mut visited = HashSet::new();
                if has_conflict(role, &mut visited, &temp_ssd.ssd, &temp_ssd.matching_roles) {
                    settings.score.user_min = ActorMatchMin::NoMatch;
                }
            }
            Ok(())
        })?;
    }
    Ok(())
}

pub fn register() {
    Api::register(super::api::EventKey::NewRoleKey, manage_tmp_ssd);
    Api::register(super::api::EventKey::BestTaskSettings, set_ssd);
    Api::register(super::api::EventKey::BestRoleSettings, add_matching_role);
    Api::register(super::api::EventKey::BestGlobalSettings, check_ssd);
}