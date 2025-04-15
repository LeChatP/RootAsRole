/// This module is not thread-safe.
use std::{cell::UnsafeCell, collections::{HashMap, HashSet}, error::Error};

use log::{info, warn};
use once_cell::sync::Lazy;

use super::{api::{Api, ApiEvent, EventKey}, BestExecSettings};

struct Matches {
    temp: HashSet<String>,
    settings: HashMap<String, BestExecSettings>,
    hierarchy: HashMap<String, HashSet<String>>,
}

thread_local! {
    static MATCHES: Lazy<UnsafeCell<Matches>> = Lazy::new(|| UnsafeCell::new(Matches {
        settings: HashMap::new(),
        hierarchy: HashMap::new(),
        temp: HashSet::new(),
    }));
}

fn manage_temp_keys(event: &mut ApiEvent) -> Result<(), Box<dyn Error>> {
    if let ApiEvent::NewRoleKey(key, value) = event {
        if *key == "parents" {
            let parents: HashSet<String> = serde_json::from_value(unsafe { std::ptr::read(*value) }).unwrap_or_default();
            if parents.is_empty() {
                warn!("Failed to parse parents");
                return Ok(());
            }
            unsafe {
                let matches = &mut *MATCHES.with(|m| m.get());
                matches.temp = parents;
            }
        }
    }
    Ok(())
}

fn task_settings(event: &mut ApiEvent) -> Result<(), Box<dyn Error>> {
    if let ApiEvent::BestTaskSettingsFound(settings) = event {
        let settings = settings.clone();
        unsafe {
            let matches = &mut *MATCHES.with(|m| m.get());
            matches.settings.insert(settings.role.clone(), settings.clone());
            matches.hierarchy.insert(settings.role.clone(), matches.temp.clone());
            matches.temp.clear();
        }
    }
    Ok(())
}



fn find_in_parents(event: &mut ApiEvent) -> Result<(), Box<dyn Error>> {
    if let ApiEvent::BestRoleSettingsFound(settings) = event {
        MATCHES.with(|matches| {
            let matches = unsafe { &*matches.get() };

            // Recursive function to find the best settings in the hierarchy
            fn find_best_in_hierarchy<'a>(
                role: &'a String,
                matches: &'a Matches,
                visited: &mut HashSet<String>,
            ) -> Option<&'a BestExecSettings> {
                if visited.contains(role) {
                    return None; // Avoid infinite recursion in case of cyclic dependencies
                }
                visited.insert(role.clone());

                let mut best_settings = matches.settings.get(role);

                if let Some(parents) = matches.hierarchy.get(role) {
                    for parent in parents {
                        if let Some(parent_settings) = find_best_in_hierarchy(parent, matches, visited) {
                            if best_settings.is_none()
                                || parent_settings.score.cmd_cmp(&best_settings.as_ref().unwrap().score).is_lt()
                            {
                                info!("Found better settings in parent role {}: {:?}", parent, parent_settings);
                                best_settings = Some(&parent_settings);
                            }
                        }
                    }
                }

                best_settings
            }

            let mut visited = HashSet::new();
            if let Some(best_settings) = find_best_in_hierarchy(&settings.role, matches, &mut visited) {
                
                log::info!(
                    "Best settings for role {}: {:?}",
                    settings.role,
                    best_settings
                );
            } else {
                log::info!("No better parent role for {}", settings.role);
            }
        });
    }
    Ok(())
}

pub fn register() {
    Api::register(EventKey::BestTaskSettings, task_settings);
    Api::register(EventKey::NewRoleKey, manage_temp_keys);
    Api::register(EventKey::BestRoleSettings, find_in_parents);
}