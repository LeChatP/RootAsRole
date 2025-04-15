use std::{cell::UnsafeCell, collections::HashMap, error::Error, path::PathBuf};

use once_cell::sync::Lazy;
use rar_common::database::finder::CmdMin;
use serde_json::Value;
use strum::Display;


use super::BestExecSettings;

thread_local! {
    static API: Lazy<UnsafeCell<Api>> = Lazy::new(|| UnsafeCell::new(Api::new()));
}


pub struct Api {
    callbacks: HashMap<EventKey, Vec<Box<dyn FnMut(&mut ApiEvent) -> Result<(), Box<dyn Error>> + Send>>>,
}


#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy, Display)]
pub enum EventKey {
    BestGlobalSettings,
    BestRoleSettings,
    BestTaskSettings,
    NewRoleKey,
    NewComplexCommand,
}

pub enum ApiEvent<'a> {
    BestGlobalSettingsFound(&'a mut BestExecSettings),
    BestRoleSettingsFound(&'a mut BestExecSettings),
    BestTaskSettingsFound(&'a mut BestExecSettings),
    NewRoleKey (&'a str, &'a Value),
    NewComplexCommand (&'a HashMap<String, Value>, &'a PathBuf, &'a [String], &'a mut CmdMin),
}

impl ApiEvent<'_> {
    fn get_key(&self) -> EventKey {
        match self {
            ApiEvent::BestGlobalSettingsFound(_) => EventKey::BestGlobalSettings,
            ApiEvent::BestRoleSettingsFound(_) => EventKey::BestRoleSettings,
            ApiEvent::BestTaskSettingsFound(_) => EventKey::BestTaskSettings,
            ApiEvent::NewRoleKey(..) => EventKey::NewRoleKey,
            ApiEvent::NewComplexCommand(..) => EventKey::NewComplexCommand,
        }
    }
}

impl Api {
    fn new() -> Self {
        Api {
            callbacks: HashMap::new(),
        }
    }
    pub fn notify(mut event: ApiEvent) -> Result<(), Box<dyn Error>> {
        let key = event.get_key();
        API.with(|api| -> Result<(), Box<dyn Error>> {
            let api = unsafe { &mut *api.get() };
            if let Some(callbacks) = api.callbacks.get_mut(&key) {
                for callback in callbacks.iter_mut() {
                    callback(&mut event)?;
                }
            }
            Ok(())
        })?;
        Ok(())
    }
    pub fn register<F>(event: EventKey, function: F)
    where
        F: FnMut(&mut ApiEvent) -> Result<(), Box<dyn Error>> + Send + 'static,
    {
        API.with(|api| 
            unsafe {
                let api = &mut *api.get();
                let callbacks = api.callbacks.entry(event).or_insert_with(Vec::new);
                callbacks.push(Box::new(function));
            }
        );
    }
}