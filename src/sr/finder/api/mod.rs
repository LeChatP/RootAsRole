use std::{cell::UnsafeCell, collections::HashMap, error::Error, path::PathBuf};

use once_cell::sync::Lazy;
use rar_common::database::score::CmdMin;
use serde_json_borrow::Value;
use strum::Display;


use crate::Cli;

use super::{de::{DConfigFinder, DLinkedRole, DLinkedTask}, BestExecSettings};

mod hierarchy;
mod ssd;
mod hashchecker;

thread_local! {
    static API: Lazy<UnsafeCell<Api>> = Lazy::new(|| UnsafeCell::new(Api::new()));
}


pub struct Api {
    callbacks: HashMap<EventKey, Vec<Box<dyn Fn(&mut ApiEvent) -> Result<(), Box<dyn Error>> + Send>>>,
}


#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy, Display)]
pub enum EventKey {
    BestGlobalSettings,
    BestRoleSettings,
    BestTaskSettings,
    NewComplexCommand,
    ActorMatching,
}

#[allow(dead_code)]
pub enum ApiEvent<'a> {
    BestGlobalSettingsFound(&'a Cli, &'a DConfigFinder<'a>, &'a mut BestExecSettings, &'a mut bool),
    BestRoleSettingsFound(&'a Cli, &'a DLinkedRole<'a>, &'a mut BestExecSettings, &'a mut bool),
    BestTaskSettingsFound(&'a Cli, &'a DLinkedTask<'a>, &'a mut BestExecSettings, &'a mut bool),
    // NewComplexCommand (Value, env_path, cmd_path, cmd_args, cmd_min, final_path),
    ProcessComplexCommand (&'a Value<'a>, &'a [PathBuf], &'a PathBuf, &'a [String], &'a mut CmdMin, &'a mut PathBuf),
    ActorMatching(&'a DLinkedRole<'a>, &'a mut BestExecSettings, &'a mut bool),
}

impl ApiEvent<'_> {
    fn get_key(&self) -> EventKey {
        match self {
            ApiEvent::BestGlobalSettingsFound(..) => EventKey::BestGlobalSettings,
            ApiEvent::BestRoleSettingsFound(..) => EventKey::BestRoleSettings,
            ApiEvent::BestTaskSettingsFound(..) => EventKey::BestTaskSettings,
            ApiEvent::ProcessComplexCommand(..) => EventKey::NewComplexCommand,
            ApiEvent::ActorMatching(..) => EventKey::ActorMatching,
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
            if let Some(callbacks) = api.callbacks.get(&key) {
                for callback in callbacks.iter() {
                    callback(&mut event)?;
                }
            }
            Ok(())
        })?;
        Ok(())
    }
    pub fn register<F>(event: EventKey, function: F)
    where
        F: Fn(&mut ApiEvent) -> Result<(), Box<dyn Error>> + Send + 'static,
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

pub(super) fn register_plugins() {
    ssd::register();
    hashchecker::register();
    hierarchy::register();
}