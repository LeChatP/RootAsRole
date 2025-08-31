use std::{cell::UnsafeCell, collections::HashMap, path::PathBuf};

use once_cell::sync::Lazy;
use rar_common::database::score::{CmdMin, Score};
use serde_json::Value;
use strum::Display;

use crate::{error::SrResult, Cli};

use super::{
    de::{DConfigFinder, DLinkedRole, DLinkedTask},
    options::BorrowedOptStack,
    BestExecSettings,
};

mod hashchecker;
mod hierarchy;
mod ssd;

thread_local! {
    static API: Lazy<UnsafeCell<Api>> = Lazy::new(|| UnsafeCell::new(Api::new()));
}

pub struct Api {
    callbacks: HashMap<EventKey, Vec<Box<dyn Fn(&mut ApiEvent) -> SrResult<()>>>>,
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
pub enum ApiEvent<'a, 't, 'c, 'f, 'g, 'h, 'i, 'j, 'k> {
    BestGlobalSettingsFound(
        &'f Cli,
        &'g DConfigFinder<'a>,
        &'j mut BorrowedOptStack<'a>,
        &'h mut BestExecSettings,
        &'i mut bool,
    ),
    BestRoleSettingsFound(
        &'f Cli,
        &'g DLinkedRole<'c, 'a>,
        &'h mut BorrowedOptStack<'a>,
        &'k &'k [&'k str],
        &'i mut BestExecSettings,
        &'j mut bool,
    ),
    BestTaskSettingsFound(
        &'f Cli,
        &'g DLinkedTask<'t, 'c, 'a>,
        &'j mut BorrowedOptStack<'a>,
        &'h mut BestExecSettings,
        &'i mut Score,
    ),
    // NewComplexCommand (Value, env_path, cmd_path, cmd_args, cmd_min, final_path),
    ProcessComplexCommand(
        &'f Value,
        &'g [&'g str],
        &'h PathBuf,
        &'i [String],
        &'j mut CmdMin,
        &'k mut Option<PathBuf>,
    ),
    ActorMatching(
        &'f DLinkedRole<'c, 'a>,
        &'g mut BestExecSettings,
        &'h mut bool,
    ),
}

impl ApiEvent<'_, '_, '_, '_, '_, '_, '_, '_, '_> {
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
    pub fn notify(mut event: ApiEvent) -> SrResult<()> {
        let key = event.get_key();
        API.with(|api| -> SrResult<()> {
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
        F: Fn(&mut ApiEvent) -> SrResult<()> + Send + 'static,
    {
        API.with(|api| unsafe {
            let api = &mut *api.get();
            let callbacks = api.callbacks.entry(event).or_default();
            callbacks.push(Box::new(function));
        });
    }
}

pub(super) fn register_plugins() {
    ssd::register();
    hashchecker::register();
    hierarchy::register();
}
