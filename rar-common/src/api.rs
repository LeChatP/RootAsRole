use std::sync::Mutex;

use capctl::CapSet;

#[cfg(feature = "finder")]
use log::debug;
#[cfg(feature = "finder")]
use serde_json::Value;
use strum::EnumIs;

#[cfg(feature = "finder")]
use crate::database::finder::{ActorMatchMin, Cred, ExecSettings, TaskMatch};
#[cfg(feature = "finder")]
use crate::database::FilterMatcher;

use crate::database::{
    actor::SActor,
    structs::{SConfig, SRole, STask},
};
use once_cell::sync::Lazy;
static API: Lazy<Mutex<PluginManager>> = Lazy::new(|| Mutex::new(PluginManager::new()));

// Define a trait for the plugin
pub trait Plugin {
    fn initialize(&self);
    fn cleanup(&self);
}

#[derive(Debug, PartialEq, Eq, EnumIs)]
pub enum PluginResultAction {
    Override, // The result of this plugin ends the algorithm to return the plugin result
    Edit,     // The result of this plugin modify the result, algorithm continues
    Ignore,   // The result of this plugin is ignored, algorithm continues
}

#[derive(Debug, PartialEq, Eq, EnumIs)]
pub enum PluginResult {
    Deny,    // The plugin denies the action
    Neutral, // The plugin has no opinion on the action
}

pub type ConfigLoaded = fn(config: &SConfig);

#[cfg(feature = "finder")]
pub type RoleMatcher = fn(
    role: &SRole,
    user: &Cred,
    filter: &Option<FilterMatcher>,
    command: &[String],
    matcher: &mut TaskMatch,
) -> PluginResultAction;
#[cfg(feature = "finder")]
pub type TaskMatcher = fn(
    task: &STask,
    user: &Cred,
    command: &[String],
    matcher: &mut TaskMatch,
) -> PluginResultAction;
#[cfg(feature = "finder")]
pub type UserMatcher = fn(role: &SRole, user: &Cred, user_struct: &Value) -> ActorMatchMin;

pub type RoleInformation = fn(role: &SRole) -> Option<String>;
pub type ActorInformation = fn(actor: &SActor) -> Option<String>;
pub type TaskInformation = fn(task: &STask) -> Option<String>;

#[cfg(feature = "finder")]
pub type DutySeparation = fn(role: &SRole, actor: &Cred) -> PluginResult;
#[cfg(feature = "finder")]
pub type TaskSeparation = fn(task: &STask, actor: &Cred) -> PluginResult;

pub type CapsFilter = fn(task: &STask, capabilities: &mut CapSet) -> PluginResultAction;
#[cfg(feature = "finder")]
pub type ExecutionChecker = fn(user: &Cred, exec: &mut ExecSettings) -> PluginResult;

pub type ComplexCommandParser =
    fn(command: &serde_json::Value) -> Result<Vec<String>, Box<dyn std::error::Error>>;

macro_rules! plugin_subscribe {
    ($plugin:ident, $plugin_type:ident, $plugin_function:ident) => {
        let mut api = API.lock().unwrap();
        api.$plugin.push($plugin_function);
    };
}

// Define a struct to hold the plugins
pub struct PluginManager {
    #[cfg(feature = "finder")]
    role_matcher_plugins: Vec<RoleMatcher>,
    #[cfg(feature = "finder")]
    task_matcher_plugins: Vec<TaskMatcher>,
    #[cfg(feature = "finder")]
    user_matcher_plugins: Vec<UserMatcher>,
    #[cfg(feature = "finder")]
    duty_separation_plugins: Vec<DutySeparation>,
    #[cfg(feature = "finder")]
    task_separation_plugins: Vec<TaskSeparation>,
    caps_filter_plugins: Vec<CapsFilter>,
    #[cfg(feature = "finder")]
    execution_checker_plugins: Vec<ExecutionChecker>,
    complex_command_parsers: Vec<ComplexCommandParser>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> Self {
        PluginManager {
            #[cfg(feature = "finder")]
            role_matcher_plugins: Vec::new(),
            #[cfg(feature = "finder")]
            task_matcher_plugins: Vec::new(),
            #[cfg(feature = "finder")]
            user_matcher_plugins: Vec::new(),
            #[cfg(feature = "finder")]
            duty_separation_plugins: Vec::new(),
            #[cfg(feature = "finder")]
            task_separation_plugins: Vec::new(),
            caps_filter_plugins: Vec::new(),
            #[cfg(feature = "finder")]
            execution_checker_plugins: Vec::new(),
            complex_command_parsers: Vec::new(),
        }
    }

    #[cfg(feature = "finder")]
    pub fn subscribe_role_matcher(plugin: RoleMatcher) {
        plugin_subscribe!(role_matcher_plugins, RoleMatcher, plugin);
    }

    #[cfg(feature = "finder")]
    pub fn subscribe_task_matcher(plugin: TaskMatcher) {
        plugin_subscribe!(task_matcher_plugins, TaskMatcher, plugin);
    }

    #[cfg(feature = "finder")]
    pub fn subscribe_user_matcher(plugin: UserMatcher) {
        plugin_subscribe!(user_matcher_plugins, UserMatcher, plugin);
    }

    #[cfg(feature = "finder")]
    pub fn subscribe_duty_separation(plugin: DutySeparation) {
        plugin_subscribe!(duty_separation_plugins, DutySeparation, plugin);
    }

    #[cfg(feature = "finder")]
    pub fn subscribe_task_separation(plugin: TaskSeparation) {
        plugin_subscribe!(task_separation_plugins, TaskSeparation, plugin);
    }

    pub fn subscribe_caps_filter(plugin: CapsFilter) {
        plugin_subscribe!(caps_filter_plugins, CapsFilter, plugin);
    }

    #[cfg(feature = "finder")]
    pub fn subscribe_privilege_checker(plugin: ExecutionChecker) {
        plugin_subscribe!(execution_checker_plugins, ExecutionChecker, plugin);
    }

    pub fn subscribe_complex_command_parser(plugin: ComplexCommandParser) {
        plugin_subscribe!(complex_command_parsers, ComplexCommandParser, plugin);
    }

    #[cfg(feature = "finder")]
    pub fn notify_role_matcher(
        role: &SRole,
        user: &Cred,
        filter: &Option<FilterMatcher>,
        command: &[String],
        matcher: &mut TaskMatch,
    ) -> PluginResultAction {
        debug!("Notifying role matchers");
        let api = API.lock().unwrap();
        let mut result = PluginResultAction::Ignore;
        for plugin in api.role_matcher_plugins.iter() {
            debug!("Calling role matcher plugin");
            match plugin(role, user, filter, command, matcher) {
                PluginResultAction::Override => return PluginResultAction::Override,
                PluginResultAction::Edit => result = PluginResultAction::Edit,
                PluginResultAction::Ignore => continue,
            }
        }
        result
    }

    #[cfg(feature = "finder")]
    pub fn notify_task_matcher(
        task: &STask,
        user: &Cred,
        command: &[String],
        matcher: &mut TaskMatch,
    ) -> PluginResultAction {
        let api = API.lock().unwrap();
        for plugin in api.task_matcher_plugins.iter() {
            match plugin(task, user, command, matcher) {
                PluginResultAction::Override => return PluginResultAction::Override,
                PluginResultAction::Edit => continue,
                PluginResultAction::Ignore => continue,
            }
        }
        PluginResultAction::Ignore
    }

    #[cfg(feature = "finder")]
    pub fn notify_user_matcher(role: &SRole, user: &Cred, user_struct: &Value) -> ActorMatchMin {
        let api = API.lock().unwrap();
        for plugin in api.user_matcher_plugins.iter() {
            let res = plugin(role, user, user_struct);
            if !res.is_no_match() {
                return res;
            }
        }
        ActorMatchMin::NoMatch
    }

    #[cfg(feature = "finder")]
    pub fn notify_duty_separation(role: &SRole, actor: &Cred) -> PluginResult {
        let api = API.lock().unwrap();
        for plugin in api.duty_separation_plugins.iter() {
            match plugin(role, actor) {
                PluginResult::Deny => return PluginResult::Deny,
                PluginResult::Neutral => continue,
            }
        }
        PluginResult::Neutral
    }

    #[cfg(feature = "finder")]
    pub fn notify_task_separation(task: &STask, actor: &Cred) -> PluginResult {
        let api = API.lock().unwrap();
        for plugin in api.task_separation_plugins.iter() {
            match plugin(task, actor) {
                PluginResult::Deny => return PluginResult::Deny,
                PluginResult::Neutral => continue,
            }
        }
        PluginResult::Neutral
    }

    pub fn notify_caps_filter(task: &STask, capabilities: &mut CapSet) -> PluginResultAction {
        let api = API.lock().unwrap();
        for plugin in api.caps_filter_plugins.iter() {
            match plugin(task, capabilities) {
                PluginResultAction::Override => return PluginResultAction::Override,
                PluginResultAction::Edit => continue,
                PluginResultAction::Ignore => continue,
            }
        }
        PluginResultAction::Ignore
    }

    #[cfg(feature = "finder")]
    pub fn notify_privilege_checker(user: &Cred, exec: &mut ExecSettings) -> PluginResult {
        let api = API.lock().unwrap();
        for plugin in api.execution_checker_plugins.iter() {
            match plugin(user, exec) {
                PluginResult::Deny => return PluginResult::Deny,
                PluginResult::Neutral => continue,
            }
        }
        PluginResult::Neutral
    }

    pub fn notify_complex_command_parser(
        command: &serde_json::Value,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let api = API.lock().unwrap();
        for plugin in api.complex_command_parsers.iter() {
            match plugin(command) {
                Ok(result) => return Ok(result),
                Err(_e) => {
                    //debug!("Error parsing command {:?}", e);
                    continue;
                }
            }
        }
        Err("No complex command parser found".into())
    }
}
