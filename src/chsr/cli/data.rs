use std::collections::HashMap;

use capctl::CapSet;
use chrono::Duration;
use linked_hash_set::LinkedHashSet;

use pest_derive::Parser;
use rar_common::database::{
    options::{
        EnvBehavior, EnvKey, OptType, PathBehavior, SAuthentication, SBounding, SPrivileged,
        TimestampType,
    },
    structs::{IdTask, SActor, SActorType, SGroups, SetBehavior},
};

#[derive(Parser)]
#[grammar = "chsr/cli/cli.pest"]
pub struct Cli;

#[derive(Debug, PartialEq, Eq)]
pub enum RoleType {
    All,
    Actors,
    Tasks,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TaskType {
    All,
    Commands,
    Credentials,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InputAction {
    Help,
    List,
    Set,
    Add,
    Del,
    Purge,
    None,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetListType {
    WhiteList,
    BlackList,
    CheckList,
    SetList,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum TimeoutOpt {
    Duration = 0,
    Type,
    MaxUsage,
}

#[derive(Debug)]
pub struct Inputs {
    pub action: InputAction,
    pub setlist_type: Option<SetListType>,
    pub timeout_arg: Option<[bool; 3]>,
    pub timeout_type: Option<TimestampType>,
    pub timeout_duration: Option<Duration>,
    pub timeout_max_usage: Option<u64>,
    pub role_id: Option<String>,
    pub role_type: Option<RoleType>,
    pub actors: Option<Vec<SActor>>,
    pub task_id: Option<IdTask>,
    pub task_type: Option<TaskType>,
    pub cmd_policy: Option<SetBehavior>,
    pub cmd_id: Option<Vec<String>>,
    pub cred_caps: Option<CapSet>,
    pub cred_setuid: Option<SActorType>,
    pub cred_setgid: Option<SGroups>,
    pub cred_policy: Option<SetBehavior>,
    pub options: bool,
    pub options_type: Option<OptType>,
    pub options_path: Option<String>,
    pub options_path_policy: Option<PathBehavior>,
    pub options_key_env: Option<LinkedHashSet<EnvKey>>,
    pub options_env_values: Option<HashMap<String, String>>,
    pub options_env_policy: Option<EnvBehavior>,
    pub options_root: Option<SPrivileged>,
    pub options_bounding: Option<SBounding>,
    pub options_wildcard: Option<String>,
    pub options_auth: Option<SAuthentication>,
}

impl Default for Inputs {
    fn default() -> Self {
        Inputs {
            action: InputAction::None,
            setlist_type: None,
            timeout_arg: None,
            timeout_type: None,
            timeout_duration: None,
            timeout_max_usage: None,
            role_id: None,
            role_type: None,
            actors: None,
            task_id: None,
            task_type: None,
            cmd_policy: None,
            cmd_id: None,
            cred_caps: None,
            cred_setuid: None,
            cred_setgid: None,
            cred_policy: None,
            options: false,
            options_type: None,
            options_path: None,
            options_path_policy: None,
            options_key_env: None,
            options_env_values: None,
            options_env_policy: None,
            options_root: None,
            options_bounding: None,
            options_wildcard: None,
            options_auth: None,
        }
    }
}
