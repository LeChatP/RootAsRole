use std::{collections::HashMap, path::PathBuf};

use bon::Builder;
use capctl::CapSet;
use chrono::Duration;
use linked_hash_set::LinkedHashSet;

use pest_derive::Parser;
use rar_common::{
    database::{
        actor::{SActor, SGroups, SUserType},
        options::{
            EnvBehavior, EnvKey, OptType, PathBehavior, SAuthentication, SBounding, SInfo,
            SPrivileged, SUMask, TimestampType,
        },
        structs::{IdTask, SetBehavior},
    },
    StorageMethod,
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

#[derive(Debug, PartialEq, Eq, Default)]
pub enum InputAction {
    Help,
    List,
    Set,
    Add,
    Del,
    Purge,
    Convert,
    #[default]
    None,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetListType {
    White,
    Black,
    Check,
    Set,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum TimeoutOpt {
    Duration = 0,
    Type,
    MaxUsage,
}

#[derive(Debug, Default)]
pub struct Inputs {
    pub action: InputAction,
    pub editor: bool,
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
    pub cred_setuid: Option<SUserType>,
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
    pub options_auth: Option<SAuthentication>,
    pub options_execinfo: Option<SInfo>,
    pub options_umask: Option<SUMask>,
    pub convertion: Option<Convertion>,
    pub convert_reconfigure: bool,
}

#[derive(Builder, Debug, Default)]
pub struct Convertion {
    pub from_type: Option<StorageMethod>,
    pub from: Option<PathBuf>,
    pub to_type: StorageMethod,
    pub to: PathBuf,
}
