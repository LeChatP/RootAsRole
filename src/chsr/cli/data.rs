use std::{collections::HashMap, num::NonZeroU8, path::PathBuf};

use bon::Builder;
use capctl::CapSet;
use indexmap::IndexSet;

use jiff::SignedDuration;
use pest_derive::Parser;
use rootasrole_core::{
    database::{
        actor::{SActor, SGroups, SUserType},
        options::{
            EnvBehavior, EnvKey, OptType, PathBehavior, SAuthentication, SBounding, SInfo,
            SPrivileged, SUMask, TimestampType, TtyOwner, WorkdirBehavior,
        },
        structs::{GroupsFrom, IdTask, SetBehavior},
    },
    util::StorageMethod,
};

#[derive(Parser)]
#[grammar = "chsr/cli/cli.pest"]
pub struct Cli;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RoleType {
    All,
    Actors,
    Tasks,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TaskType {
    All,
    Commands,
    Credentials,
}

#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub enum InputAction {
    Help,
    List,
    Set,
    Add,
    Del,
    Purge,
    Convert,
    Upgrade,
    #[default]
    None,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SetListType {
    White,
    Black,
    Check,
    Set,
}

/// The links of a role to other roles, kept in the role for the plugins.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RoleLink {
    /// The roles that a member of the role must not hold (ssd plugin)
    Ssd,
    /// The roles whose tasks the role gets (hierarchy plugin)
    Parents,
}

impl RoleLink {
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Ssd => "ssd",
            Self::Parents => "parents",
        }
    }
}

/// Whether `dosr -E` may change the env behavior, for `chsr o env override`.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EnvOverride {
    Allow,
    Deny,
    Unset,
}

/// The checks of the hashchecker plugin on the file of a command (deprecated, removed in 5.0).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CommandChecks {
    /// The hash type (`sha256`...) and the hash in hexadecimal
    pub hash: Option<(String, String)>,
    pub read_only: bool,
    pub immutable: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(usize)]
pub enum PasswordOpt {
    Tries = 0,
    Delay,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(usize)]
pub enum TimeoutOpt {
    Duration = 0,
    Type,
    MaxUsage,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
pub struct Inputs {
    pub action: InputAction,
    pub editor: bool,
    pub editor_path: Option<PathBuf>,
    pub editor_type: Option<StorageMethod>,
    pub setlist_type: Option<SetListType>,
    pub timeout_arg: Option<[bool; 3]>,
    pub timeout_type: Option<TimestampType>,
    pub timeout_duration: Option<SignedDuration>,
    pub timeout_max_usage: Option<u64>,
    pub role_link: Option<RoleLink>,
    pub role_links: Option<Vec<String>>,
    pub purpose: bool,
    pub task_purpose: Option<String>,
    pub cmd_checks: CommandChecks,
    pub options_env_override: Option<EnvOverride>,
    pub password_arg: Option<[bool; 2]>,
    pub password_tries: Option<NonZeroU8>,
    pub password_delay: Option<SignedDuration>,
    pub policy: bool,
    pub policy_path: Option<String>,
    pub role_id: Option<String>,
    pub role_type: Option<RoleType>,
    pub actors: Option<Vec<SActor>>,
    pub task_id: Option<IdTask>,
    pub task_type: Option<TaskType>,
    pub cmd_policy: Option<SetBehavior>,
    /// The command line to write in the policy, see `policy_command_line`
    pub cmd_id: Option<String>,
    pub cred_caps: Option<CapSet>,
    pub cred_setuid: Option<SUserType>,
    pub cred_setgid: Option<SGroups>,
    /// Whose groups the command gets when the task does not force them
    pub cred_groups_from: Option<GroupsFrom>,
    pub cred_policy: Option<SetBehavior>,
    pub options: bool,
    pub options_type: Option<OptType>,
    pub options_path: Option<String>,
    pub options_path_policy: Option<PathBehavior>,
    pub options_key_env: Option<IndexSet<EnvKey>>,
    pub options_env_values: Option<HashMap<String, String>>,
    pub options_env_policy: Option<EnvBehavior>,
    pub options_root: Option<SPrivileged>,
    pub options_bounding: Option<SBounding>,
    pub options_auth: Option<SAuthentication>,
    pub options_execinfo: Option<SInfo>,
    pub options_tty_owner: Option<TtyOwner>,
    pub options_umask: Option<SUMask>,
    pub options_workdir_policy: Option<WorkdirBehavior>,
    pub convertion: Option<Convertion>,
    pub convert_reconfigure: bool,
    pub upgrade_check: bool,
}

#[derive(Builder, Debug, Default)]
pub struct Convertion {
    pub from_type: Option<StorageMethod>,
    pub from: Option<PathBuf>,
    pub to_type: StorageMethod,
    pub to: PathBuf,
}
