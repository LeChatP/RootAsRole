use std::{
    cell::RefCell,
    error::Error,
    mem,
    ops::Deref,
    rc::{Rc, Weak},
    str::FromStr,
};

use capctl::{Cap, CapSet};
use chrono::Duration;
use const_format::formatcp;
use linked_hash_set::LinkedHashSet;
use pest::{error::LineColLocation, iterators::Pair, Parser};
use pest_derive::Parser;
use tracing::{debug, warn};

use crate::{
    common::{
        config::Storage,
        database::{
            options::{
                EnvBehavior, EnvKey, Opt, OptStack, OptType, PathBehavior, SBounding, SEnvOptions,
                SPathOptions, SPrivileged, STimeout, TimestampType,
            },
            structs::{
                IdTask, SActor, SActorType, SCapabilities, SCommand, SGroups, SRole,
                STask, SetBehavior,
            },
        },
        util::escape_parser_string,
    },
    rc_refcell,
};

#[derive(Parser)]
#[grammar = "chsr/cli.pest"]
struct Cli;

const LONG_ABOUT: &str = "Role Manager is a tool to configure RBAC for RootAsRole.
A role is a set of tasks that can be executed by a user or a group of users.
These tasks are multiple commands associated with their granted permissions (credentials).
Like Sudo, you could manipulate environment variables, PATH, and other options.
More than Sudo, you can manage the capabilities and remove privileges from the root user.";

const RST: &str = "\x1B[0m";
const BOLD: &str = "\x1B[1m";
const UNDERLINE: &str = "\x1B[4m";
const RED: &str = "\x1B[31m";

const RAR_USAGE_GENERAL: &str = formatcp!("{UNDERLINE}{BOLD}Usage:{RST} {BOLD}chsr{RST} [command] [options]

{UNDERLINE}{BOLD}Commands:{RST}
  {BOLD}-h, --help{RST}                    Show help for commands and options.
  {BOLD}list, show, l{RST}                 List available items; use with specific commands for detailed views.
  {BOLD}role, r{RST}                       Manage roles and related operations.
",UNDERLINE=UNDERLINE, BOLD=BOLD, RST=RST);

const RAR_USAGE_ROLE: &str = formatcp!("{UNDERLINE}{BOLD}Role Operations:{RST}
chsr role [role_name] [operation] [options]
  {BOLD}add, create{RST}                   Add a new role.
  {BOLD}del, delete, unset, d, rm{RST}     Delete a specified role.
  {BOLD}show, list, l{RST}                 Show details of a specified role (actors, tasks, all).
  {BOLD}purge{RST}                         Remove all items from a role (actors, tasks, all).
  
  {BOLD}grant{RST}                         Grant permissions to a user or group.
  {BOLD}revoke{RST}                        Revoke permissions from a user or group.
    {BOLD}-u, --user{RST} [user_name]      Specify a user for grant or revoke operations.
    {BOLD}-g, --group{RST} [group_names]   Specify one or more groups combinaison for grant or revoke operations.
",UNDERLINE=UNDERLINE, BOLD=BOLD, RST=RST);

const RAR_USAGE_TASK: &str = formatcp!("{UNDERLINE}{BOLD}Task Operations:{RST}
chsr role [role_name] task [task_name] [operation]
  {BOLD}show, list, l{RST}                 Show task details (all, cmd, cred).
  {BOLD}purge{RST}                         Purge configurations or credentials of a task (all, cmd, cred).
  {BOLD}add, create{RST}                   Add a new task.
  {BOLD}del, delete, unset, d, rm{RST}     Remove a task.
",UNDERLINE=UNDERLINE, BOLD=BOLD, RST=RST);

const RAR_USAGE_CMD: &str = formatcp!(
    "{UNDERLINE}{BOLD}Command Operations:{RST}
chsr role [role_name] task [task_name] command [cmd]
  {BOLD}show{RST}                          Show commands.
  {BOLD}setpolicy{RST} [policy]            Set policy for commands (allow-all, deny-all).
  {BOLD}whitelist, wl{RST} [listing]       Manage the whitelist for commands.
  {BOLD}blacklist, bl{RST} [listing]       Manage the blacklist for commands.
",
    UNDERLINE = UNDERLINE,
    BOLD = BOLD,
    RST = RST
);

const RAR_USAGE_CRED: &str = formatcp!(
    "{UNDERLINE}{BOLD}Credentials Operations:{RST}
chsr role [role_name] task [task_name] credentials [operation]
  {BOLD}show{RST}                          Show credentials.
  {BOLD}set, unset{RST}                    Set or unset credentials details.
  {BOLD}caps{RST}                          Manage capabilities for credentials.
",
    UNDERLINE = UNDERLINE,
    BOLD = BOLD,
    RST = RST
);

const RAR_USAGE_CRED_CAPS: &str = formatcp!(
    "{UNDERLINE}{BOLD}Capabilities Operations:{RST}
chsr role [role_name] task [task_name] credentials caps [operation]
  {BOLD}setpolicy{RST} [policy]            Set policy for capabilities (allow-all, deny-all).
  {BOLD}whitelist, wl{RST} [listing]       Manage whitelist for credentials.
  {BOLD}blacklist, bl{RST} [listing]       Manage blacklist for credentials.
",
    UNDERLINE = UNDERLINE,
    BOLD = BOLD,
    RST = RST
);

const RAR_USAGE_OPTIONS_GENERAL :&str = formatcp!("{UNDERLINE}{BOLD}Options:{RST}
chsr options [option] [operation]
chsr role [role_name] options [option] [operation]
chsr role [role_name] task [task_name] options [option] [operation]
  {BOLD}path{RST}                          Manage path settings (set, whitelist, blacklist).
  {BOLD}env{RST}                           Manage environment variable settings (set, whitelist, blacklist, checklist).
  {BOLD}root{RST} [policy]                 Defines when the root user (uid == 0) gets his privileges by default. (privileged, user, inherit)
  {BOLD}bounding{RST} [policy]             Defines when dropped capabilities are permanently removed in the instantiated process. (strict, ignore, inherit)
  {BOLD}wildcard-denied{RST}               Manage chars that are denied in binary path.
  {BOLD}timeout{RST}                       Manage timeout settings (set, unset).
",UNDERLINE=UNDERLINE, BOLD=BOLD, RST=RST);

const RAR_USAGE_OPTIONS_PATH :&str = formatcp!("{UNDERLINE}{BOLD}Path options:{RST}
chsr options path [operation]
  {BOLD}setpolicy{RST} [policy]            Specify the policy for path settings (delete-all, keep-safe, keep-unsafe, inherit).
  {BOLD}set{RST} [path]                    Set the policy as delete-all and the path to enforce.
  {BOLD}whitelist, wl{RST} [listing]       Manage the whitelist for path settings.
  {BOLD}blacklist, bl{RST} [listing]       Manage the blacklist for path settings.
",UNDERLINE=UNDERLINE, BOLD=BOLD, RST=RST);

const RAR_USAGE_OPTIONS_ENV :&str = formatcp!("{UNDERLINE}{BOLD}Environment options:{RST}
chsr options env [operation]
  {BOLD}setpolicy{RST} [policy]            Specify the policy for environment settings (delete-all, keep-all, inherit).
  {BOLD}set{RST} [key=value,...]           Set the policy as delete-all and the key-value map to enforce.
  {BOLD}whitelist, wl{RST} [listing]       Manage the whitelist for environment settings.
  {BOLD}blacklist, bl{RST} [listing]       Manage the blacklist for environment settings.
  {BOLD}checklist, cl{RST} [listing]       Manage the checklist for environment settings. (Removed if contains unsafe chars)
",UNDERLINE=UNDERLINE, BOLD=BOLD, RST=RST);

const RAR_USAGE_OPTIONS_TIMEOUT: &str = formatcp!(
    "{UNDERLINE}{BOLD}Timeout options:{RST}
chsr options timeout [operation]
  {BOLD}set, unset{RST}                    Set or unset timeout settings.
    {BOLD}--type{RST} [tty, ppid, uid]     Specify the type of timeout.
    {BOLD}--duration{RST} [HH:MM:SS]       Specify the duration of the timeout.
    {BOLD}--max-usage{RST} [number]        Specify the maximum usage of the timeout.",
    UNDERLINE = UNDERLINE,
    BOLD = BOLD,
    RST = RST
);

const RAR_USAGE_LISTING: &str = formatcp!(
    "{UNDERLINE}{BOLD}Listing:{RST}
    add [items,...]                        Add items to the list.
    del [items,...]                        Remove items from the list.
    set [items,...]                        Set items in the list.
    purge                                  Remove all items from the list.",
    UNDERLINE = UNDERLINE,
    BOLD = BOLD,
    RST = RST
);

#[derive(Debug, PartialEq, Eq)]
enum RoleType {
    All,
    Actors,
    Tasks,
}

#[derive(Debug, PartialEq, Eq)]
enum TaskType {
    All,
    Commands,
    Credentials,
}

#[derive(Debug, PartialEq, Eq)]
enum InputAction {
    Help,
    List,
    Set,
    Add,
    Del,
    Purge,
    None,
}

#[derive(Debug, PartialEq, Eq)]
enum SetListType {
    WhiteList,
    BlackList,
    CheckList,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(usize)]
enum TimeoutOpt {
    Duration = 0,
    Type,
    MaxUsage,
}

#[derive(Debug)]
struct Inputs {
    action: InputAction,
    setlist_type: Option<SetListType>,
    timeout_arg: Option<[bool;3]>,
    timeout_type: Option<TimestampType>,
    timeout_duration: Option<Duration>,
    timeout_max_usage: Option<u64>,
    role_id: Option<String>,
    role_type: Option<RoleType>,
    actors: Option<Vec<SActor>>,
    task_id: Option<IdTask>,
    task_type: Option<TaskType>,
    cmd_policy: Option<SetBehavior>,
    cmd_id: Option<String>,
    cred_caps: Option<CapSet>,
    cred_setuid: Option<SActorType>,
    cred_setgid: Option<SGroups>,
    cred_policy: Option<SetBehavior>,
    options: bool,
    options_type: Option<OptType>,
    options_path: Option<String>,
    options_path_policy: Option<PathBehavior>,
    options_env: Option<LinkedHashSet<EnvKey>>,
    options_env_policy: Option<EnvBehavior>,
    options_root: Option<SPrivileged>,
    options_bounding: Option<SBounding>,
    options_wildcard: Option<String>,
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
            options_env: None,
            options_env_policy: None,
            options_root: None,
            options_bounding: None,
            options_wildcard: None,
        }
    }
}

fn recurse_pair(pair: Pair<Rule>, inputs: &mut Inputs) {
    for inner_pair in pair.into_inner() {
        match_pair(&inner_pair, inputs);
        recurse_pair(inner_pair, inputs);
    }
}

fn match_pair(pair: &Pair<Rule>, inputs: &mut Inputs) {
    match pair.as_rule() {
        Rule::help => {
            inputs.action = InputAction::Help;
        }
        Rule::list => {
            inputs.action = InputAction::List;
        }
        Rule::set => {
            inputs.action = InputAction::Set;
        }
        Rule::add | Rule::grant => {
            inputs.action = InputAction::Add;
        }
        Rule::del | Rule::revoke => {
            inputs.action = InputAction::Del;
        }
        Rule::purge => {
            inputs.action = InputAction::Purge;
        }
        Rule::whitelist => {
            inputs.setlist_type = Some(SetListType::WhiteList);
        }
        Rule::blacklist => {
            inputs.setlist_type = Some(SetListType::BlackList);
        }
        Rule::checklist => {
            inputs.setlist_type = Some(SetListType::CheckList);
        }
        // === setpolicies ===
        Rule::cmd_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "deny-all" {
                inputs.cmd_policy = Some(SetBehavior::None);
            } else if pair.as_str() == "allow-all" {
                inputs.cmd_policy = Some(SetBehavior::All);
            } else {
                unreachable!("Unknown cmd policy: {}", pair.as_str())
            }
        }
        Rule::caps_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "deny-all" {
                inputs.cred_policy = Some(SetBehavior::None);
            } else if pair.as_str() == "allow-all" {
                inputs.cred_policy = Some(SetBehavior::All);
            } else {
                unreachable!("Unknown caps policy: {}", pair.as_str())
            }
        }
        Rule::path_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "delete-all" {
                inputs.options_path_policy = Some(PathBehavior::Delete);
            } else if pair.as_str() == "keep-safe" {
                inputs.options_path_policy = Some(PathBehavior::KeepSafe);
            } else if pair.as_str() == "keep-unsafe" {
                inputs.options_path_policy = Some(PathBehavior::KeepUnsafe);
            } else if pair.as_str() == "inherit" {
                inputs.options_path_policy = Some(PathBehavior::Inherit);
            } else {
                unreachable!("Unknown path policy: {}", pair.as_str())
            }
        }
        Rule::env_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "delete-all" {
                inputs.options_env_policy = Some(EnvBehavior::Delete);
            } else if pair.as_str() == "keep-all" {
                inputs.options_env_policy = Some(EnvBehavior::Keep);
            } else if pair.as_str() == "inherit" {
                inputs.options_env_policy = Some(EnvBehavior::Inherit);
            } else {
                unreachable!("Unknown env policy: {}", pair.as_str())
            }
        }
        // === timeout ===
        Rule::time => {
            let mut reversed = pair.as_str().split(':').rev();
            let mut duration: Duration =
                Duration::try_seconds(reversed.next().unwrap().parse::<i64>().unwrap_or(0))
                    .unwrap_or_default();
            if let Some(mins) = reversed.next() {
                duration = duration
                    .checked_add(
                        &Duration::try_minutes(mins.parse::<i64>().unwrap_or(0))
                            .unwrap_or_default(),
                    )
                    .expect("Invalid minutes");
                if let Some(hours) = reversed.next() {
                    duration = duration
                        .checked_add(
                            &Duration::try_hours(hours.parse::<i64>().unwrap_or(0)).unwrap_or_default(),
                        )
                        .expect("Invalid hours");
                }
            }
            inputs.timeout_duration = Some(duration);
        }
        Rule::opt_timeout_type => {
            if pair.as_str() == "tty" {
                inputs.timeout_type = Some(TimestampType::TTY);
            } else if pair.as_str() == "ppid" {
                inputs.timeout_type = Some(TimestampType::PPID);
            } else if pair.as_str() == "uid" {
                inputs.timeout_type = Some(TimestampType::UID);
            } else {
                unreachable!("Unknown timeout type: {}", pair.as_str())
            }
        }
        Rule::opt_timeout_t_arg => {
            let mut timeout_arg = inputs.timeout_arg.unwrap_or_default();
            timeout_arg[TimeoutOpt::Type as usize] = true;
            inputs.timeout_arg.replace(timeout_arg);
        }
        Rule::opt_timeout_d_arg => {
            let mut timeout_arg = inputs.timeout_arg.unwrap_or_default();
            timeout_arg[TimeoutOpt::Duration as usize] = true;
            inputs.timeout_arg.replace(timeout_arg);
        }
        Rule::opt_timeout_m_arg => {
            let mut timeout_arg = inputs.timeout_arg.unwrap_or_default();
            timeout_arg[TimeoutOpt::MaxUsage as usize] = true;
            inputs.timeout_arg.replace(timeout_arg);
        }
        Rule::opt_timeout_max_usage => {
            inputs.timeout_max_usage = Some(pair.as_str().parse::<u64>().unwrap());
        }
        // === roles ===
        Rule::role_id => {
            inputs.role_id = Some(pair.as_str().to_string());
        }
        Rule::role_type_arg => {
            if pair.as_str() == "all" {
                inputs.role_type = Some(RoleType::All);
            } else if pair.as_str() == "actors" {
                inputs.role_type = Some(RoleType::Actors);
            } else if pair.as_str() == "tasks" {
                inputs.role_type = Some(RoleType::Tasks);
            } else {
                unreachable!("Unknown role type: {}", pair.as_str())
            }
        }
        // === actors ===
        Rule::user => {
            if inputs.actors.is_none() {
                inputs.actors = Some(Vec::new());
            }
            inputs
                .actors
                .as_mut()
                .unwrap()
                .push(SActor::from_user_string(
                    pair.clone().into_inner().next().unwrap().as_str(),
                ));
        }
        Rule::group => {
            if inputs.actors.is_none() {
                inputs.actors = Some(Vec::new());
            }
            inputs
                .actors
                .as_mut()
                .unwrap()
                .push(SActor::from_group_vec_actors(
                    pair.clone()
                        .into_inner()
                        .map(|p| p.as_str().into())
                        .collect(),
                ));
        }
        // === tasks ===
        Rule::task_id => {
            inputs.task_id = Some(IdTask::Name(pair.as_str().to_string()));
        }
        Rule::task_type_arg => {
            if pair.as_str() == "all" {
                inputs.task_type = Some(TaskType::All);
            } else if pair.as_str() == "commands" || pair.as_str() == "cmd" {
                inputs.task_type = Some(TaskType::Commands);
            } else if pair.as_str().starts_with("cred") {
                inputs.task_type = Some(TaskType::Credentials);
            } else {
                unreachable!("Unknown task type: {}", pair.as_str());
            }
        }
        // === commands ===
        Rule::inner => {
            inputs.cmd_id = Some(pair.as_str().to_string());
        }
        // === credentials ===
        Rule::capability => {
            if inputs.cred_caps.is_none() {
                let caps = CapSet::empty();
                inputs.cred_caps = Some(caps);
            }
            if let Ok(cap) = Cap::from_str(pair.as_str()) {
                inputs.cred_caps.as_mut().unwrap().add(cap);
            } else {
                warn!("Unknown capability: {}", pair.as_str())
            }
        }
        Rule::cred_u => {
            inputs.cred_setuid = Some(pair.as_str().into());
        }
        Rule::cred_g => {
            let mut vec: Vec<SActorType> = Vec::new();
            for pair in pair.clone().into_inner() {
                if pair.as_rule() == Rule::actor_name {
                    vec.push(pair.as_str().into());
                }
            }
            if vec.is_empty() {
                warn!("No group specified");
            }
            if vec.len() == 1 {
                inputs.cred_setgid = Some(SGroups::Single(vec[0].clone()));
            } else {
                inputs.cred_setgid = Some(SGroups::Multiple(vec));
            }
        }
        // === options ===
        Rule::options_operations => {
            inputs.options = true;
        }
        Rule::opt_env_listing => {
            inputs.options_type = Some(OptType::Env);
        }
        Rule::opt_path_listing => {
            inputs.options_type = Some(OptType::Path);
        }
        Rule::opt_show_arg => {
            if pair.as_str() == "all" {
                inputs.options_type = None;
            } else if pair.as_str() == "path" {
                inputs.options_type = Some(OptType::Path);
            } else if pair.as_str() == "env" {
                inputs.options_type = Some(OptType::Env);
            } else if pair.as_str() == "root" {
                inputs.options_type = Some(OptType::Root);
            } else if pair.as_str() == "bounding" {
                inputs.options_type = Some(OptType::Bounding);
            } else if pair.as_str() == "wildcard-denied" {
                inputs.options_type = Some(OptType::Wildcard);
            } else if pair.as_str() == "timeout" {
                inputs.options_type = Some(OptType::Timeout);
            } else {
                unreachable!("Unknown option type: {}", pair.as_str())
            }
        }
        Rule::path => {
            inputs.options_path = Some(pair.as_str().to_string());
        }
        Rule::env_key => {
            if inputs.options_env.is_none() {
                inputs.options_env = Some(LinkedHashSet::new());
            }

            inputs
                .options_env
                .as_mut()
                .unwrap()
                .insert_if_absent(pair.as_str().into());
        }
        Rule::opt_root_args => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "privileged" {
                inputs.options_root = Some(SPrivileged::Privileged);
            } else if pair.as_str() == "user" {
                inputs.options_root = Some(SPrivileged::User);
            } else if pair.as_str() == "inherit" {
                inputs.options_root = Some(SPrivileged::Inherit);
            } else {
                unreachable!("Unknown root type: {}", pair.as_str());
            }
        }
        Rule::opt_bounding_args => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "strict" {
                inputs.options_bounding = Some(SBounding::Strict);
            } else if pair.as_str() == "ignore" {
                inputs.options_bounding = Some(SBounding::Ignore);
            } else if pair.as_str() == "inherit" {
                inputs.options_bounding = Some(SBounding::Inherit);
            } else {
                unreachable!("Unknown bounding type: {}", pair.as_str());
            }
        }
        Rule::wildcard_value => {
            inputs.options_wildcard = Some(pair.as_str().to_string());
        }
        Rule::all => {
            if inputs.role_id.is_some() && !inputs.task_id.is_some() {
                inputs.role_type = Some(RoleType::All);
            } else if inputs.task_id.is_some() {
                inputs.task_type = Some(TaskType::All);
            }
        }
        _ => {
            debug!("Unmatched rule: {:?}", pair.as_rule());
        }
    }
}


fn rule_to_string(rule: &Rule) -> String {
    match *rule {
        Rule::EOI => "no more input",
        Rule::args => "role, options, timeout or --help",
        Rule::opt_timeout_operations => "timeout set/unset operations",
        Rule::opt_timeout_d_arg => "--duration (hh:mm:ss)",
        Rule::opt_timeout_t_arg => "--type (tty, ppid, uid)",
        Rule::opt_timeout_m_arg => "--max-usage (\\d+)",
        Rule::roles_operations => "roles list/purge/add/del operations or existing role name",
        Rule::role_type_arg => "all, actors or tasks",
        Rule::role_grant_revoke => "grant, revoke",
        Rule::role_show_purge => "show, purge",
        Rule::task_keyword => "task",
        Rule::task_id => "task identifier",
        Rule::command_operations => "cmd",
        Rule::credentials_operations => "cred",
        Rule::cmd_checklisting => "whitelist, blacklist",
        Rule::cmd_policy => "allow-all or deny-all",
        Rule::cmd | Rule::inner => "a command line",
        Rule::cred_c => "--caps \"cap_net_raw, cap_sys_admin, ...\"",
        Rule::cred_g => "--group \"g1,g2\"",
        Rule::cred_u => "--user \"u1\"",
        Rule::cred_caps_operations => "caps",
        Rule::cli => "a command line",
        Rule::chsr => unreachable!(),
        Rule::list => "show, list, l",
        Rule::opt_timeout => "timeout",
        Rule::opt_path => "path",
        Rule::opt_env => "env",
        Rule::opt_root => "root",
        Rule::opt_bounding => "bounding",
        Rule::opt_wildcard => "wildcard",
        Rule::help => "--help",
        Rule::set => "set",
        Rule::setpolicy => "setpolicy",
        Rule::opt_env_listing => "whitelist, blacklist, checklist",
        _ => {
            println!("{:?}", rule);
            "unknown rule"
        }
    }
    .to_string()
}

fn print_role(
    role: &std::rc::Rc<std::cell::RefCell<crate::common::database::structs::SRole>>,
    role_type: &RoleType,
) {
    match role_type {
        RoleType::All => {
            println!("{}", serde_json::to_string_pretty(&role).unwrap());
        }
        RoleType::Actors => {
            println!(
                "{}",
                serde_json::to_string_pretty(&role.as_ref().borrow().actors).unwrap()
            );
        }
        RoleType::Tasks => {
            println!(
                "{}",
                serde_json::to_string_pretty(&role.as_ref().borrow().tasks).unwrap()
            );
        }
    }
}

fn start(error: &pest::error::Error<Rule>) -> (usize, usize) {
    match error.line_col {
        LineColLocation::Pos(line_col) => line_col,
        LineColLocation::Span(start_line_col, _) => start_line_col,
    }
}

fn underline(error: &pest::error::Error<Rule>) -> String {
    let mut underline = String::new();

    let mut start = start(error).1;
    let end = match error.line_col {
        LineColLocation::Span(_, (_, mut end)) => {
            let inverted_cols = start > end;
            if inverted_cols {
                mem::swap(&mut start, &mut end);
                start -= 1;
                end += 1;
            }

            Some(end)
        }
        _ => None,
    };
    let offset = start - 1;
    let line_chars = error.line().chars();

    for c in line_chars.take(offset) {
        match c {
            '\t' => underline.push('\t'),
            _ => underline.push(' '),
        }
    }

    if let Some(end) = end {
        underline.push('^');
        if end - start > 1 {
            for _ in 2..(end - start) {
                underline.push('-');
            }
            underline.push('^');
        }
    } else {
        underline.push_str("^---")
    }

    underline
}

fn usage_concat(usages: &[&'static str]) -> String {
    let mut usage = String::new();
    for u in usages {
        usage.push_str(u);
    }
    usage
}

pub fn main<I, S>(storage: &Storage, args: I) -> Result<bool, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    /*let binding = std::env::args().fold("\"".to_string(), |mut s, e| {
        s.push_str(&e);
        s.push_str("\" \"");
        s
    });*/

    let args = escape_parser_string(args);
    let args = Cli::parse(Rule::cli, &args);
    let args = match args {
        Ok(v) => v,
        Err(e) => {
            let mut usage = usage_concat(&[
                RAR_USAGE_GENERAL,
                RAR_USAGE_ROLE,
                RAR_USAGE_TASK,
                RAR_USAGE_CMD,
                RAR_USAGE_CRED,
            ]);
            let e = e.clone().renamed_rules(|rule| {
                match rule {
                    Rule::options_operations
                    | Rule::opt_args
                    | Rule::opt_show
                    | Rule::opt_show_arg
                    | Rule::opt_path
                    | Rule::opt_path_args
                    | Rule::opt_path_set
                    | Rule::opt_path_setpolicy
                    | Rule::path_policy
                    | Rule::path
                    | Rule::opt_env
                    | Rule::opt_env_args
                    | Rule::opt_env_setpolicy
                    | Rule::env_policy
                    | Rule::opt_env_set
                    | Rule::env_list
                    | Rule::env_key
                    | Rule::opt_root
                    | Rule::opt_root_args
                    | Rule::opt_bounding
                    | Rule::opt_bounding_args
                    | Rule::opt_wildcard
                    | Rule::opt_wildcard_args
                    | Rule::wildcard_value => {
                        usage = usage_concat(&[
                            RAR_USAGE_OPTIONS_GENERAL,
                            RAR_USAGE_OPTIONS_PATH,
                            RAR_USAGE_OPTIONS_ENV,
                            RAR_USAGE_OPTIONS_TIMEOUT,
                        ]);
                    }
                    Rule::caps_listing => {
                        usage = usage_concat(&[RAR_USAGE_CRED_CAPS, RAR_USAGE_LISTING]);
                    }
                    Rule::cmd_checklisting | Rule::opt_path_listing => {
                        usage = usage_concat(&[RAR_USAGE_CMD, RAR_USAGE_LISTING]);
                    }
                    Rule::opt_env_listing => {
                        usage = usage_concat(&[RAR_USAGE_OPTIONS_ENV, RAR_USAGE_LISTING]);
                    }
                    _ => {}
                };
                rule_to_string(rule)
            });
            println!("{}", usage);
            println!(
                "{RED}{BOLD}Unrecognized command line:\n| {RST}{}{RED}{BOLD}\n| {}\n= {}{RST}",
                e.line(),
                underline(&e),
                e.variant.message(),
                RED = RED,
                BOLD = BOLD,
                RST = RST
            );
            return Err(Box::new(e));
        }
    };
    let mut inputs = Inputs::default();
    for pair in args {
        recurse_pair(pair, &mut inputs);
    }
    debug!("Inputs : {:?}", inputs);
    match inputs {
        Inputs {
            action: InputAction::Help,
            ..
        } => {
            debug!("chsr help");
            println!("{}", LONG_ABOUT);
            println!("{}", RAR_USAGE_GENERAL);
            Ok(false)
        }
        Inputs {
            action: InputAction::List,
            options, // show options ?
            role_id,
            role_type,
            task_id,
            task_type,    // what to show
            options_type, // in json
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr list");
                return match list_json(
                    rconfig,
                    role_id,
                    task_id,
                    options,
                    options_type,
                    task_type,
                    role_type,
                ) {
                    Ok(_) => {
                        debug!("chsr list ok");
                        Ok(false)
                    }
                    Err(e) => {
                        debug!("chsr list err {:?}", e);
                        Err(e)
                    }
                };
            }
        },
        Inputs {
            // chsr role r1 add|del
            action,
            role_id: Some(role_id),
            task_id: None,
            setlist_type: None,
            options: false,
            actors: None,
            role_type,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 add|del");
                let mut config = rconfig.as_ref().borrow_mut();
                match action {
                    InputAction::Add => {
                        //verify if role exists
                        if config.role(&role_id).is_some() {
                            return Err("Role already exists".into());
                        }
                        config
                            .roles
                            .push(rc_refcell!(SRole::new(role_id, Weak::new())));
                        Ok(true)
                    }
                    InputAction::Del => {
                        if config.role(&role_id).is_none() {
                            return Err("Role do not exists".into());
                        }
                        config.roles.retain(|r| r.as_ref().borrow().name != role_id);
                        Ok(true)
                    }
                    InputAction::Purge => {
                        if config.role(&role_id).is_none() {
                            return Err("Role do not exists".into());
                        }
                        let role = config.role(&role_id).unwrap();
                        match role_type {
                            Some(RoleType::Actors) => {
                                role.as_ref().borrow_mut().actors.clear();
                            }
                            Some(RoleType::Tasks) => {
                                role.as_ref().borrow_mut().tasks.clear();
                            }
                            None | Some(RoleType::All) => {
                                role.as_ref().borrow_mut().actors.clear();
                                role.as_ref().borrow_mut().tasks.clear();
                            }
                        }
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
        },
        Inputs {
            // chsr role r1 grant|revoke -u u1 -u u2 -g g1,g2
            action,
            role_id: Some(role_id),
            actors: Some(mut actors),
            options: false,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 grant|revoke");
                let config = rconfig.as_ref().borrow_mut();
                let role = config.role(&role_id).ok_or("Role not found")?;
                match action {
                    InputAction::Add => {
                        //verify if actor is already in role
                        //remove already existing actors
                        actors.retain(|a| {
                            if role.as_ref().borrow().actors.contains(a) {
                                println!("Actor {} already in role", a);
                                false
                            } else {
                                true
                            }
                        });
                        role.as_ref().borrow_mut().actors.extend(actors);
                        Ok(true)
                    }
                    InputAction::Del => {
                        //if actor is not in role, warns
                        if !role.as_ref().borrow().actors.contains(&actors[0]) {
                            println!("Actor {} not in role", actors[0]);
                        }
                        role.as_ref()
                            .borrow_mut()
                            .actors
                            .retain(|a| !actors.contains(a));
                        Ok(true)
                    }
                    _ => unreachable!("Invalid action"),
                }
            }
        },

        Inputs {
            // chsr role r1 task t1 add|del
            action,
            role_id: Some(role_id),
            task_id: Some(task_id),
            setlist_type: None,
            options: false,
            cmd_id: None,
            cred_caps: None,
            cred_setuid: None,
            cred_setgid: None,
            task_type,
            cmd_policy: None,
            cred_policy: None,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 task t1 add|del");
                let config = rconfig.as_ref().borrow_mut();
                let role = config.role(&role_id).ok_or("Role not found")?;
                match action {
                    InputAction::Add => {
                        //verify if task exists
                        if role
                            .as_ref()
                            .borrow()
                            .tasks
                            .iter()
                            .any(|t| t.as_ref().borrow().name == task_id)
                        {
                            return Err("Task already exists".into());
                        }
                        role.as_ref()
                            .borrow_mut()
                            .tasks
                            .push(rc_refcell!(STask::new(task_id, Weak::new())));
                        Ok(true)
                    }
                    InputAction::Del => {
                        if role
                            .as_ref()
                            .borrow()
                            .tasks
                            .iter()
                            .all(|t| t.as_ref().borrow().name != task_id)
                        {
                            return Err("Task do not exists".into());
                        }
                        role.as_ref()
                            .borrow_mut()
                            .tasks
                            .retain(|t| t.as_ref().borrow().name != task_id);
                        Ok(true)
                    }
                    InputAction::Purge => {
                        let borrow = &role.as_ref().borrow();
                        let task = borrow.task(&task_id).expect("Task do not exists".into());
                        match task_type {
                            Some(TaskType::Commands) => {
                                task.as_ref().borrow_mut().commands.add.clear();
                                task.as_ref().borrow_mut().commands.sub.clear();
                                task.as_ref().borrow_mut().commands.default_behavior = None;
                            }
                            Some(TaskType::Credentials) => {
                                task.as_ref().borrow_mut().cred.capabilities = None;
                                task.as_ref().borrow_mut().cred.setuid = None;
                                task.as_ref().borrow_mut().cred.setgid = None;
                            }
                            None | Some(TaskType::All) => {
                                task.as_ref().borrow_mut().commands.add.clear();
                                task.as_ref().borrow_mut().commands.sub.clear();
                                task.as_ref().borrow_mut().commands.default_behavior = None;
                                task.as_ref().borrow_mut().cred.capabilities = None;
                                task.as_ref().borrow_mut().cred.setuid = None;
                                task.as_ref().borrow_mut().cred.setgid = None;
                            }
                        }
                        Ok(true)
                    }
                    _ => unreachable!("Invalid action"),
                }
            }
        },
        Inputs {
            //chsr role r1 task t1 cred set --caps "cap_net_raw,cap_sys_admin"
            action: InputAction::Set,
            role_id: Some(role_id),
            task_id: Some(task_id),
            cred_caps,
            cred_setuid,
            cred_setgid,
            cmd_id: None,
            cmd_policy: None,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 task t1 cred");
                let config = rconfig.as_ref().borrow_mut();
                match config.task(&role_id, &task_id) {
                    Ok(task) => {
                        if let Some(caps) = cred_caps {
                            task.as_ref().borrow_mut().cred.capabilities =
                                Some(SCapabilities::from(caps));
                        }
                        if let Some(setuid) = cred_setuid {
                            task.as_ref().borrow_mut().cred.setuid = Some(setuid);
                        }
                        if let Some(setgid) = cred_setgid {
                            task.as_ref().borrow_mut().cred.setgid = Some(setgid);
                        }
                        Ok(true)
                    }
                    Err(e) => Err(e),
                }
            }
        },
        Inputs {
            //chsr role r1 task t1 cred unset --caps "cap_net_raw,cap_sys_admin"
            action: InputAction::Del,
            role_id: Some(role_id),
            task_id: Some(task_id),
            cred_caps,
            cred_setuid,
            cred_setgid,
            cmd_id: None,
            cmd_policy: None,
            options: false,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 task t1 cred unset");
                let config = rconfig.as_ref().borrow_mut();
                match config.task(&role_id, &task_id) {
                    Ok(task) => {
                        if let Some(caps) = cred_caps {
                            if caps.is_empty() {
                                task.as_ref().borrow_mut().cred.capabilities = None;
                            } else if let Some(ccaps) =
                                task.as_ref().borrow_mut().cred.capabilities.as_mut()
                            {
                                ccaps.add.drop_all(caps);
                            } else {
                                return Err("No capabilities to remove".into());
                            }
                        }
                        if let Some(_) = cred_setuid {
                            task.as_ref().borrow_mut().cred.setuid = None;
                        }
                        if let Some(_) = cred_setgid {
                            task.as_ref().borrow_mut().cred.setgid = None;
                        }
                        Ok(true)
                    }
                    Err(e) => Err(e),
                }
            }
        },
        Inputs {
            action,
            role_id: Some(role_id),
            task_id: Some(task_id),
            setlist_type: Some(setlist_type),
            cred_caps: Some(cred_caps),
            cmd_policy: None,
            options: false,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 task t1 cred caps");
                let config = rconfig.as_ref().borrow_mut();
                let task = config.task(&role_id, &task_id)?;
                match setlist_type {
                    SetListType::WhiteList => match action {
                        InputAction::Add => {
                            let caps = &mut task.as_ref().borrow_mut().cred.capabilities;

                            caps.as_mut().unwrap().add = caps.as_ref().unwrap().add.union(cred_caps)
                        }
                        InputAction::Del => {
                            task.as_ref()
                                .borrow_mut()
                                .cred
                                .capabilities
                                .as_mut()
                                .unwrap()
                                .add
                                .drop_all(cred_caps);
                        }
                        InputAction::Set => {
                            task.as_ref()
                                .borrow_mut()
                                .cred
                                .capabilities
                                .as_mut()
                                .unwrap()
                                .add = cred_caps;
                        }
                        _ => unreachable!("Unknown action"),
                    },
                    SetListType::BlackList => match action {
                        InputAction::Add => {
                            let caps = &mut task.as_ref().borrow_mut().cred.capabilities;

                            caps.as_mut().unwrap().sub = caps.as_ref().unwrap().sub.union(cred_caps)
                        }
                        InputAction::Del => {
                            task.as_ref()
                                .borrow_mut()
                                .cred
                                .capabilities
                                .as_mut()
                                .unwrap()
                                .sub
                                .drop_all(cred_caps);
                        }
                        InputAction::Set => {
                            task.as_ref()
                                .borrow_mut()
                                .cred
                                .capabilities
                                .as_mut()
                                .unwrap()
                                .sub = cred_caps;
                        }
                        _ => unreachable!("Unknown action"),
                    },
                    _ => unreachable!("Unknown setlist type"),
                }
                Ok(true)
            }
        },
        Inputs {
            role_id: Some(role_id),
            task_id: Some(task_id),
            cred_policy: Some(cred_policy),
            options: false,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 task t1 cred setpolicy");
                let config = rconfig.as_ref().borrow_mut();
                let task = config.task(&role_id, &task_id)?;
                if task.as_ref().borrow_mut().cred.capabilities.is_none() {
                    task.as_ref()
                        .borrow_mut()
                        .cred
                        .capabilities
                        .replace(SCapabilities::default());
                }
                task.as_ref()
                    .borrow_mut()
                    .cred
                    .capabilities
                    .as_mut()
                    .unwrap()
                    .default_behavior = cred_policy;
                Ok(true)
            }
        },
        Inputs {
            action: InputAction::Set,
            role_id: Some(role_id),
            task_id: Some(task_id),
            cmd_policy: Some(cmd_policy),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 task t1 cmd setpolicy");
                let config = rconfig.as_ref().borrow_mut();
                let task = config.task(&role_id, &task_id)?;

                task.as_ref()
                    .borrow_mut()
                    .commands
                    .default_behavior
                    .replace(cmd_policy);
                Ok(true)
            }
        },
        Inputs {
            // chsr role r1 task t1 command whitelist add c1
            action,
            role_id: Some(role_id),
            task_id: Some(task_id),
            cmd_id: Some(cmd_id),
            setlist_type: Some(setlist_type),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 task t1 command whitelist add c1");
                let config = rconfig.as_ref().borrow_mut();
                let task = config.task(&role_id, &task_id)?;
                match setlist_type {
                    SetListType::WhiteList => match action {
                        InputAction::Add => {
                            //verify if command exists
                            if task
                                .as_ref()
                                .borrow()
                                .commands
                                .add
                                .contains(&SCommand::Simple(cmd_id.clone()))
                            {
                                return Err("Command already exists".into());
                            }
                            task.as_ref()
                                .borrow_mut()
                                .commands
                                .add
                                .push(SCommand::Simple(cmd_id));
                        }
                        InputAction::Del => {
                            //if command is not in task, warns
                            if !task
                                .as_ref()
                                .borrow()
                                .commands
                                .add
                                .contains(&SCommand::Simple(cmd_id.clone()))
                            {
                                println!("Command {} not in task", cmd_id);
                            }
                            task.as_ref().borrow_mut().commands.add.retain(|c| {
                                debug!(
                                    "'{:?}' != '{:?}' : {}",
                                    c,
                                    &SCommand::Simple(cmd_id.clone()),
                                    *c != SCommand::Simple(cmd_id.clone())
                                );
                                *c != SCommand::Simple(cmd_id.clone())
                            });
                        }
                        _ => unreachable!("Unknown action"),
                    },
                    SetListType::BlackList => match action {
                        InputAction::Add => {
                            //verify if command exists
                            if task
                                .as_ref()
                                .borrow()
                                .commands
                                .sub
                                .contains(&SCommand::Simple(cmd_id.clone()))
                            {
                                return Err("Command already exists".into());
                            }
                            task.as_ref()
                                .borrow_mut()
                                .commands
                                .sub
                                .push(SCommand::Simple(cmd_id));
                        }
                        InputAction::Del => {
                            //if command is not in task, warns
                            if !task
                                .as_ref()
                                .borrow()
                                .commands
                                .sub
                                .contains(&SCommand::Simple(cmd_id.clone()))
                            {
                                println!("Command {} not in task", cmd_id);
                            }
                            task.as_ref()
                                .borrow_mut()
                                .commands
                                .sub
                                .retain(|c| c != &SCommand::Simple(cmd_id.clone()));
                        }
                        _ => unreachable!("Unknown action"),
                    },
                    _ => unreachable!("Unknown setlist type"),
                }
                Ok(true)
            }
        },
        Inputs {
            role_id: Some(role_id),
            task_id: Some(task_id),
            cmd_policy: Some(cmd_policy),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr role r1 task t1 command setpolicy");
                let config = rconfig.as_ref().borrow_mut();
                let task = config.task(&role_id, &task_id)?;
                task.as_ref()
                    .borrow_mut()
                    .commands
                    .default_behavior
                    .replace(cmd_policy);
                Ok(true)
            }
        },
        // Set options
        Inputs {
            // chsr o env set A,B,C
            action: InputAction::Set,
            role_id,
            task_id,
            options_type: None,
            options_env: Some(options_env),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    let mut env = SEnvOptions::default();
                    env.default_behavior = EnvBehavior::Delete;
                    env.keep = options_env.clone();
                    opt.as_ref().borrow_mut().env = Some(env);
                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o root set privileged
            action: InputAction::Set,
            role_id,
            task_id,
            options_root: Some(options_root),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr o root set privileged");
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    opt.as_ref().borrow_mut().root = Some(options_root);
                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o bounding set strict
            action: InputAction::Set,
            role_id,
            task_id,
            options_bounding: Some(options_bounding),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    opt.as_ref().borrow_mut().bounding = Some(options_bounding);
                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o wildcard-denied set ";&*$"
            action,
            role_id,
            task_id,
            options_wildcard: Some(options_wildcard),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    match action {
                        InputAction::Set => {
                            opt.as_ref().borrow_mut().wildcard_denied =
                                Some(options_wildcard.clone());
                        }
                        InputAction::Add => {
                            let mut default_wildcard = opt
                                .as_ref()
                                .borrow()
                                .wildcard_denied
                                .clone()
                                .unwrap_or_default();
                            default_wildcard.extend(options_wildcard.chars());
                            opt.as_ref().borrow_mut().wildcard_denied = Some(default_wildcard);
                        }
                        InputAction::Del => {
                            if opt.as_ref().borrow().wildcard_denied.is_none() {
                                println!("No wildcard denied configured");
                                return Ok(());
                            }
                            opt.as_ref().borrow_mut().wildcard_denied.as_mut().map(|w| {
                                w.retain(|c| !options_wildcard.contains(c));
                            });
                            return Ok(());
                        }
                        InputAction::Purge => {
                            opt.as_ref().borrow_mut().wildcard_denied = None;
                            return Ok(());
                        }
                        _ => unreachable!("Unknown action"),
                    }

                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o path whitelist set a:b:c
            action: InputAction::Set,
            role_id,
            task_id,
            options_path: Some(options_path),
            options_type: Some(OptType::Path),
            setlist_type,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    let mut default_path = SPathOptions::default();
                    let mut binding = opt.as_ref().borrow_mut();
                    let path = binding.path.as_mut().unwrap_or(&mut default_path);
                    match setlist_type {
                        Some(SetListType::WhiteList) => {
                            path.add = options_path.split(':').map(|s| s.to_string()).collect();
                        }
                        Some(SetListType::BlackList) => {
                            path.sub = options_path.split(':').map(|s| s.to_string()).collect();
                        }
                        _ => unreachable!("Unknown setlist type"),
                    }
                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o path whitelist set a:b:c
            action: InputAction::Purge,
            role_id,
            task_id,
            options_path: None,
            options_type: Some(OptType::Path),
            setlist_type,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    let mut default_path = SPathOptions::default();
                    let mut binding = opt.as_ref().borrow_mut();
                    let path = binding.path.as_mut().unwrap_or(&mut default_path);
                    match setlist_type {
                        Some(SetListType::WhiteList) => {
                            path.add.clear();
                        }
                        Some(SetListType::BlackList) => {
                            path.sub.clear();
                        }
                        _ => unreachable!("Unknown setlist type"),
                    }
                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o env whitelist set A,B,C
            action: InputAction::Set,
            role_id,
            task_id,
            options_env: Some(options_env),
            options_type: Some(OptType::Env),
            setlist_type,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    let mut default_env = SEnvOptions::default();
                    let mut binding = opt.as_ref().borrow_mut();
                    let env = binding.env.as_mut().unwrap_or(&mut default_env);
                    match setlist_type {
                        Some(SetListType::WhiteList) => {
                            env.keep = options_env.clone();
                        }
                        Some(SetListType::BlackList) => {
                            env.delete = options_env.clone();
                        }
                        Some(SetListType::CheckList) => {
                            env.check = options_env.clone();
                        }
                        _ => unreachable!("Unknown setlist type"),
                    }
                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o timeout set --type tty --duration 00:00:00 --max-usage 1
            action: InputAction::Del,
            role_id,
            task_id,
            options: true,
            timeout_arg: Some(timeout_arg),
            setlist_type: None,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    let mut timeout = STimeout::default();
                    if timeout_arg[TimeoutOpt::Type as usize] {
                        timeout.type_field = None;
                    }
                    if timeout_arg[TimeoutOpt::Duration as usize] {
                        timeout.duration = None;
                    }
                    if timeout_arg[TimeoutOpt::MaxUsage as usize] {
                        timeout.max_usage = None;
                    }
                    if timeout_arg.iter().all(|b| *b) {
                        opt.as_ref().borrow_mut().timeout = None;
                    } else {
                        opt.as_ref().borrow_mut().timeout = Some(timeout);
                    }
                    
                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o timeout set --type tty --duration 00:00:00 --max-usage 1
            action: InputAction::Set,
            role_id,
            task_id,
            options: true,
            timeout_arg: Some(_),
            timeout_type,
            timeout_duration,
            timeout_max_usage,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    let mut timeout = STimeout::default();
                    if let Some(timeout_type) = timeout_type {
                        timeout.type_field = Some(timeout_type);
                    }
                    if let Some(duration) = timeout_duration {
                        timeout.duration = Some(duration);
                    }
                    if let Some(max_usage) = timeout_max_usage {
                        timeout.max_usage = Some(max_usage);
                    }
                    opt.as_ref().borrow_mut().timeout = Some(timeout);
                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o path whitelist add path1:path2:path3
            action,
            role_id,
            task_id,
            options_path: Some(options_path),
            options_type: Some(OptType::Path),
            setlist_type,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
                    let mut default_path = SPathOptions::default();
                    let mut binding = opt.as_ref().borrow_mut();
                    let path = binding.path.as_mut().unwrap_or(&mut default_path);
                    match setlist_type {
                        Some(SetListType::WhiteList) => match action {
                            InputAction::Add => {
                                path.add
                                    .extend(options_path.split(':').map(|s| s.to_string()));
                            }
                            InputAction::Del => {
                                debug!("path.add del {:?}", path.add);
                                let hashset = options_path
                                    .split(':')
                                    .map(|s| s.to_string())
                                    .collect::<LinkedHashSet<String>>();
                                path.add = path
                                    .add
                                    .difference(&hashset)
                                    .cloned()
                                    .collect::<LinkedHashSet<String>>();
                            }
                            _ => unreachable!("Unknown action"),
                        },
                        Some(SetListType::BlackList) => match action {
                            InputAction::Add => {
                                path.sub
                                    .extend(options_path.split(':').map(|s| s.to_string()));
                            }
                            InputAction::Del => {
                                debug!("path.del del {:?}", path.sub);
                                let hashset = options_path
                                    .split(':')
                                    .map(|s| s.to_string())
                                    .collect::<LinkedHashSet<String>>();
                                path.sub = path
                                    .sub
                                    .difference(&hashset)
                                    .cloned()
                                    .collect::<LinkedHashSet<String>>();
                            }
                            _ => unreachable!("Unknown action"),
                        },
                        _ => unreachable!("Unknown setlist type"),
                    }
                    Ok(())
                })?;
                Ok(true)
            }
        },
        Inputs {
            // chsr o path whitelist add path1:path2:path3
            action,
            role_id,
            task_id,
            options_env,
            options_type: Some(OptType::Env),
            setlist_type: Some(setlist_type),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                perform_on_target_opt(rconfig, role_id, task_id, move |opt: Rc<RefCell<Opt>>| {
                    let mut default_env = SEnvOptions::default();
                    let mut binding = opt.as_ref().borrow_mut();
                    let env = binding.env.as_mut().unwrap_or(&mut default_env);
                    match setlist_type {
                        SetListType::WhiteList => match action {
                            InputAction::Add => {
                                if options_env.is_none() {
                                    return Err("Empty list".into());
                                }
                                env.keep.extend(options_env.as_ref().unwrap().clone());
                            }
                            InputAction::Del => {
                                if options_env.is_none() {
                                    return Err("Empty list".into());
                                }
                                env.keep = env
                                    .keep
                                    .difference(
                                        &options_env
                                            .as_ref()
                                            .unwrap()
                                            .iter()
                                            .cloned()
                                            .collect::<LinkedHashSet<EnvKey>>(),
                                    )
                                    .cloned()
                                    .collect::<LinkedHashSet<EnvKey>>();
                            }
                            InputAction::Purge => {
                                env.keep = LinkedHashSet::new();
                            }
                            _ => unreachable!("Unknown action"),
                        },
                        SetListType::BlackList => match action {
                            InputAction::Add => {
                                if options_env.is_none() {
                                    return Err("Empty list".into());
                                }
                                env.delete.extend(options_env.as_ref().unwrap().clone());
                            }
                            InputAction::Del => {
                                if options_env.is_none() {
                                    return Err("Empty list".into());
                                }
                                env.delete = env
                                    .delete
                                    .difference(options_env.as_ref().unwrap())
                                    .cloned()
                                    .collect::<LinkedHashSet<EnvKey>>();
                            }
                            InputAction::Purge => {
                                env.delete = LinkedHashSet::new();
                            }
                            _ => unreachable!("Unknown action"),
                        },
                        SetListType::CheckList => match action {
                            InputAction::Add => {
                                if options_env.is_none() {
                                    return Err("Empty list".into());
                                }
                                env.check.extend(options_env.as_ref().unwrap().clone());
                            }
                            InputAction::Del => {
                                if options_env.is_none() {
                                    return Err("Empty list".into());
                                }
                                env.check = env
                                    .check
                                    .difference(options_env.as_ref().unwrap())
                                    .cloned()
                                    .collect::<LinkedHashSet<EnvKey>>();
                            }
                            InputAction::Purge => {
                                env.check = LinkedHashSet::new();
                            }
                            _ => unreachable!("Unknown action"),
                        },
                    }
                    Ok(())
                })?;
                Ok(true)
            }
        },
        _ => Err("Unknown action".into()),
    }
}
fn perform_on_target_opt(
    rconfig: &Rc<RefCell<crate::common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    exec_on_opt: impl Fn(Rc<RefCell<Opt>>) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let config = rconfig.as_ref().borrow_mut();
    if let Some(role_id) = role_id {
        if let Some(role) = config.role(&role_id) {
            if let Some(task_id) = task_id {
                if let Some(task) = role.as_ref().borrow().task(&task_id) {
                    if let Some(options) = &task.as_ref().borrow_mut().options {
                        exec_on_opt(options.clone())
                    } else {
                        let options = Rc::new(RefCell::new(Opt::default()));
                        let ret = exec_on_opt(options.clone());
                        task.as_ref().borrow_mut().options = Some(options);
                        ret
                    }
                } else {
                    Err("Task not found".into())
                }
            } else if let Some(options) = &role.as_ref().borrow_mut().options {
                exec_on_opt(options.clone())
            } else {
                let options = Rc::new(RefCell::new(Opt::default()));
                let ret = exec_on_opt(options.clone());
                role.as_ref().borrow_mut().options = Some(options);
                ret
            }
        } else {
            Err("Role not found".into())
        }
    } else {
        return exec_on_opt(config.options.as_ref().unwrap().clone());
    }
}

fn list_json(
    rconfig: &Rc<RefCell<crate::common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    options: bool,
    options_type: Option<OptType>,
    task_type: Option<TaskType>,
    role_type: Option<RoleType>,
) -> Result<(), Box<dyn Error>> {
    let config = rconfig.as_ref().borrow();
    debug!("list_json {:?}", config);
    if let Some(role_id) = role_id {
        if let Some(role) = config.role(&role_id) {
            list_task(task_id, role, options, options_type, task_type, role_type)
        } else {
            Err("Role not found".into())
        }
    } else {
        println!("{}", serde_json::to_string_pretty(config.deref()).unwrap());
        Ok(())
    }
}

fn list_task(
    task_id: Option<IdTask>,
    role: &Rc<RefCell<crate::common::database::structs::SRole>>,
    options: bool,
    options_type: Option<OptType>,
    task_type: Option<TaskType>,
    role_type: Option<RoleType>,
) -> Result<(), Box<dyn Error>> {
    if let Some(task_id) = task_id {
        if let Some(task) = role.as_ref().borrow().task(&task_id) {
            if options {
                let opt = OptStack::from_task(task.clone()).to_opt();
                if let Some(opttype) = options_type {
                    match opttype {
                        OptType::Env => {
                            println!("{}", serde_json::to_string_pretty(&opt.env).unwrap());
                        }
                        OptType::Path => {
                            println!("{}", serde_json::to_string_pretty(&opt.path).unwrap());
                        }
                        OptType::Root => {
                            println!("{}", serde_json::to_string_pretty(&opt.root).unwrap());
                        }
                        OptType::Bounding => {
                            println!("{}", serde_json::to_string_pretty(&opt.bounding).unwrap());
                        }
                        OptType::Wildcard => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&opt.wildcard_denied).unwrap()
                            );
                        }
                        OptType::Timeout => {
                            println!("{}", serde_json::to_string_pretty(&opt.timeout).unwrap());
                        }
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(&opt)?);
                }
            } else {
                print_task(task, task_type.unwrap_or(TaskType::All));
            }
        } else {
            return Err("Task not found".into());
        }
    } else if options {
        println!(
            "{}",
            serde_json::to_string_pretty(&OptStack::from_role(role.clone()).to_opt())?
        );
    } else {
        print_role(role, &role_type.unwrap_or(RoleType::All));
    }
    Ok(())
}

fn print_task(
    task: &std::rc::Rc<std::cell::RefCell<crate::common::database::structs::STask>>,
    task_type: TaskType,
) {
    match task_type {
        TaskType::All => {
            println!("{}", serde_json::to_string_pretty(&task).unwrap());
        }
        TaskType::Commands => {
            println!(
                "{}",
                serde_json::to_string_pretty(&task.as_ref().borrow().commands).unwrap()
            );
        }
        TaskType::Credentials => {
            println!(
                "{}",
                serde_json::to_string_pretty(&task.as_ref().borrow().cred).unwrap()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write, rc::Rc};

    use crate::common::{config, database::{read_json_config, structs::SCredentials}};

    use super::super::common::{
        config::{RemoteStorageSettings, SettingsFile, ROOTASROLE, Storage},
        database::{options::*, structs::*, version::Versioning},
    };

    use super::*;
    use capctl::Cap;
    use chrono::TimeDelta;
    use tracing::error;

    fn make_args(args: &str) -> String {
        shell_words::join(shell_words::split(args).unwrap())
    }

    fn get_inputs(args: &str) -> Inputs {
        let binding = make_args(args);
        println!("{}", binding);
        let args = Cli::parse(Rule::cli, &binding);
        let args = match args {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{RED}{BOLD}Unrecognized command line:\n| {RST}{}{RED}{BOLD}\n| {}\n= {}{RST}",
                    e.line(),
                    underline(&e),
                    e.variant.message(),
                    RED = RED,
                    BOLD = BOLD,
                    RST = RST
                );
                panic!("Error parsing args");
            }
        };
        let mut inputs = Inputs::default();
        for pair in args {
            recurse_pair(pair, &mut inputs);
        }
        inputs
    }

    #[test]
    fn test_grant() {
        let inputs = get_inputs("chsr role r1 grant -u u1 -u u2 -g g1,g2");
        assert_eq!(inputs.role_id, Some("r1".to_string()));
        assert_eq!(inputs.action, InputAction::Add);
        assert_eq!(
            inputs.actors,
            Some(vec![
                SActor::from_user_string("u1"),
                SActor::from_user_string("u2"),
                SActor::from_group_vec_string(vec!["g1", "g2"])
            ])
        );
    }

    #[test]
    fn test_list_roles() {
        let inputs = get_inputs("chsr list");
        assert_eq!(inputs.action, InputAction::List);
    }

    #[test]
    fn test_list_role() {
        let inputs = get_inputs("chsr role r1 show");
        assert_eq!(inputs.action, InputAction::List);
        assert_eq!(inputs.role_id, Some("r1".to_string()));
    }

    #[test]
    fn test_list_role_actors() {
        let inputs = get_inputs("chsr r r1 l actors");
        assert_eq!(inputs.action, InputAction::List);
        assert_eq!(inputs.role_id, Some("r1".to_string()));
        assert_eq!(inputs.role_type, Some(RoleType::Actors));
    }

    #[test]
    fn test_list_role_tasks() {
        let inputs = get_inputs("chsr r r1 l tasks");
        assert_eq!(inputs.action, InputAction::List);
        assert_eq!(inputs.role_id, Some("r1".to_string()));
        assert_eq!(inputs.role_type, Some(RoleType::Tasks));
    }

    #[test]
    fn test_list_role_all() {
        let inputs = get_inputs("chsr r r1 l all");
        assert_eq!(inputs.action, InputAction::List);
        assert_eq!(inputs.role_id, Some("r1".to_string()));
        assert_eq!(inputs.role_type, Some(RoleType::All));
    }


   

    fn setup() {
        //Write json test json file
        let mut file = std::fs::File::create(ROOTASROLE).unwrap();
        let mut settings = SettingsFile::default();
        settings.storage.method = config::StorageMethod::JSON;
        settings.storage.settings = Some(RemoteStorageSettings::default());
        settings.storage.settings.as_mut().unwrap().path = Some(ROOTASROLE.into());
        settings.storage.settings.as_mut().unwrap().immutable = Some(false);

        let mut opt = Opt::default();

        opt.timeout = Some(STimeout::default());
        opt.timeout.as_mut().unwrap().type_field = Some(TimestampType::PPID);
        opt.timeout.as_mut().unwrap().duration = Some(TimeDelta::hours(15)
            .checked_add(&TimeDelta::minutes(30))
            .unwrap()
            .checked_add(&TimeDelta::seconds(30))
            .unwrap());
        opt.timeout.as_mut().unwrap().max_usage = Some(1);

        opt.path = Some(SPathOptions::default());
        opt.path.as_mut().unwrap().default_behavior = PathBehavior::Delete;
        opt.path.as_mut().unwrap().add = vec!["path1".to_string(), "path2".to_string()]
            .into_iter()
            .collect();
        opt.path.as_mut().unwrap().sub = vec!["path3".to_string(), "path4".to_string()]
            .into_iter()
            .collect();

        opt.env = Some(SEnvOptions::default());
        opt.env.as_mut().unwrap().default_behavior = EnvBehavior::Delete;
        opt.env.as_mut().unwrap().keep = vec!["env1".into(), "env2".into()].into_iter().collect();
        opt.env.as_mut().unwrap().check = vec!["env3".into(), "env4".into()].into_iter().collect();
        opt.env.as_mut().unwrap().delete = vec!["env5".into(), "env6".into()].into_iter().collect();

        opt.root = Some(SPrivileged::Privileged);
        opt.bounding = Some(SBounding::Ignore);
        opt.wildcard_denied = Some("*".to_string());

        settings.config.as_ref().borrow_mut().options = Some(rc_refcell!(opt.clone()));

        settings.config.as_ref().borrow_mut().roles = vec![];

        let mut role = SRole::default();
        role.name = "complete".to_string();
        role.actors = vec![
            SActor::from_user_id(0),
            SActor::from_group_id(0),
            SActor::from_group_vec_string(vec!["groupA", "groupB"]),
        ];
        role.options = Some(rc_refcell!(opt.clone()));
        let role = rc_refcell!(role);

        let mut task = STask::new(IdTask::Name("t_complete".to_string()), Rc::downgrade(&role));
        task.purpose = Some("complete".to_string());
        task.commands = SCommands::default();
        task.commands.default_behavior = Some(SetBehavior::All);
        task.commands.add.push(SCommand::Simple("ls".to_string()));
        task.commands.add.push(SCommand::Simple("echo".to_string()));
        task.commands.sub.push(SCommand::Simple("cat".to_string()));
        task.commands.sub.push(SCommand::Simple("grep".to_string()));

        task.cred = SCredentials::default();
        task.cred.setuid = Some(SActorType::Name("user1".to_string()));
        task.cred.setgid = Some(SGroups::Multiple(vec![
            SActorType::Name("group1".to_string()),
            SActorType::Name("group2".to_string()),
        ]));
        task.cred.capabilities = Some(SCapabilities::default());
        task.cred.capabilities.as_mut().unwrap().default_behavior = SetBehavior::All;
        task.cred
            .capabilities
            .as_mut()
            .unwrap()
            .add
            .add(Cap::LINUX_IMMUTABLE);
        task.cred
            .capabilities
            .as_mut()
            .unwrap()
            .add
            .add(Cap::NET_BIND_SERVICE);
        task.cred
            .capabilities
            .as_mut()
            .unwrap()
            .sub
            .add(Cap::SYS_ADMIN);
        task.cred
            .capabilities
            .as_mut()
            .unwrap()
            .sub
            .add(Cap::SYS_BOOT);

        task.options = Some(rc_refcell!(opt.clone()));

        role.as_ref().borrow_mut().tasks.push(rc_refcell!(task));
        settings.config.as_ref().borrow_mut().roles.push(role);

        let versionned = Versioning::new(settings.clone());

        file.write_all(
            serde_json::to_string_pretty(&versionned)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();

        file.flush().unwrap();
    }

    fn teardown() {
        //Remove json test file
        std::fs::remove_file(ROOTASROLE).unwrap();
    }
    // we need to test every commands
    // chsr r r1 create
    // chsr r r1 delete
    // chsr r r1 show (actors|tasks|all)
    // chsr r r1 purge (actors|tasks|all)
    // chsr r r1 grant -u user1 -g group1 group2&group3
    // chsr r r1 revoke -u user1 -g group1 group2&group3
    // chsr r r1 task t1 show (all|cmd|cred)
    // chsr r r1 task t1 purge (all|cmd|cred)
    // chsr r r1 t t1 add
    // chsr r r1 t t1 del
    // chsr r r1 t t1 commands show
    // chsr r r1 t t1 cmd setpolicy (deny-all|allow-all)
    // chsr r r1 t t1 cmd (whitelist|blacklist) (add|del) super command with spaces
    // chsr r r1 t t1 credentials show
    // chsr r r1 t t1 cred (unset|set) --caps capA,capB,capC --setuid user1 --setgid group1,group2
    // chsr r r1 t t1 cred caps setpolicy (deny-all|allow-all)
    // chsr r r1 t t1 cred caps (whitelist|blacklist) (add|del) capA capB capC
    // chsr (r r1) (t t1) options show (all|path|env|root|bounding|wildcard-denied)
    // chsr o path set /usr/bin:/bin this regroups setpolicy delete and whitelist set
    // chsr o path setpolicy (delete-all|keep-all|inherit)
    // chsr o path (whitelist|blacklist) (add|del|set|purge) /usr/bin:/bin

    // chsr o env set MYVAR=1 VAR2=2 //this regroups setpolicy delete and whitelist set
    // chsr o env setpolicy (delete-all|keep-all|inherit)
    // chsr o env (whitelist|blacklist|checklist) (add|del|set|purge) MYVAR=1

    // chsr o root (privileged|user|inherit)
    // chsr o bounding (strict|ignore|inherit)
    // chsr o wildcard-denied (set|add|del) *

    // chsr o timeout set --type tty --duration 5:00 --max_usage 1
    // chsr o t unset --type --duration --max_usage

    //TODO: verify values
    #[test]
    fn test_all_main() {
        setup();
        
        // lets test every commands
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "--help"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "r1", "create"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "r1", "delete"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "show", "actors"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "show", "tasks"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "show", "all"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "purge", "actors"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "purge", "tasks"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "purge", "all"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "grant",
                "-u",
                "user1",
                "-g",
                "group1",
                "-g",
                "group2&group3"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "revoke",
                "-u",
                "user1",
                "-g",
                "group1",
                "-g",
                "group2&group3"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "task", "t_complete", "show", "all"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "task", "t_complete", "show", "cmd"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "task",
                "t_complete",
                "show",
                "cred"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "task",
                "t_complete",
                "purge",
                "all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "task",
                "t_complete",
                "purge",
                "cmd"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "task",
                "t_complete",
                "purge",
                "cred"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "t", "t1", "add"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "t", "t1", "del"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "setpolicy",
                "deny-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "setpolicy",
                "allow-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "whitelist",
                "add",
                "super command with spaces"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "blacklist",
                "add",
                "super",
                "command",
                "with",
                "spaces"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "whitelist",
                "del",
                "super command with spaces"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "blacklist",
                "del",
                "super command with spaces"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        // let settings = config::get_settings().expect("Failed to get settings");
        // assert!(main(
        //     &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
        //     vec!["chsr", "r", "complete", "t", "t_complete", "credentials", "show"],
        // )
        // .inspect_err(|e| {
        //     error!("{}", e);
        // })
        // .inspect(|e| {
        //     debug!("{}",e);
        // })
        // .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "unset",
                "--caps",
                "capA,capB,capC",
                "--setuid",
                "user1",
                "--setgid",
                "group1,group2"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "set",
                "--caps",
                "capA,capB,capC",
                "--setuid",
                "user1",
                "--setgid",
                "group1,group2"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "setpolicy",
                "deny-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "setpolicy",
                "allow-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "whitelist",
                "add",
                "capA",
                "capB",
                "capC"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "blacklist",
                "add",
                "capA",
                "capB",
                "capC"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "whitelist",
                "del",
                "capA",
                "capB",
                "capC"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "blacklist",
                "del",
                "capA",
                "capB",
                "capC"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "options", "show", "all"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "options", "show", "path"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "options", "show", "bounding"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "options",
                "show",
                "env"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "options",
                "show",
                "root"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "options",
                "show",
                "bounding"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "options",
                "show",
                "wildcard-denied"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "set",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "setpolicy",
                "delete-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "setpolicy",
                "keep-unsafe"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "setpolicy",
                "inherit"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "whitelist",
                "add",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "whitelist",
                "del",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "whitelist",
                "set",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "whitelist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "blacklist",
                "add",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "blacklist",
                "del",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "blacklist",
                "set",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "blacklist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "set",
                "MYVAR,VAR2"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "setpolicy",
                "delete-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "setpolicy",
                "keep-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "setpolicy",
                "inherit"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "whitelist",
                "add",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "whitelist",
                "del",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "whitelist",
                "set",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "whitelist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "blacklist",
                "add",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "blacklist",
                "del",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "blacklist",
                "set",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "blacklist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "checklist",
                "add",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "checklist",
                "del",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "checklist",
                "set",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "checklist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "root",
                "privileged"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "root",
                "user"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "root",
                "inherit"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "bounding",
                "strict"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "bounding",
                "ignore"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "bounding",
                "inherit"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "wildcard-denied",
                "set",
                "*"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "wildcard-denied",
                "add",
                "*"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "wildcard-denied",
                "del",
                "*"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "timeout",
                "set",
                "--type",
                "tty",
                "--duration",
                "15:05:10",
                "--max-usage",
                "1"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "timeout",
                "unset",
                "--type",
                "--duration",
                "--max-usage"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "tosk",
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_err());
        teardown();
    }
}
