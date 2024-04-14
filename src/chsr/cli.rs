use std::{cell::RefCell, ops::Deref, process::ExitCode, rc::Rc, str::FromStr, time::Duration};

use capctl::{Cap, CapSet};
use pest::{iterators::Pair, Parser};
use pest_derive::Parser;
use tracing::{debug, error, warn};

use crate::common::{
    config::Storage,
    database::{
        options::{
            EnvBehavior, Level, OptStack, OptType, PathBehavior, SBounding, SPrivileged,
            TimestampType,
        },
        structs::{
            IdTask, SActor, SActorType, SGroups, SetBehavior,
        },
    },
};

#[derive(Parser)]
#[grammar = "chsr/cli.pest"]
struct Cli;

const RAR_SHORT_DESC: &str = "Configure Roles for RootAsRole";
const LONG_ABOUT: &str = "Role Manager is a tool to configure RBAC for RootAsRole.
A role is a set of tasks that can be executed by a user or a group of users.
These tasks are multiple commands associated with their permissions (capabilities).
Like Sudo, you could manipulate environment variables, PATH, and other options.
But Sudo is not designed to use permissions for commands.";

#[derive(Debug)]
enum RoleType {
    All,
    Actors,
    Tasks,
}

#[derive(Debug)]
enum TaskType {
    All,
    Commands,
    Credentials,
}

#[derive(Debug)]
enum InputAction {
    Help,
    List,
    Set,
    Add,
    Del,
    Purge,
}

#[derive(Debug)]
enum SetListType {
    WhiteList,
    BlackList,
    CheckList,
}

#[derive(Debug)]
struct Inputs {
    action: InputAction,
    setlist_type: Option<SetListType>,
    timeout_type: Option<TimestampType>,
    timeout_duration: Option<Duration>,
    timeout_max_usage: Option<u64>,
    role_id: Option<String>,
    role_type: Option<RoleType>,
    actors: Vec<SActor>,
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
    options_env: Option<Vec<(String, String)>>,
    options_env_policy: Option<EnvBehavior>,
    options_root: Option<SPrivileged>,
    options_bounding: Option<SBounding>,
    options_wildcard: Option<String>,
}

impl Default for Inputs {
    fn default() -> Self {
        Inputs {
            action: InputAction::Help,
            setlist_type: None,
            timeout_type: None,
            timeout_duration: None,
            timeout_max_usage: None,
            role_id: None,
            role_type: None,
            actors: Vec::new(),
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
        Rule::add => {
            inputs.action = InputAction::Add;
        }
        Rule::del => {
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
            if pair.as_str() == "deny-all" {
                inputs.cmd_policy = Some(SetBehavior::None);
            } else if pair.as_str() == "allow-all" {
                inputs.cmd_policy = Some(SetBehavior::All);
            } else {
                warn!("Unknown cmd policy: {}", pair.as_str())
            }
        }
        Rule::caps_policy => {
            if pair.as_str() == "deny-all" {
                inputs.cred_policy = Some(SetBehavior::None);
            } else if pair.as_str() == "allow-all" {
                inputs.cred_policy = Some(SetBehavior::All);
            } else {
                warn!("Unknown cmd policy: {}", pair.as_str())
            }
        }
        Rule::path_policy => {
            if pair.as_str() == "delete-all" {
                inputs.options_path_policy = Some(PathBehavior::Delete);
            } else if pair.as_str() == "keep-safe" {
                inputs.options_path_policy = Some(PathBehavior::KeepSafe);
            } else if pair.as_str() == "keep-unsafe" {
                inputs.options_path_policy = Some(PathBehavior::KeepUnsafe);
            } else if pair.as_str() == "inherit" {
                inputs.options_path_policy = Some(PathBehavior::Inherit);
            } else {
                warn!("Unknown path policy: {}", pair.as_str())
            }
        }
        Rule::env_policy => {
            if pair.as_str() == "delete-all" {
                inputs.options_env_policy = Some(EnvBehavior::Delete);
            } else if pair.as_str() == "keep-all" {
                inputs.options_env_policy = Some(EnvBehavior::Keep);
            } else if pair.as_str() == "inherit" {
                inputs.options_env_policy = Some(EnvBehavior::Inherit);
            } else {
                warn!("Unknown env policy: {}", pair.as_str())
            }
        }
        // === timeout ===
        Rule::opt_timeout_d_arg => {
            let mut reversed = pair.as_str().split(':').rev();
            let mut duration: Duration =
                Duration::from_secs(reversed.nth(0).unwrap().parse::<u64>().unwrap());
            if let Some(mins) = reversed.nth(1) {
                duration += Duration::from_secs(mins.parse::<u64>().unwrap() * 60);
            }
            if let Some(hours) = reversed.nth(2) {
                duration += Duration::from_secs(hours.parse::<u64>().unwrap() * 3600);
            }
            inputs.timeout_duration = Some(duration);
        }
        Rule::opt_timeout_t_arg => {
            if pair.as_str() == "tty" {
                inputs.timeout_type = Some(TimestampType::TTY);
            } else if pair.as_str() == "ppid" {
                inputs.timeout_type = Some(TimestampType::PPID);
            } else if pair.as_str() == "uid" {
                inputs.timeout_type = Some(TimestampType::UID);
            } else {
                warn!("Unknown timeout type: {}", pair.as_str())
            }
        }
        Rule::opt_timeout_m_arg => {
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
                warn!("Unknown role type: {}", pair.as_str())
            }
        }
        // === actors ===
        Rule::user => {
            inputs.actors.push(SActor::from_user_string(
                pair.clone().into_inner().nth(0).unwrap().as_str(),
            ));
        }
        Rule::group => {
            inputs.actors.push(SActor::from_group_vec_actors(
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
            } else if pair.as_str() == "commands" || pair.as_str() == "cmds" {
                inputs.task_type = Some(TaskType::Commands);
            } else if pair.as_str().starts_with("cred") {
                inputs.task_type = Some(TaskType::Credentials);
            } else {
                warn!("Unknown role type: {}", pair.as_str())
            }
        }
        // === commands ===
        Rule::cmd => {
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
        Rule::opt_show => {
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
            } else if pair.as_str() == "wildcard" {
                inputs.options_type = Some(OptType::Wildcard);
            } else if pair.as_str() == "timeout" {
                inputs.options_type = Some(OptType::Timeout);
            } else {
                warn!("Unknown option type: {}", pair.as_str())
            }
        }
        Rule::path => {
            inputs.options_path = Some(pair.as_str().to_string());
        }
        Rule::env => {
            if inputs.options_env.is_none() {
                inputs.options_env = Some(Vec::new());
            }
            let mut inner = pair.clone().into_inner();
            let key = inner.nth(0).unwrap().as_str().to_string();
            let value = inner.nth(2).unwrap().as_str().to_string();
            inputs.options_env.as_mut().unwrap().push((key, value));
        }
        Rule::opt_root_args => {
            if pair.as_str() == "privileged" {
                inputs.options_root = Some(SPrivileged::Privileged);
            } else if pair.as_str() == "user" {
                inputs.options_root = Some(SPrivileged::User);
            } else if pair.as_str() == "inherit" {
                inputs.options_root = Some(SPrivileged::Inherit);
            } else {
                warn!("Unknown root type: {}", pair.as_str());
            }
        }
        Rule::opt_bounding_args => {
            if pair.as_str() == "strict" {
                inputs.options_bounding = Some(SBounding::Strict);
            } else if pair.as_str() == "ignore" {
                inputs.options_bounding = Some(SBounding::Ignore);
            } else if pair.as_str() == "inherit" {
                inputs.options_bounding = Some(SBounding::Inherit);
            } else {
                warn!("Unknown bounding type: {}", pair.as_str());
            }
        }
        Rule::wildcard_value => {
            inputs.options_wildcard = Some(pair.as_str().to_string());
        }
        _ => {
            debug!("Unmatched rule: {:?}", pair.as_rule());
        }
    }
}

fn rule_to_string(rule: &Rule) -> String {
    match *rule {
        Rule::EOF => "no more input",
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
        Rule::cmd => "a command line",
        Rule::cred_c => "--caps \"cap_net_raw, cap_sys_admin, ...\"",
        Rule::cred_g => "--group \"g1,g2\"",
        Rule::cred_u => "--user \"u1\"",
        Rule::cred_caps_operations => "caps",
        Rule::EOI => "end of input",
        Rule::cli => "a command line",
        Rule::chsr => unreachable!(),
        Rule::list => todo!(),
        Rule::set => todo!(),
        Rule::add => todo!(),
        Rule::del => todo!(),
        Rule::purge => todo!(),
        Rule::grant => todo!(),
        Rule::revoke => todo!(),
        Rule::setpolicy => todo!(),
        Rule::whitelist => todo!(),
        Rule::blacklist => todo!(),
        Rule::checklist => todo!(),
        Rule::all => todo!(),
        Rule::name => todo!(),
        Rule::opt_timeout => todo!(),
        Rule::opt_timeout_args => todo!(),
        Rule::opt_timeout_type => todo!(),
        Rule::time => todo!(),
        Rule::colon => todo!(),
        Rule::hours => todo!(),
        Rule::minutes => todo!(),
        Rule::seconds => todo!(),
        Rule::opt_timeout_max_usage => todo!(),
        Rule::role => todo!(),
        Rule::role_operations => todo!(),
        Rule::role_id => todo!(),
        Rule::user_or_groups => todo!(),
        Rule::user => todo!(),
        Rule::group => todo!(),
        Rule::name_combination => todo!(),
        Rule::actor_name => todo!(),
        Rule::tasks_operations => todo!(),
        Rule::task_operations => todo!(),
        Rule::task_show_purge => todo!(),
        Rule::task_type_arg => todo!(),
        Rule::task_spec => todo!(),
        Rule::cmd_keyword => todo!(),
        Rule::cmd_setpolicy => todo!(),
        Rule::cred_keyword => todo!(),
        Rule::cred_set_operations => todo!(),
        Rule::cred_set_args => todo!(),
        Rule::capabilities => todo!(),
        Rule::capability => todo!(),
        Rule::caps_setpolicy => todo!(),
        Rule::caps_policy => todo!(),
        Rule::caps_listing => todo!(),
        Rule::options_operations => todo!(),
        Rule::opt_args => todo!(),
        Rule::opt_show => todo!(),
        Rule::opt_show_arg => todo!(),
        Rule::opt_path => todo!(),
        Rule::opt_path_args => todo!(),
        Rule::opt_path_set => todo!(),
        Rule::opt_path_setpolicy => todo!(),
        Rule::path_policy => todo!(),
        Rule::opt_path_listing => todo!(),
        Rule::path => todo!(),
        Rule::opt_env => todo!(),
        Rule::opt_env_args => todo!(),
        Rule::opt_env_setpolicy => todo!(),
        Rule::env_policy => todo!(),
        Rule::opt_env_listing => todo!(),
        Rule::opt_env_set => todo!(),
        Rule::env_list => todo!(),
        Rule::env => todo!(),
        Rule::env_key => todo!(),
        Rule::env_value => todo!(),
        Rule::opt_root => todo!(),
        Rule::opt_root_args => todo!(),
        Rule::opt_bounding => todo!(),
        Rule::opt_bounding_args => todo!(),
        Rule::opt_wildcard => todo!(),
        Rule::opt_wildcard_args => todo!(),
        Rule::wildcard_value => todo!(),
        Rule::assignment => todo!(),
        Rule::help => todo!(),
        Rule::NOT_ESCAPE_QUOTE => todo!(),
        Rule::WHITESPACE => todo!(),
        _ => todo!(),
    }
    .to_string()
}

fn print_role(
    role: &std::rc::Rc<std::cell::RefCell<crate::common::database::structs::SRole>>,
    role_type: &RoleType,
) {
    println!("Role: {}", role.as_ref().borrow().name);
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

pub fn main(storage: &Storage) -> ExitCode {
    let binding = std::env::args().fold("\"".to_string(), |mut s, e| {
        s.push_str(&e);
        s.push_str("\" \"");
        s
    });
    let args = binding.trim_end_matches(" \"");
    let args = Cli::parse(Rule::cli, &args);
    let args = match args {
        Ok(v) => v,
        Err(e) => {
            let e = e.clone().renamed_rules(|rule| rule_to_string(rule));
            println!("{UNDERLINE}{BOLD}Usage:{RST} {BOLD}chsr{RST} [command] [options]

{UNDERLINE}{BOLD}Commands:{RST}
  {BOLD}help, -h, --help{RST}                Show help for commands and options.
  {BOLD}list, show, l{RST}                   List available items; use with specific commands for detailed views.
  {BOLD}role, r{RST}                         Manage roles and related operations.

{UNDERLINE}{BOLD}Role Operations:{RST}
chsr role [role_name] [operation] [options]
  {BOLD}add, create{RST}                   Add a new role.
  {BOLD}del, delete, unset, d, rm{RST}     Delete a specified role.
  {BOLD}show, list, l{RST}                 Show details of a specified role (actors, tasks, all).
  {BOLD}purge{RST}                         Remove all items from a role (actors, tasks, all).
  
  {BOLD}grant{RST}                         Grant permissions to a user or group.
  {BOLD}revoke{RST}                        Revoke permissions from a user or group.
    {BOLD}-u, --user{RST} [user_name]        Specify a user for grant or revoke operations.
    {BOLD}-g, --group{RST} [group_names]     Specify one or more groups for grant or revoke operations.

{UNDERLINE}{BOLD}Task Operations:{RST}
chsr role [role_name] task [task_name] [operation]
  {BOLD}show, list, l{RST}                 Show task details (all, cmd, cred).
  {BOLD}purge{RST}                         Purge configurations or credentials of a task (all, cmd, cred).
  {BOLD}add, create{RST}                   Add a new task.
  {BOLD} del, delete, unset, d, rm{RST}     Remove a task.

{UNDERLINE}{BOLD}Command Operations:{RST}
chsr role [role_name] task [task_name] command [cmd]
  {BOLD}show{RST}                          Show commands.
  {BOLD}setpolicy{RST} [policy]            Set policy for commands (allow-all, deny-all).
  {BOLD}whitelist, wl{RST}                 Manage the whitelist for commands.
  {BOLD}blacklist, bl{RST}                 Manage the blacklist for commands.

{UNDERLINE}{BOLD}Credentials Operations:{RST}
chsr role [role_name] task [task_name] credentials [operation]
  {BOLD}show{RST}                          Show credentials.
  {BOLD}set, unset{RST}                    Set or unset credentials details.
  {BOLD}whitelist, wl{RST}                 Manage whitelist for credentials.
  {BOLD}blacklist, bl{RST}                 Manage blacklist for credentials.

{UNDERLINE}{BOLD}Options:{RST}
chsr options [option] [operation]
chsr role [role_name] options [option] [operation]
chsr role [role_name] task [task_name] options [option] [operation]
  {BOLD}path{RST}                          Manage path settings (set, whitelist, blacklist).
  {BOLD}env{RST}                           Manage environment variable settings (set, whitelist, blacklist, checklist).
  {BOLD}root{RST}                          Set root options (privileged, user, inherit).
  {BOLD}bounding{RST}                      Set bounding options (strict, ignore, inherit).
  {BOLD}wildcard-denied{RST}               Manage settings for denied wildcards (add, set, del).
  {BOLD}timeout{RST}                       Manage timeout settings (set, unset).

Timeout:
  chsr timeout [operation]
  {BOLD}set, unset{RST}                    Set or unset timeout settings.
    {BOLD}--type{RST} [tty, ppid, uid]     Specify the type of timeout.
    {BOLD}--duration{RST} [HH:MM:SS]       Specify the duration of the timeout.
    {BOLD}--max-usage{RST} [number]        Specify the maximum usage of the timeout.

{UNDERLINE}{BOLD}Note: Use '-h' or '--help' with any command to get more detailed help about that specific command.{RST}
", UNDERLINE = "\x1B[4m", BOLD = "\x1B[1m", RST = "\x1B[0m");
            println!("Unrecognized input:\n{}", e.to_string());
            return ExitCode::FAILURE;
        }
    };
    let mut inputs = Inputs::default();
    for pair in args {
        recurse_pair(pair, &mut inputs);
    }

    match inputs {
        Inputs {
            action: InputAction::Help,
            ..
        } => {
            println!("{}", LONG_ABOUT);
            ExitCode::SUCCESS
        }
        Inputs {
            action: InputAction::List,
            options, // show options ?
            role_id,
            role_type,
            task_id,
            task_type,                     // what to show
            options_type,           // in json
            ..
        } => match storage {
            Storage::JSON(rconfig) => list_json(
                rconfig,
                role_id,
                task_id,
                options,
                options_type,
                task_type,
                role_type,
            ),
            _ => {
                error!("Unsupported storage method");
                ExitCode::FAILURE
            }
        },
        Inputs {
            action: InputAction::Set,
            ..
        } => {
            println!("Set");
            ExitCode::SUCCESS
        }
        Inputs {
            action: InputAction::Add,
            ..
        } => {
            println!("Add");
            ExitCode::SUCCESS
        }
        Inputs {
            action: InputAction::Del,
            ..
        } => {
            println!("Del");
            ExitCode::SUCCESS
        }
        Inputs {
            action: InputAction::Purge,
            ..
        } => {
            println!("Purge");
            ExitCode::SUCCESS
        }
        _ => {
            println!("Unknown action");
            ExitCode::SUCCESS
        }
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
) -> ExitCode {
    let config = rconfig.as_ref().borrow();
    if let Some(role_id) = role_id {
        if let Some(role) = config.role(&role_id) {
            list_task(
                task_id,
                role,
                options,
                options_type,
                task_type,
                role_type,
            )
        } else {
            error!("Role not found");
            ExitCode::FAILURE
        }
    } else {
        println!("{}", serde_json::to_string_pretty(config.deref()).unwrap());
        ExitCode::SUCCESS
    }
}

fn list_task(
    task_id: Option<IdTask>,
    role: &Rc<RefCell<crate::common::database::structs::SRole>>,
    options: bool,
    options_type: Option<OptType>,
    task_type: Option<TaskType>,
    role_type: Option<RoleType>,
) -> ExitCode {
    if let Some(task_id) = task_id {
        if let Some(task) = role.as_ref().borrow().task(&task_id) {
            if options {
                let stack = OptStack::from_task(task.clone());
                if let Some(opttype) = options_type {
                    println!("{}", stack.get_description(Level::Task, opttype));
                } else {
                    println!("{}", stack);
                }
            } else {
                print_task(
                    task,
                    task_type.unwrap_or(TaskType::All),
                );
            }
            ExitCode::SUCCESS
        } else {
            error!("Task not found");
            ExitCode::FAILURE
        }
    } else {
        if options {
            println!("{}", OptStack::from_role(role.clone()));
        } else {
            print_role(
                &role,
                &role_type.unwrap_or(RoleType::All),
            );
        }
        ExitCode::SUCCESS
    }
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

// Generate tests for all test cases in tests/pest/foo/ and all subdirectories. Since
// `lazy_static = true`, a single `PestTester` is created and used by all tests; otherwise a new
// `PestTester` would be created for each test.

#[cfg(test)]
mod cli_tests {
    use pest_test_gen::pest_tests;
    #[pest_tests(
        super::super::Cli,
        super::super::Rule,
        "cli",
        subdir = "chsr",
        recursive = true
    )]
    mod grammar_tests {}
}
