use std::error::Error;

use const_format::formatcp;
use tracing::debug;

use super::data::Rule;
use crate::util::underline;
use rar_common::util::{BOLD, RED, RST, UNDERLINE};

const LONG_ABOUT: &str = "Role Manager is a tool to configure RBAC for RootAsRole.
A role is a set of tasks that can be executed by a user or a group of users.
These tasks are multiple commands associated with their granted permissions (credentials).
Like Sudo, you could manipulate environment variables, PATH, and other options.
More than Sudo, you can manage the capabilities and remove privileges from the root user.";

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

pub fn help() -> Result<bool, Box<dyn Error>> {
    debug!("chsr help");
    println!("{}", LONG_ABOUT);
    println!("{}", RAR_USAGE_GENERAL);
    Ok(false)
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
        Rule::cmd => "a command line",
        Rule::cred_c => "--caps \"cap_net_raw, cap_sys_admin, ...\"",
        Rule::cred_g => "--group \"g1,g2\"",
        Rule::cred_u => "--user \"u1\"",
        Rule::cred_caps_operations => "caps",
        Rule::cli => "a command line",
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

fn usage_concat(usages: &[&'static str]) -> String {
    let mut usage = String::new();
    for u in usages {
        usage.push_str(u);
    }
    usage
}

pub fn print_usage(e: pest::error::Error<Rule>) -> Result<bool, Box<dyn Error>> {
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
            | Rule::env_key_list
            | Rule::env_value_list
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
    Err(Box::new(e))
}
