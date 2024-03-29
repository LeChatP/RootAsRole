use std::error::Error;
use clap::{Parser, Subcommand, ValueEnum};

use crate::rolemanager::RoleContext;

//chsr newrole "role1" --user "user1" --group "group1" "group2"
//chsr addtask "role1" --cmds "command1" --caps "cap_dac_override,cap_dac_read_search"
//chsr addtask "role1" --with-id "myid" --cmds "command2" --caps "cap_dac_override"

//chsr deltask "role1" "myid"

//chsr grant "role1" --user "user1" --group "group1,group2"
//chsr revoke "role1" --user "user1"

//chsr delrole "role1"

//chsr config --role "role1" --task "myid" --path "/usr/bin:/bin"
//chsr config --role "role1" --env "MYVAR=1"
//chsr config --allow-bounding false

#[derive(Parser, Debug)]
#[command(
    about = "Configure Roles for RootAsRole",
    long_about = "Role Manager is a tool to configure RBAC for RootAsRole.
A role is a set of tasks that can be executed by a user or a group of users.
These tasks are multiple commands associated with their permissions (capabilities).
Like Sudo, you could manipulate environment variables, PATH, and other options.
But Sudo is not designed to use permissions for commands."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CCommand>,
}

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)] // ArgEnum here
#[clap(rename_all = "kebab_case")]
enum Action {
    Add,
    Del,
    Purge,
    Set,
    List,
}

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)] // ArgEnum here
#[clap(rename_all = "kebab_case")]
enum Manage {
    Grant,
    Revoke,
    Purge,
    Set,
    List,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum CCommand {
    /// Manipulate role, you can add users, groups, tasks. You can assign tasks through the command "addtask"
    #[command(name = "role")]
    Role {
        /// WARNING! Purge == remove all roles on the config
        #[arg(value_enum)]
        action: Action,
        /// Always Confirm dangerous action if set
        #[arg(short)]
        yes: bool,

        /// Role name
        role: String,
        /// Add users to role, multiple users can be added by multiple -u
        #[arg(short, long)]
        user: Option<Vec<String>>,
        /// Add groups to role, multiple groups can be added by multiple -g,
        /// Group combinaison can be done by separating groups with a comma,
        /// Example: -g group1 -g group2,group3
        #[arg(short, long)]
        group: Option<Vec<String>>,
    },

    /// Manipulate users assigned to roles
    #[command(name = "actors")]
    Actors {
        /// Purge == remove all users and groups from role
        #[arg(value_enum)]
        action: Manage,
        /// Always Confirm dangerous action if set
        #[arg(short)]
        yes: bool,

        /// Role name
        role: String,
        /// Add users to role, multiple users can be added by multiple -u
        #[arg(short, long)]
        user: Option<Vec<String>>,
        /// Add groups to role, multiple groups can be added by multiple -g,
        /// Group combinaison can be done by separating groups with a comma,
        /// Example: -g group1 -g group2,group3
        #[arg(short, long)]
        group: Option<Vec<String>>,
    },

    /// Add a task to a role, you can add commands and capabilities
    #[command(name = "task")]
    Task {
        /// WARNING! Purge == remove all tasks from role
        #[arg(value_enum)]
        action: Action,
        /// Always Confirm dangerous action if set
        #[arg(short)]
        yes: bool,

        role: String,
        #[arg(short = 't', long)]
        id: Option<String>,
    },
    /// Perform action on command entries to a task
    #[command(name = "cmd")]
    Cmd {
        /// WARNING! Purge == remove all commands from task, and set all_cmd to false
        #[arg(value_enum)]
        action: Action,
        /// Always Confirm dangerous action if set
        #[arg(short)]
        yes: bool,

        role: String,
        task_id: String,
        /// If set, all commands are allowed. This option is exclusive with whitelist
        #[arg(short, long)]
        all_cmd: bool,
        /// append whitelisted commands
        #[arg(short, long)]
        whitelist: Option<Vec<String>>,
        /// append blacklisted commands
        #[arg(short, long)]
        blacklist: Option<Vec<String>>,
    },

    #[command(name = "cred")]
    Cred {
        /// Purge == remove all credentials from task, the task will be executable as executor user without privileges.
        #[arg(value_enum)]
        action: Action,
        /// Always Confirm dangerous action if set
        #[arg(short)]
        yes: bool,

        role: String,
        task_id: String,
        /// Set capabilities to task
        /// Format: cap1 cap2 cap3
        /// Or : all- cap1 cap2
        #[arg(short, long)]
        caps: Option<String>,
        /// Setuid applied to task
        #[arg(short, long)]
        setuid: Option<String>,
        /// Setgid applied to task
        #[arg(short, long)]
        setgid: Option<String>,
    },
    #[command(name = "config")]
    Config {
        /// WARNING! Purge == purges global, role or task config considering the options you set
        #[arg(value_enum)]
        action: Action,
        /// Always Confirm dangerous action if set
        #[arg(short)]
        yes: bool,
        #[arg(short, long)]
        /// Role name
        role: Option<String>,
        #[arg(short, long)]
        /// Task id or index in the list
        task: Option<String>,
        /// Set PATH environment variable
        #[arg(long)]
        path: Option<String>,
        /// Keep environment variables without changing them
        #[arg(long)]
        env_keep: Option<String>,
        /// Keep environment variables if they are valid
        #[arg(long)]
        env_check: Option<String>,
        /// When false, capabilties are permanently dropped, when true, process can regain them (with sudo as example)
        #[arg(long)]
        allow_bounding: Option<bool>,
        /// When false, root is disabled, when true, root is enabled
        #[arg(long)]
        allow_root: Option<bool>,
        /// When you configure command with wildcard, you can except chars of wildcard match
        #[arg(long)]
        wildcard_denied: Option<String>,
    },
    /// NOT IMPLEMENTED: Import sudoers file
    Import {
        /// Import sudoers file as RootAsRole roles
        file: String,
    },
}

fn perform_option_command(
    manager: &mut RoleContext,
    action: Action,
    opttype: OptType,
    value: OptValue,
) {
    match action {
        Action::Add => {
            let mut optvalue = manager.get_options().get_from_type(opttype);
            match value {
                OptValue::String(s) => {
                    optvalue.1.as_string().push_str(&s);
                }
                OptValue::VecString(v) => {
                    optvalue.1.as_vec_string().extend(v.0);
                }
                OptValue::Bool(b) => {
                    optvalue.1 = OptValue::Bool(value.as_bool());
                }
            }
            manager.get_options().set_value(opttype, Some(optvalue.1));
        }
        Action::Del => {
            let mut optvalue = manager.get_options().get_from_type(opttype);
            match value {
                OptValue::String(s) => {
                    optvalue.1 = OptValue::String(optvalue.1.as_string().replace(&s, ""));
                }
                OptValue::VecString(v) => {
                    optvalue.1.as_vec_string().retain(|x| !v.0.contains(x));
                }
                OptValue::Bool(b) => {
                    manager.get_options().set_value(opttype, None);
                    return;
                }
            }
            manager.get_options().set_value(opttype, Some(optvalue.1));
        }
        Action::Purge => {
            manager.get_options().unset_value(opttype);
        }
        Action::Set => {
            manager.get_options().set_value(opttype, Some(value));
        }
        Action::List => {
            let paths = manager.get_options().get_from_type(opttype);
            match paths.1 {
                OptValue::String(s) => {
                    println!("{} = {}", opttype, s);
                }
                OptValue::VecString(v) => {
                    println!("{} = {}", opttype, v.0.join(&v.1));
                }
                OptValue::Bool(b) => {
                    println!("{} = {}", opttype, b);
                }
            }
        }
    }
}

/**
 * Parse the command line arguments
 */
pub fn parse_args(manager: &mut RoleContext) -> Result<bool, Box<dyn Error>> {
    let args = Cli::parse();
    match args.command.as_ref() {
        Some(CCommand::Role {
            action,
            yes,
            role,
            user,
            group,
        }) => {
            Ok(true)
        }
        Some(CCommand::Actors {
            action,
            yes,
            role,
            user,
            group,
        }) => {
            Ok(true)
        }
        Some(CCommand::Task {
            action,
            yes,
            role,
            id,
        }) => {
            Ok(true)
        }
        Some(CCommand::Cmd {
            action,
            yes,
            role,
            task_id,
            all_cmd,
            whitelist,
            blacklist,
        }) => {
            Ok(true)
        }
        Some(CCommand::Cred {
            action,
            yes,
            role,
            task_id,
            caps,
            setuid,
            setgid,
        }) => {
            Ok(true)
        }

        Some(CCommand::Config {
            action,
            yes,
            role,
            task,
            path,
            env_keep,
            env_check,
            allow_bounding,
            allow_root,
            wildcard_denied,
        }) => {
            if let Some(role) = role.as_ref() {
                manager.select_role_by_name(role)?;
            }
            if let Some(task) = task {
                let tid = match task.parse::<usize>() {
                    Ok(id) => IdTask::Number(id),
                    Err(_) => IdTask::Name(task.to_string()),
                };
                manager.select_task_by_id(&tid)?;
            }
            if let Some(path) = path {
                perform_option_command(
                    manager,
                    action.to_owned(),
                    OptType::Path,
                    OptValue::from_str_vec(OptType::Path, path.to_string()),
                );
            }
            if let Some(env_keep) = env_keep {
                perform_option_command(
                    manager,
                    action.to_owned(),
                    OptType::EnvWhitelist,
                    OptValue::from_str_vec(OptType::EnvWhitelist, env_keep.to_string()),
                );
            }
            if let Some(env_check) = env_check {
                perform_option_command(
                    manager,
                    action.to_owned(),
                    OptType::EnvChecklist,
                    OptValue::from_str_vec(OptType::EnvChecklist, env_check.to_string()),
                );
            }
            if let Some(allow_bounding) = allow_bounding {
                perform_option_command(
                    manager,
                    action.to_owned(),
                    OptType::Bounding,
                    OptValue::Bool(allow_bounding.to_owned()),
                );
            }
            if let Some(allow_root) = allow_root {
                perform_option_command(
                    manager,
                    action.to_owned(),
                    OptType::NoRoot,
                    OptValue::Bool(allow_root.to_owned()),
                );
            }
            if let Some(wildcard_denied) = wildcard_denied {
                perform_option_command(
                    manager,
                    action.to_owned(),
                    OptType::Wildcard,
                    OptValue::String(wildcard_denied.to_owned()),
                );
            }
            save_config(&manager.get_config().as_ref().borrow())?;
            Ok(true)
        }
        Some(CCommand::Import { file: _ }) => Err("not implemented".into()),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
}
