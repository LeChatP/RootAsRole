use clap::{Args, Parser, Subcommand};

use crate::version::PACKAGE_VERSION;

//rar newrole "role1" --user "user1" --group "group1" "group2"
//rar addtask "role1" --cmds "command1" --caps "cap_dac_override,cap_dac_read_search"
//rar addtask "role1" --with-id "myid" --cmds "command2" --caps "cap_dac_override"

//rar deltask "role1" "myid"

//rar grant "role1" --user "user1" --group "group1,group2"
//rar revoke "role1" --user "user1"

//rar delrole "role1"

//rar config --role "role1" --task "myid" --path "/usr/bin:/bin"
//rar config --role "role1" --env "MYVAR=1"
//rar config --allow-bounding false

#[derive(Parser, Debug)]
#[command(name = "RootAsRole")]
#[command(author = "Eddie B. <eddie.billoir@irit.fr>")]
#[command(version = PACKAGE_VERSION)]
#[command(
    about = "Configure Roles for RootAsRole",
    long_about = "Role Manager is a tool to configure RBAC for RootAsRole.
A role is a set of tasks that can be executed by a user or a group of users.
These tasks are multiple commands associated with their permissions (capabilities).
Like Sudo, you could manipulate environment variables, PATH, and other options.
But Sudo is not designed to use permissions for commands.
"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CCommand>,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
enum CCommand {
    /// List all roles
    #[command(name = "list")]
    List {
        #[arg(short, long)]
        /// Describe role
        role: Option<String>,
        #[arg(short, long)]
        /// Describe task within role
        task: Option<String>,
    },
    /// Create a new role, you can add users, groups, tasks. You can assign tasks through the command "addtask"
    #[command(name = "newrole")]
    NewRole {
        role: String,
        #[arg(short, long)]
        user: Option<Vec<String>>,
        #[arg(short, long)]
        group: Option<Vec<String>>,
    },
    /// You can grant users/groups to role
    #[command(name = "grant")]
    Grant {
        role: String,
        #[arg(short, long)]
        user: Option<Vec<String>>,
        #[arg(short, long)]
        group: Option<Vec<String>>,
    },
    /// You can revoke users/groups from role
    #[command(name = "revoke")]
    Revoke {
        role: String,
        #[arg(short, long)]
        user: Option<Vec<String>>,
        #[arg(short, long)]
        group: Option<Vec<String>>,
    },
    /// Add a task to a role, you can add commands and capabilities
    #[command(name = "addtask")]
    AddTask {
        role: String,
        #[arg(short, long)]
        withid: Option<String>,
        #[arg(short, long)]
        cmds: Option<Vec<String>>,
        #[arg(short = 'p', long)]
        caps: Option<String>,
    },
    /// Delete a task from a role
    #[command(name = "deltask")]
    DelTask { role: String, id: String },
    /// Delete a role, this is not reversible
    #[command(name = "delrole")]
    DelRole { role: String },
    /// You could configure options for all roles, specific role, or specific task
    #[command(name = "config")]
    Config {
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
        /// When you configure command with wildcard, you can except chars of wildcard match
        #[arg(long)]
        wildcard_denied: Option<bool>,
    },
    Import {
        /// Import sudoers file as RootAsRole roles
        file: String,
    },
}

/**
 * Parse the command line arguments
 */
pub fn parse_args() {
    let args = Cli::parse();
    match args.command.as_ref() {
        Some(CCommand::NewRole { role, user, group }) => {
            println!("new role: {}", role);
            println!("new user: {:?}", user);
            println!("new group: {:?}", group);
        }
        Some(CCommand::Grant { role, user, group }) => {
            println!("grant role: {}", role);
            println!("grant user: {:?}", user);
            println!("grant group: {:?}", group);
        }
        Some(CCommand::Revoke { role, user, group }) => {
            println!("revoke role: {}", role);
            println!("revoke user: {:?}", user);
            println!("revoke group: {:?}", group);
        }
        Some(CCommand::AddTask {
            role,
            withid,
            cmds,
            caps,
        }) => {
            println!("add task: {}", role);
            println!("add withid: {:?}", withid);
            println!("add cmds: {:?}", cmds);
            println!("add caps: {:?}", caps);
        }
        Some(CCommand::DelTask { role, id }) => {
            println!("del task: {}", role);
            println!("del id: {:?}", id);
        }
        Some(CCommand::DelRole { role }) => {
            println!("del role: {}", role);
        }
        Some(CCommand::Config {
            role,
            task,
            path,
            env_keep,
            env_check,
            allow_bounding,
            wildcard_denied,
        }) => {
            println!("config role: {:?}", role);
            println!("config task: {:?}", task);
            println!("config path: {:?}", path);
            println!("config env_keep: {:?}", env_keep);
            println!("config env_check: {:?}", env_check);
            println!("config allow_bounding: {:?}", allow_bounding);
            println!("config wildcard_denied: {:?}", wildcard_denied);
        }
        Some(CCommand::List { role, task }) => {
            println!("config role: {:?}", role);
            println!("config task: {:?}", task);
        }
        Some(CCommand::Import { file }) => {
            println!("import file: {:?}", file);
        }
        None => {
            println!("no command");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_args_new_role() {
        let args = Cli::parse_from(&[
            "rar", "newrole", "admin", "--user", "user1", "--group", "group1",
        ])
        .command;
        let expected_command = Some(CCommand::NewRole {
            role: "admin".to_string(),
            user: Some(["user1".to_string()].to_vec()),
            group: Some(["group1".to_string()].to_vec()),
        });
        assert_eq!(args, expected_command);
    }

    #[test]
    fn test_parse_args_grant() {
        let args = Cli::parse_from(&[
            "rar", "grant", "admin", "--user", "user1", "--group", "group1",
        ])
        .command;
        let expected_command = Some(CCommand::Grant {
            role: "admin".to_string(),
            user: Some(["user1".to_string()].to_vec()),
            group: Some(["group1".to_string()].to_vec()),
        });
        assert_eq!(args, expected_command);
    }

    #[test]
    fn test_parse_args_revoke() {
        let args = Cli::parse_from(&[
            "rar", "revoke", "admin", "--user", "user1", "--group", "group1",
        ])
        .command;
        let expected_command = Some(CCommand::Revoke {
            role: "admin".to_string(),
            user: Some(["user1".to_string()].to_vec()),
            group: Some(["group1".to_string()].to_vec()),
        });
        assert_eq!(args, expected_command);
    }

    #[test]
    fn test_parse_args_add_task() {
        let args = Cli::parse_from(&[
            "rar", "addtask", "admin", "--withid", "task1", "--cmds", "cmd1", "--caps", "cap1",
        ])
        .command;
        let expected_command = Some(CCommand::AddTask {
            role: "admin".to_string(),
            withid: Some("task1".to_string()),
            cmds: Some(["cmd1".to_string()].to_vec()),
            caps: Some("cap1".to_string()),
        });
        assert_eq!(args, expected_command);
    }

    #[test]
    fn test_parse_args_del_task() {
        let args = Cli::parse_from(&["rar", "deltask", "admin", "task1"]).command;
        let expected_command = Some(CCommand::DelTask {
            role: "admin".to_string(),
            id: "task1".to_string(),
        });
        assert_eq!(args, expected_command);
    }

    #[test]
    fn test_parse_args_del_role() {
        let args = Cli::parse_from(&["rar", "delrole", "admin"]).command;
        let expected_command = Some(CCommand::DelRole {
            role: "admin".to_string(),
        });
        assert_eq!(args, expected_command);
    }

    #[test]
    fn test_parse_args_config() {
        let args = Cli::parse_from(&[
            "rar",
            "config",
            "--role",
            "admin",
            "--task",
            "task1",
            "--path",
            "/path/to/file",
            "--env-keep",
            "env1",
            "--env-check",
            "env2",
            "--allow-bounding",
            "true",
            "--wildcard-denied",
            "false",
        ])
        .command;
        let expected_command = Some(CCommand::Config {
            role: Some("admin".to_string()),
            task: Some("task1".to_string()),
            path: Some("/path/to/file".to_string()),
            env_keep: Some("env1".to_string()),
            env_check: Some("env2".to_string()),
            allow_bounding: Some(true),
            wildcard_denied: Some(false),
        });
        assert_eq!(args, expected_command);
    }

    #[test]
    fn test_parse_args_list() {
        let args = Cli::parse_from(&["rar", "list", "--role", "admin", "--task", "task1"]).command;
        let expected_command = Some(CCommand::List {
            role: Some("admin".to_string()),
            task: Some("task1".to_string()),
        });
        assert_eq!(args, expected_command);
    }

    #[test]
    fn test_parse_args_import() {
        let args = Cli::parse_from(&["rar", "import", "/path/to/file"]).command;
        let expected_command = Some(CCommand::Import {
            file: "/path/to/file".to_string(),
        });
        assert_eq!(args, expected_command);
    }

    #[test]
    fn test_parse_args_no_command() {
        let args = Cli::parse_from(&["rar"]).command;
        let expected_command = None;
        assert_eq!(args, expected_command);
    }
}
