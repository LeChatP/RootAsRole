use clap::{Parser,Subcommand, Args};

use crate::version::PACKAGE_VERSION;

//rar roles add "role1"
//rar role role1 add user "user1"
//rar role role1 add group "group1" "group2"
//rar role role1 add commands with id "myid" "command1" "command2"
//rar role role1 add commands "command3" "command4"
//rar role role1 commands "myid" set capabilties "cap_dac_override,cap_sys_admin"
//rar role role1 set options 
//rar role role1 remove user "user1"
//rar role role1 remove group "group1" "group2"
//rar role role1 remove commands with id "myid"

//rar newrole --name "role1" --user "user1" --group "group1" "group2" --task --cmds "command1" "command2" --task --with-id "myid" --cmds "command3" "command4" --perm "cap_dac_override,cap_sys_admin"
//rar newrole "role2" --user "user2" --group "group1" "group2,group3" --task --cmds "command5" "command6" --caps "cap_dac_override,cap_dac_read_search" --task --with-id "myid2" --cmds "command7" "command8" --perm "cap_dac_override,cap_sys_admin"

//rar editrole "role1" --add-user "user2" --delgroup "group1" --deltask 1 

//rar delrole "role1"

#[derive(Parser, Debug)]
#[command(name = "RootAsRole")]
#[command(author = "Eddie B. <eddie.billoir@irit.fr>")]
#[command(version = PACKAGE_VERSION)]
#[command(about = "Configure Roles for RootAsRole", long_about = "Role Manager is a tool to configure RBAC for RootAsRole.
A role is a set of tasks that can be executed by a user or a group of users.
These tasks are multiple commands associated with their permissions (capabilities).
Like Sudo, you could manipulate environment variables, PATH, and other options.
But Sudo is not designed to use permissions for commands.
")]
struct Cli {
    #[command(subcommand)]
    command: Option<CCommand>,
}

#[derive(Subcommand, Debug)]
enum CCommand {
    /// List all roles
    #[command(name = "list")]
    List {
        /// Describe role
        role: Option<String>,
        /// Describe task within role
        task: Option<String>,
    },
    /// Create a new role, you can add users, groups, tasks. Tasks are commands with capabilities, use config to configure options of this new role.
    #[command(name = "newrole")]
    NewRole {
        role: String,
        #[arg(short, long)]
        user: Option<Vec<String>>,
        #[arg(short, long)]
        group: Option<Vec<String>>,
        #[command(flatten)]
        task: Task,
    },
    /// Edit a role, you can add or remove users, groups, tasks, commands, capabilities, options
    #[command(name = "editrole")]
    EditRole {
        role: String,
        #[arg(short, long)]
        add_user: Option<Vec<String>>,
        #[arg(short, long)]
        del_user: Option<Vec<String>>,
        #[arg(short, long)]
        add_group: Option<Vec<String>>,
        #[arg(short, long)]
        del_group: Option<Vec<String>>,
        #[command(flatten)]
        add_task: Task,
        #[arg(short, long)]
        del_task: Option<Vec<String>>, // task id, or index in the list

        #[command(flatten)]
        add_cmds: AddCmd,
        #[command(flatten)]
        del_cmds: DelCmd,

        #[command(flatten)]
        add_caps: AddCaps,
        #[command(flatten)]
        del_caps: DelCaps,

        #[command(flatten)]
        add_options: AddExecParams,
        #[command(flatten)]
        del_options: DelExecParams,

    },
    /// Delete a role, this is not reversible
    #[command(name = "delrole")]
    DelRole {
        role: String,
    },
    /// You could configure options for all roles, specific role, or specific task
    #[command(name = "config")]
    Config {
        /// Role name
        role: Option<String>,
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
        allow_bounding: Option<String>,
        /// When you configure command with wildcard, you can except chars of wildcard match
        #[arg(long)]
        wildcard_denied: Option<String>,
    },
    Import {
        /// Import sudoers file as RootAsRole roles
        file: String,
    },
}


#[derive(Args, Debug)]
#[group(required = false, multiple = true)]
struct Task {
    /// Task number or id
    task: Option<String>,

    /// Set/Add capabilities to the task (separeted by comma, could be empty)
    caps: Option<String>,

    /// Set/Add commands to the task
    cmds: Vec<String>,
}

#[derive(Args, Debug)]
#[group(required = false, multiple = true)]
struct AddCmd {
    #[arg(short, long)]
    id: String,
    #[arg(short, long)]
    cmds: Vec<String>,
}

#[derive(Args, Debug)]
#[group(required = false, multiple = true)]
struct DelCmd {
    #[arg(short, long)]
    id: String,
    #[arg(short, long)]
    cmds: Vec<String>,
}

#[derive(Args, Debug)]
#[group(required = false, multiple = true)]
struct AddCaps {
    #[arg(short, long)]
    id: String,
    #[arg(short, long)]
    caps: String,
}

#[derive(Args, Debug)]
#[group(required = false, multiple = true)]
struct DelCaps {
    #[arg(short, long)]
    id: String,
    #[arg(short, long)]
    caps: String,
}

#[derive(Args, Debug)]
#[group(required = false, multiple = true)]
struct AddExecParams {
    #[arg(short, long)]
    id: String,
    #[arg(short, long)]
    options: String,
}

#[derive(Args, Debug)]
#[group(required = false, multiple = true)]
struct DelExecParams {
    #[arg(short, long)]
    id: String,
    #[arg(short, long)]
    options: String,
}

/**
 * Parse the command line arguments
 */
pub fn parse_args(){
    let args = Cli::parse();
    match args.command {
        Some(CCommand::NewRole{role, user, group, task}) => {
            println!("new role: {}", role);
            println!("user: {:?}", user);
            println!("group: {:?}", group);
            println!("task: {:?}", task);
        },
        Some(CCommand::EditRole{role, add_user, del_user, add_group, del_group, add_task, del_task, add_cmds, del_cmds, add_caps, del_caps, add_options, del_options}) => {
            println!("edit role: {}", role);
            println!("add user: {:?}", add_user);
            println!("del user: {:?}", del_user);
            println!("add group: {:?}", add_group);
            println!("del group: {:?}", del_group);
            println!("add task: {:?}", add_task);
            println!("del task: {:?}", del_task);
            println!("add cmds: {:?}", add_cmds);
            println!("del cmds: {:?}", del_cmds);
            println!("add caps: {:?}", add_caps);
            println!("del caps: {:?}", del_caps);
            println!("add options: {:?}", add_options);
            println!("del options: {:?}", del_options);
        },
        Some(CCommand::DelRole{role}) => {
            println!("del role: {}", role);
        },
        Some(CCommand::Config{role, task, path, env_keep, env_check, allow_bounding, wildcard_denied}) => {
            println!("config role: {:?}", role);
            println!("config task: {:?}", task);
            println!("config path: {:?}", path);
            println!("config env_keep: {:?}", env_keep);
            println!("config env_check: {:?}", env_check);
            println!("config allow_bounding: {:?}", allow_bounding);
            println!("config wildcard_denied: {:?}", wildcard_denied);
        },
        Some(CCommand::List{role,task}) => {
            println!("config role: {:?}", role);
            println!("config task: {:?}", task);
        },
        Some(CCommand::Import{file}) => {
            println!("import file: {:?}", file);
        },
        None => {
            println!("no command");
        }
    }
}

