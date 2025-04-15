pub mod pam;
mod timeout;
mod finder;

use capctl::CapState;
use const_format::formatcp;
use finder::BestExecSettings;
use nix::{
    libc::dev_t,
    sys::stat,
    unistd::{getgroups, getuid, isatty, Group, User},
};
use rar_common::{database::{
    actor::{SGroupType, SGroups, SUserType},
    finder::Cred,
    options::EnvBehavior,
    FilterMatcher,
}, util::final_path};
use rar_common::util::escape_parser_string;

use log::{debug, error};
use pam::PAM_PROMPT;
use pty_process::blocking::{Command, Pty};
use std::{error::Error, io::stdout, os::fd::AsRawFd, path::PathBuf};

use rar_common::
    util::{
        activates_no_new_privs, drop_effective, setgid_effective, setpcap_effective, setuid_effective, subsribe, BOLD, RST, UNDERLINE,
    }
;

#[cfg(not(test))]
const ROOTASROLE: &str = env!("RAR_CFG_PATH");
#[cfg(test)]
const ROOTASROLE: &str = "target/rootasrole.json";

//const ABOUT: &str = "Execute privileged commands with a role-based access control system";
//const LONG_ABOUT: &str =
//    "sr is a tool to execute privileged commands with a role-based access control system.
//It is designed to be used in a multi-user environment,
//where users can be assigned to different roles,
//and each role has a set of rights to execute commands.";

const USAGE: &str = formatcp!(
    r#"{UNDERLINE}{BOLD}Usage:{RST} {BOLD}sr{RST} [OPTIONS] [COMMAND]...

{UNDERLINE}{BOLD}Arguments:{RST}
  [COMMAND]...
          Command to execute

{UNDERLINE}{BOLD}Options:{RST}
  {BOLD}-r, --role <ROLE>{RST}
          Role option allows you to select a specific role to use

  {BOLD}-t, --task <TASK>{RST}
          Task option allows you to select a specific task to use in the selected role. Note: You must specify a role to designate a task

  {BOLD}-E, --preserve-env <TASK>{RST}
          Preserve environment variables if allowed by a matching task

  {BOLD}-p, --prompt <PROMPT>{RST}
          Prompt option allows you to override the default password prompt and use a custom one
          
          [default: "Password: "]

  {BOLD}-u, --user <USER>{RST}
          Specify the user to execute the command as
  {BOLD} -g --group <GROUP>{RST}
          Specify the group to execute the command as

  {BOLD}-i, --info{RST}
          Display rights of executor

  {BOLD}-h, --help{RST}
          Print help (see a summary with '-h')"#,
    UNDERLINE = UNDERLINE,
    BOLD = BOLD,
    RST = RST
);

#[derive(Debug)]
struct Cli {
    /// Role option allows you to select a specific role to use.
    opt_filter: Option<FilterMatcher>,

    /// Prompt option allows you to override the default password prompt and use a custom one.
    prompt: String,

    /// Display rights of executor
    info: bool,

    /// Display help
    help: bool,

    /// Command to execute
    cmd_path: PathBuf,

    /// Command arguments
    cmd_args: Vec<String>,

    /// Use stdin for password prompt
    stdin: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Cli {
            opt_filter: None,
            prompt: PAM_PROMPT.to_string(),
            info: false,
            help: false,
            stdin: false,
            cmd_path: PathBuf::new(),
            cmd_args: Vec::new(),
        }
    }
}

const CAPABILITIES_ERROR: &str =
    "You need at least dac_read_search or dac_override, setpcap and setuid capabilities to run sr";
fn cap_effective_error(caplist: &str) -> String {
    format!(
        "Unable to toggle {} privilege. {}",
        caplist, CAPABILITIES_ERROR
    )
}

fn getopt<S, I>(s: I) -> Result<Cli, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = Cli::default();
    let mut iter = s.into_iter().skip(1);
    let mut role = None;
    let mut task = None;
    let mut user: Option<SUserType> = None;
    let mut group: Option<SGroups> = None;
    let mut env = None;

    while let Some(arg) = iter.next() {
        // matches only first options
        match arg.as_ref() {
            "-u" | "--user" => {
                user = iter.next().map(|s| escape_parser_string(s).as_str().into());
            }
            "-g" | "--group" => {
                group = iter
                    .next()
                    .map(|s| {
                        SGroups::Multiple(
                            s.as_ref()
                                .split(',')
                                .map(|g| g.into())
                                .collect::<Vec<SGroupType>>(),
                        )
                    })
                    .into();
            }
            "-S" | "--stdin" => {
                args.stdin = true;
            }
            "-r" | "--role" => {
                role = iter.next().map(|s| escape_parser_string(s));
            }
            "-t" | "--task" => {
                task = iter.next().map(|s| escape_parser_string(s));
            }
            "-E" | "--preserve-env" => {
                env.replace(EnvBehavior::Keep);
            }
            "-p" | "--prompt" => {
                args.prompt = iter
                    .next()
                    .map(|s| escape_parser_string(s))
                    .unwrap_or_default();
            }
            "-i" | "--info" => {
                args.info = true;
            }
            "-h" | "--help" => {
                args.help = true;
            }
            _ => {
                if arg.as_ref().starts_with('-') {
                    return Err(format!("Unknown option: {}", arg.as_ref()).into());
                } else {
                    args.cmd_path = final_path(arg.as_ref());
                    break;
                }
            }
        }
        
    }
    args.opt_filter = Some(
        FilterMatcher::builder()
            .maybe_role(role)
            .maybe_task(task)
            .maybe_env_behavior(env)
            .maybe_user(user)
            .maybe_group(group)
            .build(),
    );
    for arg in iter {
        args.cmd_args.push(escape_parser_string(arg));
    }
    Ok(args)
}

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), Box<dyn Error>> {
    use finder::find_best_exec_settings;
    use crate::{pam::check_auth, ROOTASROLE};

    subsribe("sr")?;
    drop_effective()?;
    let args = std::env::args();
    if args.len() < 2 {
        println!("{}", USAGE);
        return Ok(());
    }
    let args = getopt(args)?;

    if args.help {
        println!("{}", USAGE);
        return Ok(());
    }
    let user = make_cred();
    let execcfg = find_best_exec_settings(&args, &user, &ROOTASROLE.to_string())?;

    check_auth(&execcfg.opt, &user, &args.prompt)?;

    if !execcfg.score.fully_matching() {
        println!("You are not allowed to execute this command, this incident will be reported.");
        error!(
            "User {} tried to execute command : {:?} {:?} without the permission.",
            &user.user.name, args.cmd_path, args.cmd_args
        );

        std::process::exit(1);
    }

    if args.info {
        println!("Role: {}", execcfg.role);
        println!("Task: {}", execcfg.task);
        println!(
            "With capabilities: {}",
            execcfg
                .caps
                .unwrap_or_default()
                .into_iter()
                .fold(String::new(), |acc, cap| acc + &cap.to_string() + " ")
        );
        std::process::exit(0);
    }

    // disable root
    if execcfg.opt.root.is_none_or(|root| root.is_user()) {
        activates_no_new_privs().expect("Failed to activate no new privs");
    }

    debug!("setuid : {:?}", execcfg.setuid);

    setuid_setgid(&execcfg);
    let cred = make_cred();

    set_capabilities(&execcfg);

    //execute command
    let envset = execcfg.opt
        .calc_env(args.opt_filter, cred, std::env::vars())
        .expect("Failed to calculate env");

    let pty = Pty::new().expect("Failed to create pty");

    debug!(
        "Command: {:?} {:?}",
        args.cmd_path,
        args.cmd_args.join(" ")
    );
    let command = Command::new(&args.cmd_path)
        .args(args.cmd_args.iter())
        .env_clear()
        .envs(envset)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn(&pty.pts().expect("Failed to get pts"));
    let mut command = match command {
        Ok(command) => command,
        Err(e) => {
            error!("{}", e);
            eprintln!("sr: {} : {}", args.cmd_path.display(), e);
            std::process::exit(1);
        }
    };
    let status = command.wait().expect("Failed to wait for command");
    std::process::exit(status.code().unwrap_or(1));
}

fn make_cred() -> Cred {
    let user = User::from_uid(getuid())
        .expect("Failed to get user")
        .expect("Failed to get user");
    let mut groups = getgroups()
        .expect("Failed to get groups")
        .iter()
        .map(|g| {
            Group::from_gid(*g)
                .expect("Failed to get group")
                .expect("Failed to get group")
        })
        .collect::<Vec<_>>();
    groups.insert(
        0,
        Group::from_gid(user.gid)
            .expect("Failed to get group")
            .expect("Failed to get group"),
    );
    debug!("User: {} ({}), Groups: {:?}", user.name, user.uid, groups,);
    let mut tty: Option<dev_t> = None;
    if let Ok(stat) = stat::fstat(stdout().as_raw_fd()) {
        if let Ok(istty) = isatty(stdout().as_raw_fd()) {
            if istty {
                tty = Some(stat.st_rdev);
            }
        }
    }
    // get parent pid
    let ppid = nix::unistd::getppid();

    Cred {
        user,
        groups,
        tty,
        ppid,
    }
}

fn set_capabilities(execcfg: &BestExecSettings) {
    //set capabilities
    if let Some(caps) = execcfg.caps {
        // case where capabilities are more than bounding set
        let bounding = capctl::bounding::probe();
        if bounding & caps != caps {
            panic!("Unable to setup the execution environment: There are more capabilities in this task than the current bounding set! You may are in a container or already in a RootAsRole session.");
        }
        setpcap_effective(true).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
        let mut capstate = CapState::empty();
        if !execcfg.opt.bounding.is_some_and(|b| b.is_ignore()) {
            for cap in (!caps).iter() {
                capctl::bounding::drop(cap).expect("Failed to set bounding cap");
            }
        }
        capstate.permitted = caps;
        capstate.inheritable = caps;
        debug!("caps : {:?}", caps);
        capstate.set_current().expect("Failed to set current cap");
        for cap in caps.iter() {
            capctl::ambient::raise(cap).expect("Failed to set ambiant cap");
        }
        setpcap_effective(false).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
    } else {
        setpcap_effective(true).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
        if !execcfg.opt.bounding.is_some_and(|b| b.is_ignore()){
            capctl::bounding::clear().expect("Failed to clear bounding cap");
        }
        let capstate = CapState::empty();
        capstate.set_current().expect("Failed to set current cap");
        setpcap_effective(false).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
    }
}

fn setuid_setgid(execcfg: &BestExecSettings) {
    let uid = execcfg.setuid.as_ref().and_then(|u| {
        let res = u.fetch_user();
        if let Some(user) = res {
            Some(user.uid.as_raw())
        } else {
            None
        }
    });
    let gid = execcfg.setgroups.as_ref().and_then(|g| match g {
        SGroups::Single(g) => {
            let res = g.fetch_group();
            if let Some(group) = res {
                Some(group.gid.as_raw())
            } else {
                None
            }
        }
        SGroups::Multiple(g) => {
            let res = g.first().unwrap().fetch_group();
            if let Some(group) = res {
                Some(group.gid.as_raw())
            } else {
                None
            }
        }
    });
    let groups = execcfg.setgroups.as_ref().and_then(|g| match g {
        SGroups::Single(g) => {
            let res = g.fetch_group();
            if let Some(group) = res {
                Some(vec![group.gid.as_raw()])
            } else {
                None
            }
        }
        SGroups::Multiple(g) => {
            let res = g.iter().map(|g| g.fetch_group());
            let mut groups = Vec::new();
            for group in res.flatten() {
                groups.push(group.gid.as_raw());
            }
            Some(groups)
        }
    });

    setgid_effective(true).unwrap_or_else(|_| panic!("{}", cap_effective_error("setgid")));
    setuid_effective(true).unwrap_or_else(|_| panic!("{}", cap_effective_error("setuid")));
    capctl::cap_set_ids(uid, gid, groups.as_deref()).expect("Failed to set ids");
    setgid_effective(false).unwrap_or_else(|_| panic!("{}", cap_effective_error("setgid")));
    setuid_effective(false).unwrap_or_else(|_| panic!("{}", cap_effective_error("setuid")));
}

#[cfg(test)]
mod tests {
    use libc::getgid;
    use nix::unistd::Pid;
    
    

    use super::*;
    
    

    /**
    #[test]
    fn test_from_json_execution_settings() {
        let mut args = Cli {
            opt_filter: None,
            prompt: PAM_PROMPT.to_string(),
            info: false,
            help: false,
            stdin: false,
            command: vec!["ls".to_string(), "-l".to_string()],
        };
        let user = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            groups: vec![],
            tty: None,
            ppid: Pid::parent(),
        };
        let config = rc_refcell!(SConfig::default());
        let role = rc_refcell!(SRole::default());
        let task = rc_refcell!(STask::default());
        task.as_ref().borrow_mut().name = IdTask::Name("task1".to_owned());
        task.as_ref().borrow_mut().commands = SCommands::default();
        task.as_ref()
            .borrow_mut()
            .commands
            .add
            .push(SCommand::Simple("ls -l".to_owned()));
        role.as_ref().borrow_mut().name = "role1".to_owned();
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user(0).build());
        role.as_ref().borrow_mut().tasks.push(task);
        let task = rc_refcell!(STask::default());
        task.as_ref().borrow_mut().name = IdTask::Name("task2".to_owned());
        task.as_ref().borrow_mut().commands = SCommands::default();
        task.as_ref()
            .borrow_mut()
            .commands
            .add
            .push(SCommand::Simple("ls .*".to_owned()));
        role.as_ref().borrow_mut().tasks.push(task);
        let task = rc_refcell!(STask::default());
        task.as_ref().borrow_mut().name = IdTask::Name("task3".to_owned());
        role.as_ref().borrow_mut().tasks.push(task);
        config.as_ref().borrow_mut().roles.push(role);
        make_weak_config(&config);
        let taskmatch = from_json_execution_settings(&args, &config, &user).unwrap();
        assert!(taskmatch.score.fully_matching());
        args.opt_filter = Some(FilterMatcher::default());
        args.opt_filter.as_mut().unwrap().role = Some("role1".to_owned());
        let taskmatch = from_json_execution_settings(&args, &config, &user).unwrap();
        assert!(taskmatch.score.fully_matching());
        args.opt_filter.as_mut().unwrap().task = Some("task1".to_owned());
        let taskmatch = from_json_execution_settings(&args, &config, &user).unwrap();
        assert!(taskmatch.score.fully_matching());
        args.opt_filter.as_mut().unwrap().task = Some("task2".to_owned());
        let taskmatch = from_json_execution_settings(&args, &config, &user).unwrap();
        assert!(taskmatch.score.fully_matching());
        args.opt_filter.as_mut().unwrap().task = Some("task3".to_owned());
        let taskmatch = from_json_execution_settings(&args, &config, &user);
        assert!(taskmatch.is_err());
        args.opt_filter.as_mut().unwrap().role = None;
        let taskmatch = from_json_execution_settings(&args, &config, &user);
        assert!(taskmatch.is_err());
    }*/

    #[test]
    fn test_getopt() {
        let args = getopt(vec![
            "chsr", "-r", "role1", "-t", "task1", "-p", "prompt", "-i", "-h", "ls", "-l",
        ])
        .unwrap();
        let opt_filter = args.opt_filter.as_ref().unwrap();
        assert_eq!(opt_filter.role.as_deref(), Some("role1"));
        assert_eq!(opt_filter.task.as_deref(), Some("task1"));
        assert_eq!(args.prompt, "prompt");
        assert!(args.info);
        assert!(args.help);
        assert_eq!(args.cmd_path, PathBuf::from("/usr/bin/ls"));
        assert_eq!(args.cmd_args, vec!["-l".to_string()]);
    }

    #[test]
    fn test_make_cred() {
        let user = make_cred();
        let gid = unsafe { getgid() };
        assert_eq!(user.user.uid, getuid());
        assert_eq!(user.user.gid.as_raw(), gid);
        assert!(!user.groups.is_empty());
        assert_eq!(user.groups[0].gid.as_raw(), gid);
        assert_eq!(user.ppid, Pid::parent());
    }
}
