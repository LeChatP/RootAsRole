mod finder;
pub mod pam;
mod timeout;

use bon::Builder;
use capctl::CapState;
use const_format::formatcp;
use finder::BestExecSettings;
use nix::{sys::stat, unistd::isatty};
use rar_common::util::escape_parser_string;
use rar_common::{
    database::{
        actor::{SGroupType, SGroups, SUserType},
        options::EnvBehavior,
        FilterMatcher,
    },
    Cred,
};

use log::{debug, error};
use pam::PAM_PROMPT;
use pty_process::blocking::{Command, Pty};
use std::{error::Error, io::stdout, os::fd::AsRawFd, path::PathBuf};

use rar_common::util::{
    activates_no_new_privs, drop_effective, setgid_effective, setpcap_effective, setuid_effective,
    subsribe, BOLD, RST, UNDERLINE,
};

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

#[derive(Debug, Builder)]
struct Cli {
    /// Role option allows you to select a specific role to use.
    opt_filter: Option<FilterMatcher>,

    #[builder(into)]
    /// Prompt option allows you to override the default password prompt and use a custom one.
    prompt: Option<String>,

    #[builder(default, with = || true)]
    /// Display rights of executor
    info: bool,

    #[builder(default, with = || true)]
    /// Display help
    help: bool,

    #[builder(default, into)]
    /// A non-absolute path to the command that needs to be found in the PATH
    cmd_path: PathBuf,

    #[builder(default, with = |i : impl IntoIterator<Item = impl Into<String>> | i.into_iter().map(|s| s.into()).collect())]
    /// Command arguments
    cmd_args: Vec<String>,

    #[builder(default, with = || true)]
    /// Use stdin for password prompt
    stdin: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Cli::builder().prompt(PAM_PROMPT).build()
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
                args.prompt = Some(
                    iter.next()
                        .map(|s| escape_parser_string(s))
                        .expect("Missing prompt for -p option"),
                );
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
                    args.cmd_path = arg.as_ref().into();
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
            .maybe_user(user)?
            .maybe_group(group)?
            .build(),
    );
    for arg in iter {
        args.cmd_args.push(escape_parser_string(arg));
    }
    Ok(args)
}

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), Box<dyn Error>> {
    use std::env;

    use crate::{pam::check_auth, ROOTASROLE};
    use finder::find_best_exec_settings;

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
    let execcfg = find_best_exec_settings(
        &args,
        &user,
        &ROOTASROLE.to_string(),
        env::vars(),
        env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .collect::<Vec<_>>()
            .as_slice(),
    )?;

    check_auth(
        &execcfg.auth,
        &execcfg.timeout,
        &user,
        &args.prompt.unwrap_or(PAM_PROMPT.to_string()),
    )?;

    if !execcfg.score.fully_matching() {
        println!("You are not allowed to execute this command, this incident will be reported.");
        error!(
            "User {} tried to execute command : {:?} {:?} without the permission.",
            &user.user.name, args.cmd_path, args.cmd_args
        );

        std::process::exit(1);
    }

    if args.info {
        //println!("Role: {}", if execcfg.role.is_empty() { "None" } else { &execcfg.role });
        //println!("Task: {}", execcfg.task);
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
    if execcfg.root.is_user() {
        activates_no_new_privs().expect("Failed to activate no new privs");
    }

    debug!("setuid : {:?}", execcfg.setuid);

    setuid_setgid(&execcfg);

    set_capabilities(&execcfg);

    let pty = Pty::new().expect("Failed to create pty");

    debug!(
        "Command: {:?} {:?}",
        execcfg.final_path,
        args.cmd_args.join(" ")
    );
    let command = Command::new(&execcfg.final_path)
        .args(args.cmd_args.iter())
        .env_clear()
        .envs(execcfg.env)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn(&pty.pts().expect("Failed to get pts"));
    let mut command = match command {
        Ok(command) => command,
        Err(e) => {
            error!("{}", e);
            eprintln!("sr: {} : {}", execcfg.final_path.display(), e);
            std::process::exit(1);
        }
    };
    let status = command.wait().expect("Failed to wait for command");
    std::process::exit(status.code().unwrap_or(1));
}

fn make_cred() -> Cred {
    return Cred::builder()
        .maybe_tty(stat::fstat(stdout().as_raw_fd()).ok().and_then(|s| {
            if isatty(stdout().as_raw_fd()).ok().unwrap_or(false) {
                Some(s.st_rdev)
            } else {
                None
            }
        }))
        .build();
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
        if execcfg.bounding.is_strict() {
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
        if execcfg.bounding.is_strict() {
            capctl::bounding::clear().expect("Failed to clear bounding cap");
        }
        capctl::ambient::clear().expect("Failed to clear ambient cap");
        let capstate = CapState::empty();
        capstate.set_current().expect("Failed to set current cap");
    }
}

fn setuid_setgid(execcfg: &BestExecSettings) {
    let gid = execcfg.setgroups.as_ref().and_then(|g| g.first().cloned());

    setgid_effective(true).unwrap_or_else(|_| panic!("{}", cap_effective_error("setgid")));
    setuid_effective(true).unwrap_or_else(|_| panic!("{}", cap_effective_error("setuid")));
    capctl::cap_set_ids(execcfg.setuid, gid, execcfg.setgroups.as_deref())
        .expect("Failed to set ids");
    setgid_effective(false).unwrap_or_else(|_| panic!("{}", cap_effective_error("setgid")));
    setuid_effective(false).unwrap_or_else(|_| panic!("{}", cap_effective_error("setuid")));
}

#[cfg(test)]
mod tests {
    use capctl::{Cap, CapSet};
    use libc::getgid;
    use nix::unistd::{getuid, Pid};
    use rar_common::database::options::SBounding;

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
            "sr",
            "-u",
            "root",
            "-g",
            "root,root",
            "-r",
            "role1",
            "-t",
            "task1",
            "-p",
            "prompt",
            "-E",
            "-i",
            "-h",
            "ls",
            "-l",
        ])
        .unwrap();
        let opt_filter = args.opt_filter.as_ref().unwrap();
        assert_eq!(opt_filter.user, Some(0));
        assert_eq!(opt_filter.group, Some(vec![0, 0]));
        assert_eq!(opt_filter.role.as_deref(), Some("role1"));
        assert_eq!(opt_filter.task.as_deref(), Some("task1"));
        assert_eq!(args.prompt.unwrap(), "prompt");
        assert!(args.info);
        assert!(args.help);
        assert_eq!(args.cmd_path, PathBuf::from("ls"));
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

    #[test]
    fn test_setuid_setgid() {
        let mut capset = CapState::get_current().unwrap();
        if capset.permitted.has(Cap::SETUID) && capset.permitted.has(Cap::SETGID) {
            println!("setuid and setgid are available");
            capset.effective.add(Cap::SETUID);
            capset.effective.add(Cap::SETGID);
            capset.set_current().unwrap();
            let mut execcfg = BestExecSettings::default();
            execcfg.setuid = Some(1000);
            execcfg.setgroups = Some(vec![1000]);
            setuid_setgid(&execcfg);
            assert_eq!(getuid().as_raw(), execcfg.setuid.unwrap());
            if let Some(gid) = execcfg.setgroups.as_ref().and_then(|g| g.first()) {
                assert_eq!(unsafe { getgid() }, *gid);
            }
            capset.effective.clear();
            capset.set_current().unwrap();
        }
    }

    #[test]
    fn test_set_capabilities() {
        let mut capset = CapState::get_current().unwrap();
        if capset.permitted.has(Cap::SETPCAP) {
            capset.effective.add(Cap::SETPCAP);
            capset.set_current().unwrap();
            let mut execcfg = BestExecSettings::default();
            let mut capset = CapSet::empty();
            capset.add(Cap::SETUID);
            capset.add(Cap::SETGID);
            capset.add(Cap::SETPCAP);
            execcfg.caps = Some(capset);
            set_capabilities(&execcfg);
            let capset = CapState::get_current().unwrap();
            assert!(capset.permitted.has(Cap::SETUID));
            assert!(capset.permitted.has(Cap::SETGID));
            assert!(capset.permitted.has(Cap::SETPCAP));
            assert!(capset.inheritable.has(Cap::SETUID));
            assert!(capset.inheritable.has(Cap::SETGID));
            assert!(capset.inheritable.has(Cap::SETPCAP));
            assert!(capctl::bounding::probe().has(Cap::SETUID));
            assert!(capctl::bounding::probe().has(Cap::SETGID));
            assert!(capctl::bounding::probe().has(Cap::SETPCAP));
            assert!(capctl::ambient::probe().unwrap().has(Cap::SETUID));
            assert!(capctl::ambient::probe().unwrap().has(Cap::SETGID));
            assert!(capctl::ambient::probe().unwrap().has(Cap::SETPCAP));
            execcfg.caps = None;
            execcfg.bounding = SBounding::Strict;
            set_capabilities(&execcfg);
            let capset = CapState::get_current().unwrap();
            assert!(!capset.permitted.has(Cap::SETUID));
            assert!(!capset.permitted.has(Cap::SETGID));
            assert!(!capset.permitted.has(Cap::SETPCAP));
            assert!(!capset.inheritable.has(Cap::SETUID));
            assert!(!capset.inheritable.has(Cap::SETGID));
            assert!(!capset.inheritable.has(Cap::SETPCAP));
            assert!(!capctl::bounding::probe().has(Cap::SETUID));
            assert!(!capctl::bounding::probe().has(Cap::SETGID));
            assert!(!capctl::bounding::probe().has(Cap::SETPCAP));
            assert!(!capctl::ambient::probe().unwrap().has(Cap::SETUID));
            assert!(!capctl::ambient::probe().unwrap().has(Cap::SETGID));
            assert!(!capctl::ambient::probe().unwrap().has(Cap::SETPCAP));
        }
    }
}
