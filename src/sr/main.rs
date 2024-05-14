#[path = "../mod.rs"]
mod common;
mod timeout;

use capctl::CapState;
use common::database::finder::{Cred, TaskMatch, TaskMatcher};
use common::database::structs::IdTask;
use common::database::{options::OptStack, structs::SConfig};
use const_format::formatcp;
use nix::{
    libc::dev_t,
    sys::stat,
    unistd::{getgroups, getuid, isatty, Group, User},
};
use pam_client::{Context, Flag};
use pam_client::{ConversationHandler, ErrorCode};
use pcre2::bytes::RegexBuilder;
use pest_derive::Parser;
use pty_process::blocking::{Command, Pty};
use shell_words::ParseError;
use std::ffi::{CStr, CString};
#[cfg(not(debug_assertions))]
use std::panic::set_hook;
use std::{cell::RefCell, error::Error, io::stdout, os::fd::AsRawFd, rc::Rc};
use tracing::{debug, error, info};

use crate::common::plugin::register_plugins;
use crate::common::{
    activates_no_new_privs,
    config::{self, Storage},
    dac_override_effective,
    database::{read_json_config, structs::SGroups},
    read_effective, setgid_effective, setpcap_effective, setuid_effective,
    util::{BOLD, RED, RST, UNDERLINE},
};
use crate::common::{drop_effective, subsribe};

use pest::iterators::Pair;
use pest::Parser;

#[cfg(not(test))]
const PAM_SERVICE: &str = "sr";
#[cfg(test)]
const PAM_SERVICE: &str = "sr_test";

const PAM_PROMPT: &str = "Password: ";

#[derive(Parser, Debug)]
#[grammar = "sr/cli.pest"]
struct Grammar;

const ABOUT: &str = "Execute privileged commands with a role-based access control system";
const LONG_ABOUT: &str =
    "sr is a tool to execute privileged commands with a role-based access control system. 
It is designed to be used in a multi-user environment, 
where users can be assigned to different roles, 
and each role has a set of rights to execute commands.";

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

  {BOLD}-p, --prompt <PROMPT>{RST}
          Prompt option allows you to override the default password prompt and use a custom one
          
          [default: "Password: "]

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
    role: Option<String>,

    /// Task option allows you to select a specific task to use in the selected role.
    /// Note: You must specify a role to designate a task.
    task: Option<String>,

    /// Prompt option allows you to override the default password prompt and use a custom one.
    prompt: String,

    /// Display rights of executor
    info: bool,

    /// Display help
    help: bool,

    /// Command to execute
    command: Vec<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Cli {
            role: None,
            task: None,
            prompt: PAM_PROMPT.to_string(),
            info: false,
            help: false,
            command: vec![],
        }
    }
}

struct SrConversationHandler {
    username: Option<String>,
    prompt: String,
}

impl SrConversationHandler {
    fn new(prompt: &str) -> Self {
        SrConversationHandler {
            prompt: prompt.to_string(),
            username: None,
        }
    }
    fn is_pam_password_prompt(&self, prompt: &CStr) -> bool {
        let pam_prompt = prompt.to_string_lossy();
        RegexBuilder::new()
            .build("^Password: ?$")
            .unwrap()
            .is_match(pam_prompt.as_bytes())
            .is_ok_and(|f| f)
            || self.username.as_ref().is_some_and(|username| {
                RegexBuilder::new()
                    .build(&format!("^{}'s Password: ?$", username))
                    .unwrap()
                    .is_match(pam_prompt.as_bytes())
                    .is_ok_and(|f| f)
            })
    }
}

impl Default for SrConversationHandler {
    fn default() -> Self {
        SrConversationHandler {
            prompt: "Password: ".to_string(),
            username: None,
        }
    }
}

impl ConversationHandler for SrConversationHandler {
    fn prompt_echo_on(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
        self.prompt_echo_off(prompt)
    }

    fn prompt_echo_off(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
        let pam_prompt = prompt.to_string_lossy();
        if self.prompt == Self::default().prompt && !self.is_pam_password_prompt(prompt) {
            self.prompt = pam_prompt.to_string()
        }
        match rpassword::prompt_password(&self.prompt) {
            Err(_) => Err(ErrorCode::CONV_ERR),
            Ok(password) => CString::new(password).map_err(|_| ErrorCode::CONV_ERR),
        }
    }

    fn text_info(&mut self, msg: &CStr) {
        info!("{}", msg.to_string_lossy());
        println!("{}", msg.to_string_lossy());
    }

    fn error_msg(&mut self, msg: &CStr) {
        error!("{}", msg.to_string_lossy());
        eprintln!("{}", msg.to_string_lossy());
    }
}

fn match_pair(pair: &Pair<Rule>, inputs: &mut Cli) -> Result<(), ParseError> {
    match pair.as_rule() {
        Rule::role => {
            inputs.role = Some(pair.as_str().to_string());
        }
        Rule::task => {
            inputs.task = Some(pair.as_str().to_string());
        }
        Rule::prompt => {
            inputs.prompt = pair.as_str().to_string();
        }
        Rule::info => {
            inputs.info = true;
        }
        Rule::help => {
            inputs.help = true;
        }
        Rule::command => {
            inputs.command = shell_words::split(pair.as_str())?;
        }
        _ => {}
    }
    Ok(())
}

fn recurse_pair(pair: Pair<Rule>, inputs: &mut Cli) -> Result<(), ParseError> {
    for inner_pair in pair.into_inner() {
        match_pair(&inner_pair, inputs)?;
        recurse_pair(inner_pair, inputs)?;
    }
    Ok(())
}

const CAPABILITIES_ERROR: &str =
    "You need at least dac_read_search or dac_override, setpcap and setuid capabilities to run sr";
fn cap_effective_error(caplist: &str) -> String {
    format!(
        "Unable to toggle {} privilege. {}",
        caplist, CAPABILITIES_ERROR
    )
}

fn from_json_execution_settings(
    args: &Cli,
    config: &Rc<RefCell<SConfig>>,
    user: &Cred,
) -> Result<TaskMatch, Box<dyn Error>> {
    match (&args.role, &args.task) {
        (None, None) => config.matches(user, &args.command).map_err(|m| m.into()),
        (Some(role), None) => as_borrow!(config)
            .role(role)
            .expect("Permission Denied")
            .matches(user, &args.command)
            .map_err(|m| m.into()),
        (Some(role), Some(task)) => {
            let task = IdTask::Name(task.to_string());
            let res = as_borrow!(config)
                .role(role)
                .expect("Permission Denied")
                .matches(user, &args.command)?;
            if res.fully_matching() && res.settings.task().as_ref().borrow().name == task {
                Ok(res)
            } else if res.user_matching() {
                let mut taskres = as_borrow!(config)
                    .task(role, &task)
                    .expect("Permission Denied")
                    .matches(user, &args.command)?;
                if taskres.command_matching() {
                    taskres.score.user_min = res.score.user_min;
                    Ok(taskres)
                } else {
                    Err("Permission Denied".into())
                }
            } else {
                Err("Permission Denied".into())
            }
        }
        (None, Some(_)) => Err("You must specify a role to designate a task".into()),
    }
}

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), Box<dyn Error>> {
    use crate::common::util::{escape_parser_string, underline};

    subsribe("sr");
    drop_effective()?;
    register_plugins();
    let grammar = escape_parser_string(std::env::args());
    let grammar = Grammar::parse(Rule::cli, &grammar);
    let grammar = match grammar {
        Ok(v) => v,
        Err(e) => {
            println!("{}", USAGE);
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
    let mut args = Cli::default();
    for pair in grammar {
        recurse_pair(pair, &mut args);
    }
    if args.help {
        println!("{}", USAGE);
        return Ok(());
    }
    read_effective(true)
        .or(dac_override_effective(true))
        .unwrap_or_else(panic!(
            "{}",
            cap_effective_error("dac_read_search or dac_override")
        ));
    let settings = config::get_settings().expect("Failed to get settings");
    read_effective(false)
        .and(dac_override_effective(false))
        .unwrap_or_else(|_| panic!("{}", cap_effective_error("dac_read")));
    let config = match settings.clone().as_ref().borrow().storage.method {
        config::StorageMethod::JSON => {
            Storage::JSON(read_json_config(settings).expect("Failed to read config"))
        }
        _ => {
            return Err("Unsupported storage method".into());
        }
    };
    let user = make_cred();
    let taskmatch = match config {
        Storage::JSON(ref config) => {
            from_json_execution_settings(&args, config, &user).unwrap_or_default()
        }
    };
    let execcfg = &taskmatch.settings;

    let optstack = &execcfg.opt;
    check_auth(optstack, &config, &user, &args.prompt)?;

    if !taskmatch.fully_matching() {
        println!("You are not allowed to execute this command, this incident will be reported.");
        error!(
            "User {} tried to execute command : {:?} without the permission.",
            &user.user.name, args.command
        );
        std::process::exit(1);
    }

    if args.info {
        println!("Role: {}", execcfg.role().as_ref().borrow().name);
        println!("Task: {}", execcfg.task().as_ref().borrow().name);
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
    if !optstack.get_root_behavior().1.is_privileged() {
        activates_no_new_privs().expect("Failed to activate no new privs");
    }

    debug!("setuid : {:?}", execcfg.setuid);

    setuid_setgid(execcfg);

    set_capabilities(execcfg, optstack);

    //execute command
    let envset = optstack
        .calculate_filtered_env()
        .expect("Failed to calculate env");
    let pty = Pty::new().expect("Failed to create pty");

    let command = Command::new(&execcfg.exec_path)
        .args(execcfg.exec_args.iter())
        .envs(envset)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn(&pty.pts().expect("Failed to get pts"));
    let mut command = match command {
        Ok(command) => command,
        Err(e) => {
            error!("{}", e);
            /*error!(
                "{} : command not found",
                matching.exec_path.display()
            );*/
            eprintln!("sr: {} : command not found", execcfg.exec_path.display());
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

    let user = Cred {
        user,
        groups,
        tty,
        ppid,
    };
    user
}

fn set_capabilities(execcfg: &common::database::finder::ExecSettings, optstack: &OptStack) {
    //set capabilities
    if let Some(caps) = execcfg.caps {
        setpcap_effective(true).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
        let mut capstate = CapState::empty();
        if !optstack.get_bounding().1.is_ignore() {
            for cap in (!caps).iter() {
                capctl::bounding::drop(cap).expect("Failed to set bounding cap");
            }
        }
        capstate.permitted = caps;
        capstate.inheritable = caps;
        capstate.set_current().expect("Failed to set current cap");
        for cap in caps.iter() {
            capctl::ambient::raise(cap).expect("Failed to set ambiant cap");
        }
        setpcap_effective(false).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
    } else {
        setpcap_effective(true).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
        if !optstack.get_bounding().1.is_ignore() {
            capctl::bounding::clear().expect("Failed to clear bounding cap");
        }
        let capstate = CapState::empty();
        capstate.set_current().expect("Failed to set current cap");
        setpcap_effective(false).unwrap_or_else(|_| panic!("{}", cap_effective_error("setpcap")));
    }
}

fn setuid_setgid(execcfg: &common::database::finder::ExecSettings) {
    let uid = execcfg.setuid.as_ref().and_then(|u| {
        let res = u.into_user().unwrap_or(None);
        if let Some(user) = res {
            Some(user.uid.as_raw())
        } else {
            None
        }
    });
    let gid = execcfg.setgroups.as_ref().and_then(|g| match g {
        SGroups::Single(g) => {
            let res = g.into_group().unwrap_or(None);
            if let Some(group) = res {
                Some(group.gid.as_raw())
            } else {
                None
            }
        }
        SGroups::Multiple(g) => {
            let res = g.first().unwrap().into_group().unwrap_or(None);
            if let Some(group) = res {
                Some(group.gid.as_raw())
            } else {
                None
            }
        }
    });
    let groups = execcfg.setgroups.as_ref().and_then(|g| match g {
        SGroups::Single(g) => {
            let res = g.into_group().unwrap_or(None);
            if let Some(group) = res {
                Some(vec![group.gid.as_raw()])
            } else {
                None
            }
        }
        SGroups::Multiple(g) => {
            let res = g.iter().map(|g| g.into_group().unwrap_or(None));
            let mut groups = Vec::new();
            for group in res {
                if let Some(group) = group {
                    groups.push(group.gid.as_raw());
                }
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

fn check_auth(
    optstack: &OptStack,
    config: &Storage,
    user: &Cred,
    prompt: &str,
) -> Result<(), Box<dyn Error>> {
    let timeout = optstack.get_timeout().1;
    let is_valid = match config {
        Storage::JSON(_) => timeout::is_valid(user, user, &timeout),
    };
    debug!("need to re-authenticate : {}", !is_valid);
    if !is_valid {
        let mut context = Context::new(
            PAM_SERVICE,
            Some(&user.user.name),
            SrConversationHandler::new(prompt),
        )
        .expect("Failed to initialize PAM");
        context.authenticate(Flag::SILENT)?;
        context.acct_mgmt(Flag::SILENT)?;
    }
    match config {
        Storage::JSON(_) => {
            timeout::update_cookie(user, user, &timeout)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use nix::unistd::Pid;

    use super::*;
    use crate::common::database::make_weak_config;
    use crate::common::database::structs::{
        IdTask, SActor, SCommand, SCommands, SConfig, SRole, STask,
    };

    #[test]
    fn test_from_json_execution_settings() {
        let mut args = Cli {
            role: None,
            task: None,
            prompt: PAM_PROMPT.to_string(),
            info: false,
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
            .push(SActor::from_user_id(0));
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
        assert!(taskmatch.fully_matching());
        args.role = Some("role1".to_owned());
        let taskmatch = from_json_execution_settings(&args, &config, &user).unwrap();
        assert!(taskmatch.fully_matching());
        args.task = Some("task1".to_owned());
        let taskmatch = from_json_execution_settings(&args, &config, &user).unwrap();
        assert!(taskmatch.fully_matching());
        args.task = Some("task2".to_owned());
        let taskmatch = from_json_execution_settings(&args, &config, &user).unwrap();
        assert!(taskmatch.fully_matching());
        args.task = Some("task3".to_owned());
        let taskmatch = from_json_execution_settings(&args, &config, &user);
        assert!(taskmatch.is_err());
        args.role = None;
        let taskmatch = from_json_execution_settings(&args, &config, &user);
        assert!(taskmatch.is_err());
    }
}
