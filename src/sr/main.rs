#[path = "../mod.rs"]
mod common;
mod timeout;

use capctl::CapState;
use clap::Parser;
use common::database::finder::{Cred, TaskMatch, TaskMatcher};
use common::database::{options::OptStack, structs::SConfig};
use nix::{
    libc::dev_t,
    sys::stat,
    unistd::{getgroups, getuid, isatty, Group, User},
};
use pam_client::{Context, Flag};
use pam_client::{ConversationHandler, ErrorCode};
use pcre2::bytes::RegexBuilder;
use pty_process::blocking::{Command, Pty};
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
};
use crate::common::{drop_effective, subsribe};

#[derive(Parser, Debug)]
#[command(
    about = "Execute privileged commands with a role-based access control system",
    long_about = "sr is a tool to execute privileged commands with a role-based access control system. 
It is designed to be used in a multi-user environment, 
where users can be assigned to different roles, 
and each role has a set of rights to execute commands."
)]
struct Cli {
    /// Role option allows you to select a specific role to use.
    #[arg(short, long)]
    role: Option<String>,

    /// Task option allows you to select a specific task to use in the selected role.
    /// Note: You must specify a role to designate a task.
    #[arg(short, long)]
    task: Option<String>,

    /// Prompt option allows you to override the default password prompt and use a custom one.
    #[arg(short, long, default_value = "Password: ")]
    prompt: String,

    /// Display rights of executor
    #[arg(short, long)]
    info: bool,
    /// Command to execute
    command: Vec<String>,
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

fn add_dashes() -> Vec<String> {
    //get current argv
    let mut args = std::env::args().collect::<Vec<_>>();
    debug!("args : {:?}", args);
    let mut i = -1;
    //iter through args until we find no dash
    let mut iter = args.iter().enumerate();
    iter.next();
    while let Some((pos, arg)) = iter.next() {
        if arg.starts_with('-') {
            if arg == "-r" {
                iter.next();
            }
            continue;
        } else {
            // add argument at this position
            i = pos as i32;
            break;
        }
    }
    if i > -1 {
        args.insert(i as usize, String::from("--"));
    }
    debug!("final args : {:?}", args);
    args
}

const CAPABILITIES_ERROR: &str =
    "You need at least dac_override, setpcap, setuid capabilities to run sr";
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
        (Some(role), Some(task)) => as_borrow!(config)
            .task(
                role,
                &common::database::structs::IdTask::Name(task.to_string()),
            )
            .expect("Permission Denied")
            .matches(user, &args.command)
            .map_err(|m| m.into()),
        (None, Some(_)) => Err("You must specify a role to designate a task".into()),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    subsribe("sr");
    drop_effective()?;
    register_plugins();
    let args = add_dashes();
    let args = Cli::parse_from(args.iter());
    read_effective(true).unwrap_or_else(|_| { panic!("{}", cap_effective_error("dac_read")) });
    let settings = config::get_settings().expect("Failed to get settings");
    read_effective(false).unwrap_or_else(|_| { panic!("{}", cap_effective_error("dac_read")) });
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

    dac_override_effective(true).unwrap_or_else(|_| { panic!("{}", cap_effective_error("dac_override")) });
    let config = match settings.clone().as_ref().borrow().storage.method {
        config::StorageMethod::JSON => {
            Storage::JSON(read_json_config(settings).expect("Failed to read config"))
        }
        _ => {
            return Err("Unsupported storage method".into());
        }
    };
    let taskmatch = match config {
        Storage::JSON(ref config) => {
            from_json_execution_settings(&args, config, &user).unwrap_or_default()
        }
    };
    let execcfg = &taskmatch.settings;

    let optstack = &execcfg.opt;
    check_auth(optstack, &config, &user, &args.prompt)?;
    dac_override_effective(false).unwrap_or_else(|_| { panic!("{}", cap_effective_error("dac_override")) });

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
        println!(
            "Task: {}",
            execcfg.task().as_ref().borrow().name
        );
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

    setgid_effective(true).unwrap_or_else(|_| { panic!("{}", cap_effective_error("setgid")) });
    setuid_effective(true).unwrap_or_else(|_| { panic!("{}", cap_effective_error("setuid")) });
    capctl::cap_set_ids(uid, gid, groups.as_deref())
        .expect("Failed to set ids");
    setgid_effective(false).unwrap_or_else(|_| { panic!("{}", cap_effective_error("setgid")) });
    setuid_effective(false).unwrap_or_else(|_| { panic!("{}", cap_effective_error("setuid")) });

    //set capabilities
    if let Some(caps) = execcfg.caps {
        setpcap_effective(true).unwrap_or_else(|_| { panic!("{}", cap_effective_error("setpcap")) });
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
        setpcap_effective(false).unwrap_or_else(|_| { panic!("{}", cap_effective_error("setpcap")) });
    } else {
        setpcap_effective(true).unwrap_or_else(|_| { panic!("{}", cap_effective_error("setpcap")) });
        if !optstack.get_bounding().1.is_ignore() {
            capctl::bounding::clear().expect("Failed to clear bounding cap");
        }
        let capstate = CapState::empty();
        capstate.set_current().expect("Failed to set current cap");
        setpcap_effective(false).unwrap_or_else(|_| { panic!("{}", cap_effective_error("setpcap")) });
    }

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
            "sr",
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
