mod command;
#[path = "../mod.rs"]
mod common;
mod finder;
mod timeout;

use capctl::{prctl, Cap, CapState};
use clap::Parser;
use common::{
    config::{Settings, ROOTASROLE},
    database::structs::SConfig,
};
use finder::{Cred, ExecSettings, TaskMatcher};
use nix::{
    libc::{dev_t, PATH_MAX},
    sys::stat,
    unistd::{getgroups, getuid, isatty, Group, User},
};
use pam_client::{conv_cli::Conversation, Context, Flag};
use pty_process::blocking::{Command, Pty};
#[cfg(not(debug_assertions))]
use std::panic::set_hook;
use std::{
    cell::RefCell, collections::HashMap, env::Vars, error::Error, io::stdout, os::fd::AsRawFd,
    rc::Rc,
};
use tracing::{debug, error, Level};
use tracing_subscriber::util::SubscriberInitExt;

use crate::common::{config, database::structs::SGroups};

#[derive(Parser, Debug)]
#[command(
    about = "Execute privileged commands with a role-based access control system",
    long_about = "sr is a tool to execute privileged commands with a role-based access control system. 
It is designed to be used in a multi-user environment, 
where users can be assigned to different roles, 
and each role has a set of rights to execute commands."
)]
struct Cli {
    /// Role to select
    #[arg(short, long)]
    role: Option<String>,
    /// Display rights of executor
    #[arg(short, long)]
    info: bool,
    /// Command to execute
    command: Vec<String>,
}

enum Storage {
    JSON(Rc<RefCell<SConfig>>),
}

fn cap_effective(cap: Cap, enable: bool) -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.set_state(cap, enable);
    current.set_current()
}

fn setpcap_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETPCAP, enable)
}

fn setuid_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETUID, enable)
}

fn setgid_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETGID, enable)
}

fn read_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::DAC_READ_SEARCH, enable)
}

fn dac_override_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::DAC_OVERRIDE, enable)
}

fn activates_no_new_privs() -> Result<(), capctl::Error> {
    prctl::set_no_new_privs()
}

fn tz_is_safe(tzval: &str) -> bool {
    // tzcode treats a value beginning with a ':' as a path.
    let tzval = if tzval.starts_with(':') {
        &tzval[1..]
    } else {
        tzval
    };

    // Reject fully-qualified TZ that doesn't begin with the zoneinfo dir.
    if tzval.starts_with('/') {
        return false;
    }

    // Make sure TZ only contains printable non-space characters
    // and does not contain a '..' path element.
    let mut lastch = '/';
    for cp in tzval.chars() {
        if cp.is_ascii_whitespace() || !cp.is_ascii_graphic() {
            return false;
        }
        if lastch == '/'
            && cp == '.'
            && tzval
                .chars()
                .nth(tzval.chars().position(|c| c == '.').unwrap() + 1)
                == Some('.')
            && (tzval
                .chars()
                .nth(tzval.chars().position(|c| c == '.').unwrap() + 2)
                == Some('/')
                || tzval
                    .chars()
                    .nth(tzval.chars().position(|c| c == '.').unwrap() + 2)
                    .is_none())
        {
            return false;
        }
        lastch = cp;
    }

    // Reject extra long TZ values (even if not a path).
    if tzval.len() >= PATH_MAX.try_into().unwrap() {
        return false;
    }

    true
}

fn check_var(key: &str, value: &str) -> bool {
    if key.is_empty() || value.is_empty() {
        false
    } else {
        match key {
            "TZ" => tz_is_safe(value),
            _ => !value.contains(['/', '%']),
        }
    }
}

fn filter_env_vars(
    env: Vars,
    checklist: &[String],
    whitelist: &[String],
) -> HashMap<String, String> {
    env.filter(|(key, value)| {
        checklist.contains(key) && check_var(key, value) || whitelist.contains(key)
    })
    .collect()
}

#[cfg(debug_assertions)]
fn subsribe() {
    let identity = std::ffi::CStr::from_bytes_with_nul(b"sr\0").unwrap();
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_file(true)
        .with_line_number(true)
        .with_writer(syslog)
        .finish()
        .init();
}

#[cfg(not(debug_assertions))]
fn subsribe() {
    let identity = std::ffi::CStr::from_bytes_with_nul(b"sr\0").unwrap();
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
    tracing_subscriber::fmt()
        .with_max_level(Level::ERROR)
        .with_writer(syslog)
        .finish()
        .init();
    set_hook(Box::new(|info| {
        if let Some(s) = info.payload().downcast_ref::<String>() {
            println!("{}", s);
        }
    }));
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

fn read_json_config(settings: Settings) -> Result<Rc<RefCell<SConfig>>, Box<dyn Error>> {
    let file = std::fs::File::open(
        settings
            .remote_storage_settings
            .unwrap_or_default()
            .path
            .unwrap_or(ROOTASROLE.into()),
    )?;
    let config = serde_json::from_reader(file)?;
    Ok(config)
}

fn from_json_execution_settings(
    args: &Cli,
    config: &Rc<RefCell<SConfig>>,
    user: &Cred,
) -> Result<ExecSettings, Box<dyn Error>> {
    match &args.role {
        None => match config.matches(&user, &args.command) {
            Err(_) => {
                error!("Permission Denied");
                std::process::exit(1);
            }
            Ok(matching) => Ok(matching.settings),
        },
        Some(role) => Ok(as_borrow!(config)
            .role(&role)
            .expect("Permission Denied")
            .matches(&user, &args.command)
            .expect("Permission Denied")
            .settings),
    }
}

fn main() {
    subsribe();
    let args = add_dashes();
    let args = Cli::parse_from(args.iter());
    read_effective(true).expect("Failed to read_effective");
    let settings = config::get_settings();
    read_effective(false).expect("Failed to read_effective");
    debug!("loaded config : {:#?}", settings);
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

    dac_override_effective(true).expect("Failed to dac_override_effective");
    let config = match settings.storage_method {
        config::StorageMethod::JSON => {
            Storage::JSON(read_json_config(settings).expect("Failed to read config"))
        }
        _ => {
            error!("Unsupported storage method");
            std::process::exit(1);
        }
    };
    let is_valid = match config {
        Storage::JSON(ref config) => timeout::is_valid(&user, &user, &config.as_ref().borrow().timeout),
    };
    debug!("need to re-authenticate : {}", !is_valid);
    if !is_valid {
        let mut context = Context::new("sr", Some(&user.user.name), Conversation::new())
            .expect("Failed to initialize PAM");
        context.authenticate(Flag::NONE).expect("Permission Denied");
        context.acct_mgmt(Flag::NONE).expect("Permission Denied");
    }
    match config {
        Storage::JSON(ref config) => {
            timeout::update_cookie(&user, &user, &config.as_ref().borrow().timeout)
                .expect("Failed to add cookie");
        }
    }
    dac_override_effective(false).expect("Failed to dac_override_effective");
    let matching: ExecSettings = match config {
        Storage::JSON(ref config) => {
            let result =
                from_json_execution_settings(&args, config, &user).expect("Failed to get settings");

            result
        }
    };
    debug!(
        "Config : Matched user {}\n - with task {}\n - with role {}",
        user.user.name,
        matching.task().as_ref().borrow().name.to_string(),
        matching.role().as_ref().borrow().name
    );

    if args.info {
        println!("Role: {}", matching.role().as_ref().borrow().name);
        println!(
            "Task: {}",
            matching.task().as_ref().borrow().name.to_string()
        );
        println!(
            "With capabilities: {}",
            matching
                .caps
                .unwrap_or_default()
                .into_iter()
                .fold(String::new(), |acc, cap| acc + &cap.to_string() + " ")
        );
        std::process::exit(0);
    }

    let optstack = matching.opt.as_ref().unwrap();

    // disable root
    if !optstack.get_root_behavior().1.is_privileged() {
        activates_no_new_privs().expect("Failed to activate no new privs");
    }

    debug!("setuid : {:?}", matching.setuid);

    let uid = matching.setuid.and_then(|u| {
        let res = u.into_user().unwrap_or(None);
        if let Some(user) = res {
            Some(user.uid.as_raw())
        } else {
            None
        }
    });
    let gid = matching.setgroups.as_ref().and_then(|g| match g {
        SGroups::Single(g) => {
            let res = g.into_group().unwrap_or(None);
            if let Some(group) = res {
                Some(group.gid.as_raw())
            } else {
                None
            }
        }
        SGroups::Multiple(g) => {
            let res = g.get(0).unwrap().into_group().unwrap_or(None);
            if let Some(group) = res {
                Some(group.gid.as_raw())
            } else {
                None
            }
        }
    });
    let groups = matching.setgroups.as_ref().and_then(|g| {
        match g {
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
        }
    });

    setgid_effective(true).expect("Failed to setgid_effective");
    setuid_effective(true).expect("Failed to setuid_effective");
    capctl::cap_set_ids(uid, gid, groups.as_ref().map(|g| g.as_slice()))
        .expect("Failed to set ids");
    setgid_effective(false).expect("Failed to setgid_effective");
    setuid_effective(false).expect("Failed to setuid_effective");

    //set capabilities
    if let Some(caps) = matching.caps {
        setpcap_effective(true).expect("Failed to setpcap_effective");
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
        setpcap_effective(false).expect("Failed to setpcap_effective");
    } else {
        setpcap_effective(true).expect("Failed to setpcap_effective");
        if !optstack.get_bounding().1.is_ignore() {
            capctl::bounding::clear().expect("Failed to clear bounding cap");
        }
        let capstate = CapState::empty();
        capstate.set_current().expect("Failed to set current cap");
        setpcap_effective(false).expect("Failed to setpcap_effective");
    }

    //execute command
    let envset = optstack.calculate_filtered_env().expect("Failed to calculate env");
    let pty = Pty::new().expect("Failed to create pty");

    let command = Command::new(&matching.exec_path)
        .args(matching.exec_args)
        .envs(envset)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn(&pty.pts().expect("Failed to get pts"));
    let mut command = match command {
        Ok(command) => command,
        Err(_) => {
            error!(
                "{} : command not found",
                matching.exec_path.display()
            );
            eprintln!(
                "sr: {} : command not found",
                matching.exec_path.display()
            );
            std::process::exit(1);
        }
    };
    let status = command.wait().expect("Failed to wait for command");
    std::process::exit(status.code().unwrap_or(1));
}
