mod command;
#[path = "../config/mod.rs"]
mod config;
mod finder;
mod timeout;
#[path = "../util.rs"]
mod util;
#[path = "../xml_version.rs"]
mod xml_version;

use std::{collections::HashMap, env::Vars, io::stdout, ops::Not, os::fd::AsRawFd};

use capctl::{prctl, Cap, CapState};
use clap::Parser;
use config::{load::load_config, FILENAME};
use finder::{Cred, TaskMatcher};
use nix::{
    libc::{dev_t, PATH_MAX},
    sys::stat,
    unistd::{getgroups, getuid, isatty, setegid, seteuid, setgroups, Group, User},
};
use pam_client::{conv_cli::Conversation, Context, Flag};
#[cfg(not(debug_assertions))]
use std::panic::set_hook;
use tracing::{debug, Level, error};
use tracing_subscriber::util::SubscriberInitExt;

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

fn filter_env_vars(env: Vars, checklist: &[&str], whitelist: &[&str]) -> HashMap<String, String> {
    env.filter(|(key, value)| {
        checklist.contains(&key.as_str()) && check_var(key, value)
            || whitelist.contains(&key.as_str())
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

fn main() {
    subsribe();
    let args = add_dashes();
    let args = Cli::parse_from(args.iter());
    read_effective(true).expect("Failed to read_effective");
    let config = load_config(&FILENAME).expect("Failed to load config file");
    read_effective(false).expect("Failed to read_effective");
    debug!("loaded config : {:#?}", config);
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
    let is_valid = timeout::is_valid(&user, &user, &config.as_ref().borrow().timestamp);
    debug!("need to re-authenticate : {}", !is_valid);
    if !is_valid {
        let mut context = Context::new("sr", Some(&user.user.name), Conversation::new())
            .expect("Failed to initialize PAM");
        context.authenticate(Flag::NONE).expect("Permission Denied");
        context.acct_mgmt(Flag::NONE).expect("Permission Denied");
    }
    timeout::update_cookie(&user, &user, &config.as_ref().borrow().timestamp)
        .expect("Failed to add cookie");
    dac_override_effective(false).expect("Failed to dac_override_effective");
    let matching = match args.role {
        None => match config
            .matches(&user, &args.command) {
                Err(err) => {
                    error!("Permission Denied");
                    std::process::exit(1);
                },
                Ok(matching) => matching,
            } 
            ,
        Some(role) => config
            .as_ref()
            .borrow()
            .roles
            .iter()
            .find(|r| r.as_ref().borrow().name == role)
            .expect("Permission Denied")
            .matches(&user, &args.command)
            .expect("Permission Denied"),
    };
    debug!(
        "Config : Matched user {}\n - with task {}\n - with role {}",
        user.user.name,
        matching.task().as_ref().borrow().id.to_string(),
        matching.role().as_ref().borrow().name
    );

    if args.info {
        println!("Role: {}", matching.role().as_ref().borrow().name);
        println!("Task: {}", matching.task().as_ref().borrow().id.to_string());
        println!(
            "With capabilities: {}",
            matching
                .caps()
                .unwrap_or_default()
                .into_iter()
                .fold(String::new(), |acc, cap| acc + &cap.to_string() + " ")
        );
        std::process::exit(0);
    }

    let optstack = matching.opt().as_ref().unwrap();

    // disable root
    if optstack.get_no_root().1 {
        activates_no_new_privs().expect("Failed to activate no new privs");
    }

    debug!("setuid : {:?}", matching.setuid());

    let uid = matching.setuid().as_ref().map(|u| {
        User::from_name(&u)
            .expect("Failed to get user")
            .expect("Failed to get user")
            .uid
            .as_raw()
    });
    let gid = matching.setgroups().as_ref().map(|g| {
        Group::from_name(&g.groups[0])
            .expect("Failed to get group")
            .expect("Failed to get group")
            .gid
            .as_raw()
    });
    let groups = matching.setgroups().as_ref().map(|g| {
        g.groups
            .iter()
            .map(|g| {
                Group::from_name(g)
                    .expect("Failed to get group")
                    .expect("Failed to get group")
                    .gid
                    .as_raw()
            })
            .collect::<Vec<_>>()
    });

    setuid_effective(true).expect("Failed to setuid_effective");
    capctl::cap_set_ids(uid, gid, groups.as_ref().map(|g| g.as_slice()))
        .expect("Failed to set ids");
    setuid_effective(false).expect("Failed to setuid_effective");

    //set capabilities
    if let Some(caps) = matching.caps() {
        setpcap_effective(true).expect("Failed to setpcap_effective");
        let mut capstate = CapState::empty();
        if optstack.get_bounding().1 {
            for cap in caps.not().iter() {
                capctl::bounding::drop(cap).expect("Failed to set bounding cap");
            }
        }
        capstate.permitted = *caps;
        capstate.inheritable = *caps;
        capstate.set_current().expect("Failed to set current cap");
        for cap in caps.iter() {
            capctl::ambient::raise(cap).expect("Failed to set ambiant cap");
        }
        setpcap_effective(false).expect("Failed to setpcap_effective");
    } else {
        setpcap_effective(true).expect("Failed to setpcap_effective");
        if optstack.get_bounding().1 {
            capctl::bounding::clear().expect("Failed to clear bounding cap");
        }
        let capstate = CapState::empty();
        capstate.set_current().expect("Failed to set current cap");
        setpcap_effective(false).expect("Failed to setpcap_effective");
    }

    //execute command
    let checklist = optstack.get_env_checklist().1;
    let whitelist = optstack.get_env_whitelist().1;
    let veccheck: Vec<&str> = checklist.split(',').collect();
    let vecwhitelist: Vec<&str> = whitelist.split(',').collect();
    let mut command = std::process::Command::new(matching.file_exec_path())
        .args(matching.exec_args())
        .envs(filter_env_vars(std::env::vars(), &veccheck, &vecwhitelist))
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn();
    let mut command = match command {
        Ok(command) => command,
        Err(_) => {
            error!("{} : command not found", matching.file_exec_path());
            eprintln!("sr: {} : command not found", matching.file_exec_path());
            std::process::exit(1);
        }
    };
    //wait for command to finish
    let status = command.wait().expect("Failed to wait for command");
    std::process::exit(status.code().unwrap_or(1));
}
