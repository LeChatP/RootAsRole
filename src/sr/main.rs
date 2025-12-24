mod error;
mod finder;
pub mod pam;
#[cfg(feature = "timeout")]
mod timeout;

use bon::Builder;
use capctl::{Cap, CapState};
use const_format::formatcp;
use finder::BestExecSettings;
use nix::{sys::stat, unistd::isatty};
use rar_common::util::{escape_parser_string, initialize_capabilities, with_privileges};
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
use std::{io::stdout, os::fd::AsRawFd, path::PathBuf};

use rar_common::util::{activates_no_new_privs, drop_effective, subsribe, BOLD, RST, UNDERLINE};

use crate::error::SrError;
use crate::error::SrResult;

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
    r#"{UNDERLINE}{BOLD}Usage:{RST} {BOLD}dosr{RST} [OPTIONS] [COMMAND]...

{UNDERLINE}{BOLD}Arguments:{RST}
  [COMMAND]...
          Command to execute

{UNDERLINE}{BOLD}Options:{RST}
  {BOLD}-r, --role <ROLE>{RST}
          Role option allows you to select a specific role to use

  {BOLD}-t, --task <TASK>{RST}
          Task option allows you to select a specific task to use in the selected role. Note: You must specify a role to designate a task

  {BOLD}-E, --preserve-env{RST}
          Preserve environment variables if allowed by a matching task

  {BOLD}-p, --prompt <PROMPT>{RST}
          Prompt option allows you to override the default password prompt and use a custom one
          [default: "Password: "]

  {BOLD}-u, --user <USER>{RST}
          Specify the user to execute the command as

  {BOLD}-g --group <GROUP>(,<GROUP>...){RST}
          Specify the group to execute the command as

  {BOLD}-i, --info{RST}
          Display rights of executor

  {BOLD}-v, --version{RST}
          Print dosr version

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

    #[builder(default, with = || false)]
    /// Delete timestamp cookie after successful authentication
    del_ts: bool,
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

fn getopt<S, I>(s: I) -> SrResult<Cli>
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
                group = iter.next().map(|s| {
                    SGroups::Multiple(
                        s.as_ref()
                            .split(',')
                            .map(|g| g.into())
                            .collect::<Vec<SGroupType>>(),
                    )
                });
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
            #[cfg(feature = "timeout")]
            "-K" | "--remove-timestamp" => {
                args.del_ts = true;
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
            "-v" | "--version" => {
                println!("dosr: version {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => {
                if arg.as_ref().starts_with('-') {
                    error!("Unknown option: {}", arg.as_ref());
                    return Err(SrError::InvalidAgruments);
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
            .maybe_user(user)
            .map_err(|e| {
                error!("Error parsing user: {}", e);
                SrError::InvalidAgruments
            })?
            .maybe_group(group)
            .map_err(|e| {
                error!("Error parsing group: {}", e);
                SrError::InvalidAgruments
            })?
            .build(),
    );
    for arg in iter {
        args.cmd_args.push(escape_parser_string(arg));
    }
    Ok(args)
}

#[cfg(not(tarpaulin_include))]
fn main() {
    if let Err(e) = subsribe("sr") {
        eprintln!("sr: Failed to initialize logging: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = main_inner() {
        eprintln!("sr: {}", e);

        use nix::unistd::{Uid, User};
        if let SrError::InsufficientPrivileges = e {
            error!("Insufficient privileges to run sr. {}", CAPABILITIES_ERROR);
        } else if let SrError::AuthenticationFailed = e {
            error!(
                "Authentication failed for user '{}', when trying running '''{}'''",
                User::from_uid(Uid::current())
                    .and_then(|u| u.map(|u| u.name).ok_or(nix::errno::Errno::EAGAIN))
                    .unwrap_or(Uid::current().to_string()),
                std::env::args().skip(1).collect::<Vec<_>>().join(" ")
            );
            eprintln!("This incident is reported.");
        } else {
            error!(
                "User '{}' got a '{}' when trying running '''{}'''",
                User::from_uid(Uid::current())
                    .and_then(|u| u.map(|u| u.name).ok_or(nix::errno::Errno::EAGAIN))
                    .unwrap_or(Uid::current().to_string()),
                e,
                std::env::args().skip(1).collect::<Vec<_>>().join(" ")
            );
        }
        std::process::exit(1);
    }
}

#[cfg(not(tarpaulin_include))]
fn main_inner() -> SrResult<()> {
    use std::env;

    use crate::{pam::check_auth, ROOTASROLE};
    use finder::find_best_exec_settings;
    use nix::sys::stat::umask;

    debug!("Started with capabilities: {:?}", CapState::get_current()?);
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
    if args.del_ts {
        #[cfg(not(feature = "timeout"))]
        {
            error!("The timeout feature is not enabled, cannot delete timestamp cookie");
            return Err(SrError::InvalidAgruments);
        }
        #[cfg(feature = "timeout")]
        {
            timeout::clear_cookies(&user).map_err(|e| {
                error!("Failed to clear timestamp cookies: {}", e);
                SrError::InsufficientPrivileges
            })?;
            if args.cmd_path.as_os_str().is_empty() {
                return Ok(());
            }
        }
    }
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

    debug!("Best exec settings: {:?}", execcfg);

    check_auth(&execcfg.auth, &execcfg.timeout, &user, &args)?;

    if !execcfg.score.fully_matching() {
        println!("You are not allowed to execute this command, this incident will be reported.");
        error!(
            "User {} tried to execute command : {:?} {:?} without the permission.",
            &user.user.name, args.cmd_path, args.cmd_args
        );

        std::process::exit(1);
    }

    if args.info {
        use capctl::CapSet;
        println!(
            "Role: {}",
            if execcfg.role.is_empty() {
                "None"
            } else {
                &execcfg.role
            }
        );
        println!(
            "Task: {}",
            if execcfg.task.is_none() {
                "None"
            } else {
                &execcfg.task.as_ref().unwrap()
            }
        );
        print!(
            "Execute as user: {}",
            if let Some(u) = execcfg.cred.setuid {
                format!("{} ({})", u.name, u.uid)
            } else {
                "Your current user".to_string()
            }
        );
        if let Some(gids) = execcfg.cred.setgroups.as_ref() {
            print!(" and group(s): ");
            let groups = gids
                .iter()
                .map(|g| format!("{} ({})", g.name, g.gid))
                .collect::<Vec<_>>()
                .join(", ");
            println!("{}", groups);
        } else {
            println!(" your current group(s)");
        }
        println!(
            "With capabilities: {}",
            if execcfg.cred.caps.is_none() {
                "None".to_string()
            } else if *execcfg.cred.caps.as_ref().unwrap() == !CapSet::empty() {
                "All capabilities".to_string()
            } else {
                execcfg
                    .cred
                    .caps
                    .unwrap()
                    .into_iter()
                    .fold(String::new(), |acc, cap| acc + &cap.to_string() + " ")
                    .trim_end()
                    .to_string()
            }
        );
        println!("Command: {:?} {:?}", execcfg.final_path, args.cmd_args);
        std::process::exit(0);
    }

    // disable root
    if execcfg.root.is_user() {
        activates_no_new_privs().expect("Failed to activate no new privs");
    }

    debug!("setuid : {:?}", execcfg.cred.setuid);

    umask(execcfg.umask.into());

    setuid_setgid(&execcfg)?;

    set_capabilities(&execcfg)?;

    let pty = Pty::new().expect("Failed to create pty");

    debug!(
        "Command: {:?} {:?}",
        execcfg.final_path,
        args.cmd_args.join(" ")
    );
    let cargs = args.cmd_args.clone();
    let cfinal_path = execcfg.final_path.clone();
    let cfinal_env = execcfg.env.clone();
    let command = unsafe {
        Command::new(&execcfg.final_path)
            .pre_exec(move || {
                use crate::finder::api::{Api, ApiEvent};
                Api::notify(ApiEvent::PreExec(&args, &execcfg)).map_err(|e| {
                    error!("Failed to notify pre-exec event: {}", e);
                    std::io::Error::new(std::io::ErrorKind::Other, "Failed to notify pre-exec")
                })?;
                Ok(())
            })
            .args(cargs.iter())
            .env_clear()
            .envs(cfinal_env)
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn(&pty.pts().expect("Failed to get pts"))
    };
    let mut command = match command {
        Ok(command) => command,
        Err(e) => {
            error!("{}", e);
            eprintln!("sr: {} : {}", cfinal_path.display(), e);
            std::process::exit(1);
        }
    };
    let status = command.wait().expect("Failed to wait for command");
    std::process::exit(status.code().unwrap_or(1));
}

fn make_cred() -> Cred {
    Cred::builder()
        .maybe_tty(stat::fstat(stdout().as_raw_fd()).ok().and_then(|s| {
            if isatty(stdout().as_raw_fd()).ok().unwrap_or(false) {
                Some(s.st_rdev)
            } else {
                None
            }
        }))
        .build()
}

fn set_capabilities(execcfg: &BestExecSettings) -> SrResult<()> {
    //set capabilities
    let caps = execcfg.cred.caps.unwrap_or_default();
    // case where capabilities are more than bounding set
    let bounding = capctl::bounding::probe();
    if bounding & caps != caps {
        error!("Unable to setup the execution environment: There are more capabilities in this task than the current bounding set! You may are in a container or already in a RootAsRole session.");
        return Err(SrError::InsufficientPrivileges);
    }
    initialize_capabilities(&[Cap::SETPCAP])
        .inspect_err(|_| error!("{}", cap_effective_error("setpcap")))?;
    let mut capstate = CapState::empty();
    if execcfg.bounding.is_strict() {
        for cap in (!caps).iter() {
            capctl::bounding::drop(cap).expect("Failed to set bounding cap");
        }
    }
    capstate.effective.clear();
    capstate.permitted = caps;
    capstate.inheritable = caps;
    debug!("caps : {:?}", caps);
    capstate.set_current().expect("Failed to set current cap");
    for cap in caps.iter() {
        capctl::ambient::raise(cap).expect("Failed to set ambiant cap");
    }
    Ok(())
}

fn setuid_setgid(execcfg: &BestExecSettings) -> SrResult<()> {
    let gid = execcfg
        .cred
        .setgroups
        .as_ref()
        .and_then(|g| g.first().cloned())
        .map(|g| g.gid.as_raw());
    with_privileges(&[Cap::SETUID, Cap::SETGID], || {
        capctl::cap_set_ids(
            execcfg.cred.setuid.as_ref().map(|u| u.uid.as_raw()),
            gid,
            execcfg
                .cred
                .setgroups
                .as_ref()
                .map(|g| g.iter().map(|g| g.gid.as_raw()).collect::<Vec<_>>())
                .as_deref(),
        )?;
        Ok(())
    })
    .map_err(|e| {
        error!("{}", cap_effective_error("setuid/setgid"));
        e.into()
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::finder::de::CredOwnedData;
    use capctl::{Cap, CapSet};
    use libc::getgid;
    use nix::unistd::{getgroups, getuid, Group, Pid, User};
    use rar_common::database::options::SBounding;

    use super::*;

    fn get_non_root_uid(nth: usize) -> Option<u32> {
        // list all users
        let passwd = fs::read_to_string("/etc/passwd").unwrap();
        let passwd: Vec<&str> = passwd.split('\n').collect();
        passwd
            .iter()
            .map(|line| {
                let line: Vec<&str> = line.split(':').collect();
                line[2].parse::<u32>().unwrap()
            })
            .filter(|uid| *uid != 0)
            .nth(nth)
    }

    fn get_non_root_gid(nth: usize) -> Option<u32> {
        // list all users
        let passwd = fs::read_to_string("/etc/group").unwrap();
        let passwd: Vec<&str> = passwd.split('\n').collect();
        passwd
            .iter()
            .map(|line| {
                let line: Vec<&str> = line.split(':').collect();
                line[2].parse::<u32>().unwrap()
            })
            .filter(|uid| *uid != 0)
            .nth(nth)
    }

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
        let groups = getgroups()
            .unwrap()
            .iter()
            .map(|g| Group::from_gid(*g).unwrap().unwrap())
            .collect::<Vec<_>>();
        assert!(!user.groups.is_empty());
        assert_eq!(user.groups, groups);
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
            let execcfg = BestExecSettings::builder()
                .cred(
                    CredOwnedData::builder()
                        .setuid(
                            User::from_uid(get_non_root_uid(0).unwrap().into())
                                .unwrap()
                                .unwrap(),
                        )
                        .setgroups(vec![Group::from_gid(get_non_root_gid(0).unwrap().into())
                            .unwrap()
                            .unwrap()])
                        .build(),
                )
                .build();
            setuid_setgid(&execcfg).unwrap();
            assert_eq!(getuid(), execcfg.cred.setuid.unwrap().uid);
            if let Some(gid) = execcfg.cred.setgroups.as_ref().and_then(|g| g.first()) {
                assert_eq!(unsafe { getgid() }, gid.gid.as_raw());
            }
            capset.effective.clear();
            capset.set_current().unwrap();
        }
    }

    #[test]
    fn test_set_capabilities() {
        let mut capset = CapState::get_current().unwrap();
        if capset.permitted.has(Cap::SETPCAP)
            && capset.permitted.has(Cap::SETUID)
            && capset.permitted.has(Cap::SETGID)
        {
            capset.effective.add(Cap::SETPCAP);
            capset.set_current().unwrap();
            let mut execcfg = BestExecSettings::default();
            let mut capset = CapSet::empty();
            capset.add(Cap::SETUID);
            capset.add(Cap::SETGID);
            capset.add(Cap::SETPCAP);
            execcfg.cred.caps = Some(capset);
            set_capabilities(&execcfg).unwrap();
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
            execcfg.cred.caps = None;
            execcfg.bounding = SBounding::Strict;
            set_capabilities(&execcfg).unwrap();
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
