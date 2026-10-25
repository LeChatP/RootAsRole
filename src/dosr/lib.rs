//! dosr, executed by the `dosr` binary through [`dosr_main`].
//! It is a library so that its internals can be fuzzed in-process (see the `fuzzing` feature).
#![cfg(feature = "finder")]

// `println!` and the like panic when the output is a closed pipe (`EPIPE`, since Rust ignores
// `SIGPIPE`): outside the tests, the `*_ignore_io_error` macros of rootasrole-core are used.
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! println {
    ($($tt:tt)*) => {
        compile_error!("println! panics on EPIPE, use println_ignore_io_error!")
    };
}
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! print {
    ($($tt:tt)*) => {
        compile_error!("print! panics on EPIPE, use print_ignore_io_error!")
    };
}
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! eprintln {
    ($($tt:tt)*) => {
        compile_error!("eprintln! panics on EPIPE, use eprintln_ignore_io_error!")
    };
}
#[cfg(not(test))]
#[allow(unused_macros)]
macro_rules! eprint {
    ($($tt:tt)*) => {
        compile_error!("eprint! panics on EPIPE, use eprintln_ignore_io_error!")
    };
}

mod error;
mod finder;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
mod pam;
mod pre_exec;
mod procfs;
#[cfg(feature = "timeout")]
mod timeout;

use bon::Builder;
use capctl::{Cap, CapState};
use const_format::formatcp;
use nix::unistd::{Uid, User};
use rootasrole_core::database::options::SBounding;
use rootasrole_core::util::{initialize_capabilities, with_privileges};
use rootasrole_core::{
    Cred,
    database::{
        FilterMatcher,
        actor::{SGroupType, SGroups, SUserType},
        options::EnvBehavior,
    },
    log::subscribe,
};

use log::{debug, error, info};
use pam::PAM_PROMPT;
use rootasrole_core::{eprintln_ignore_io_error, print_ignore_io_error, println_ignore_io_error};
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::{io, process::Command};

use crate::pre_exec::{PRE_EXEC_ORCHESTRATOR, configure_pre_exec};
use rootasrole_core::util::{BOLD, RST, UNDERLINE, drop_effective};

use crate::error::SrError;
use crate::error::SrResult;
use crate::finder::de::cred::CredOwnedData;

#[cfg(not(test))]
pub(crate) const RAR_CFG_PATH: &str = env!("RAR_CFG_PATH");
#[cfg(test)]
pub(crate) const RAR_CFG_PATH: &str = "target/rootasrole.json";

#[cfg(not(test))]
pub(crate) const RAR_CFG_DATA_PATH: &str = env!("RAR_CFG_DATA_PATH");
#[cfg(test)]
pub(crate) const RAR_CFG_DATA_PATH: &str = "target/rootasrole.json";

//const ABOUT: &str = "Execute privileged commands with a role-based access control system";
//const LONG_ABOUT: &str =
//    "sr is a tool to execute privileged commands with a role-based access control system.
//It is designed to be used in a multi-user environment,
//where users can be assigned to different roles,
//and each role has a set of rights to execute commands.";
#[allow(clippy::needless_raw_string_hashes)]
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

  {BOLD}-D, --chdir <WORKDIR>{RST}
          Workdir option allows you to specify the working directory for the command

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
          Print help (see a summary with '-h')"#
);

#[derive(Debug, Builder)]
#[allow(clippy::struct_excessive_bools)]
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

    #[builder(default, with = |i : impl IntoIterator<Item = impl Into<String>> | i.into_iter().map(std::convert::Into::into).collect())]
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
        Self::builder().prompt(PAM_PROMPT).build()
    }
}

const CAPABILITIES_ERROR: &str = "You need at least dac_read_search or dac_override, setpcap and setuid capabilities to run dosr";
fn cap_effective_error(caplist: &str) -> String {
    format!("Unable to toggle {caplist} privilege. {CAPABILITIES_ERROR}")
}

/// Why dosr lacks the capabilities that it needs to run at all (see [`CAPABILITIES_ERROR`]),
/// from the state of its process: `None` when it has them.
///
/// Without them, reading the policy fails and the user would only see "Permission denied", as if
/// the policy refused the command. The usual case is dosr run from a command that dosr started:
/// with `root: user`, that command has `no_new_privs`, and under a strict bounding set it lacks
/// the capabilities dosr needs.
fn missing_privileges_reason(
    no_new_privs: bool,
    permitted: capctl::CapSet,
    bounding: capctl::CapSet,
) -> Option<String> {
    let mut missing: capctl::CapSet = [Cap::SETPCAP, Cap::SETUID]
        .into_iter()
        .filter(|cap| !permitted.has(*cap))
        .collect();
    if !permitted.has(Cap::DAC_READ_SEARCH) && !permitted.has(Cap::DAC_OVERRIDE) {
        missing.add(Cap::DAC_READ_SEARCH);
    }
    if missing.is_empty() {
        return None;
    }
    let names = |caps: capctl::CapSet| {
        caps.iter()
            .map(|cap| cap.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let outside_bounding = missing & !bounding;
    Some(if no_new_privs {
        "no_new_privs is set in this session, so the kernel does not give dosr the capabilities \
         of its file: it is set by a service with NoNewPrivileges=yes, a container, \
         setpriv --no-new-privs, or a command that dosr runs with \"root\": \"user\""
            .to_string()
    } else if !outside_bounding.is_empty() {
        format!(
            "the bounding set of this session lacks {}, which dosr needs: it is reduced by a \
             service with CapabilityBoundingSet=, a container, or a command that dosr runs with \
             a strict bounding set",
            names(outside_bounding)
        )
    } else {
        format!(
            "dosr lacks {}: its file has no capabilities (setcap '=p'), or its file system is \
             mounted nosuid",
            names(missing)
        )
    })
}

/// [`missing_privileges_reason`] for this process.
fn missing_privileges() -> Option<String> {
    let no_new_privs = capctl::prctl::get_no_new_privs().unwrap_or(false);
    let permitted = CapState::get_current()
        .map(|state| state.permitted)
        .unwrap_or_default();
    missing_privileges_reason(no_new_privs, permitted, capctl::bounding::probe())
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
    let mut workdir = None;
    let mut user: Option<SUserType> = None;
    let mut group: Option<SGroups> = None;
    let mut env = None;

    while let Some(arg) = iter.next() {
        // matches only first options
        match arg.as_ref() {
            "-u" | "--user" => {
                user = iter.next().map(|s| s.as_ref().into());
            }
            "-g" | "--group" => {
                group = iter.next().map(|s| {
                    SGroups::Multiple(
                        s.as_ref()
                            .split(',')
                            .map(std::convert::Into::into)
                            .collect::<Vec<SGroupType>>(),
                    )
                });
            }
            "-S" | "--stdin" => {
                args.stdin = true;
            }
            "-r" | "--role" => {
                role = iter.next().map(|s| s.as_ref().to_string());
            }
            "-t" | "--task" => {
                task = iter.next().map(|s| s.as_ref().to_string());
            }
            "-E" | "--preserve-env" => {
                env.replace(EnvBehavior::Keep);
            }
            "-D" | "--chdir" => {
                workdir = iter.next().map(|s| s.as_ref().to_string());
            }
            #[cfg(feature = "timeout")]
            "-K" | "--remove-timestamp" => {
                args.del_ts = true;
            }
            "-p" | "--prompt" => {
                let Some(prompt) = iter.next() else {
                    error!("Missing prompt for -p option");
                    return Err(SrError::InvalidAgruments);
                };
                args.prompt = Some(prompt.as_ref().to_string());
            }
            "-i" | "--info" => {
                args.info = true;
            }
            "-h" | "--help" => {
                args.help = true;
            }
            // the end of the options, like sudo: the next word is the command, even when it
            // starts with -
            "--" => {
                if let Some(command) = iter.next() {
                    args.cmd_path = command.as_ref().into();
                }
                break;
            }
            "-v" | "--version" => {
                println_ignore_io_error!("dosr: version {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => {
                if arg.as_ref().starts_with('-') {
                    error!("Unknown option: {}", arg.as_ref());
                    return Err(SrError::InvalidAgruments);
                }
                //else
                args.cmd_path = arg.as_ref().into();
                break;
            }
        }
    }
    args.opt_filter = Some(
        FilterMatcher::builder()
            .maybe_role(role)
            .maybe_task(task)
            .maybe_workdir(workdir)
            .maybe_env_behavior(env)
            .maybe_user(user)
            .map_err(|e| {
                error!("Error parsing user: {e}");
                SrError::InvalidAgruments
            })?
            .maybe_group(group)
            .map_err(|e| {
                error!("Error parsing group: {e}");
                SrError::InvalidAgruments
            })?
            .build(),
    );
    for arg in iter {
        args.cmd_args.push(arg.as_ref().to_string());
    }
    Ok(args)
}

#[cfg(not(tarpaulin_include))]
pub fn dosr_main() {
    if let Err(e) = subscribe("dosr") {
        eprintln_ignore_io_error!("dosr: Failed to initialize logging: {e}");
        std::process::exit(1);
    }
    if let Err(e) = main_inner() {
        eprintln_ignore_io_error!("dosr: {e}");
        // whatever the error, it comes from the missing capabilities when dosr lacks them
        let missing = missing_privileges();
        if let Some(reason) = &missing {
            eprintln_ignore_io_error!("dosr: {reason}");
        }
        if e == SrError::InsufficientPrivileges || missing.is_some() {
            error!(
                "Insufficient privileges to run dosr: {}",
                missing.as_deref().unwrap_or(CAPABILITIES_ERROR)
            );
        } else if e == SrError::AuthenticationFailed {
            error!(
                "Authentication failed for user '{}', when trying running '''{}'''",
                User::from_uid(Uid::current())
                    .and_then(|u| u.map(|u| u.name).ok_or(nix::errno::Errno::EAGAIN))
                    .unwrap_or_else(|_| Uid::current().to_string()),
                command_line()
            );
            eprintln_ignore_io_error!("This incident is reported.");
        } else {
            error!(
                "User '{}' got a '{}' when trying running '''{}'''",
                User::from_uid(Uid::current())
                    .and_then(|u| u.map(|u| u.name).ok_or(nix::errno::Errno::EAGAIN))
                    .unwrap_or_else(|_| Uid::current().to_string()),
                e,
                command_line()
            );
        }
        std::process::exit(1);
    }
}

#[cfg(not(tarpaulin_include))]
#[allow(clippy::too_many_lines)]
fn main_inner() -> SrResult<()> {
    use std::env;

    use crate::{
        RAR_CFG_PATH,
        finder::api::{Api, register_plugins},
        pam::{session_env, start_session},
    };
    use finder::find_best_exec_settings;
    use rootasrole_core::util::RAR_CFG_TYPE;

    debug!("Started with capabilities: {:?}", CapState::get_current()?);
    drop_effective()?;
    let args = utf8_args(std::env::args_os())?;
    if args.len() < 2 {
        println_ignore_io_error!("{USAGE}");
        return Ok(());
    }
    let args = getopt(args)?;

    if args.help {
        println_ignore_io_error!("{USAGE}");
        return Ok(());
    }
    let user = make_cred().map_err(|_| SrError::SystemError)?;
    if args.del_ts {
        #[cfg(not(feature = "timeout"))]
        {
            error!("The timeout feature is not enabled, cannot delete timestamp cookie");
            return Err(SrError::InvalidAgruments);
        }
        #[cfg(feature = "timeout")]
        {
            timeout::clear_cookies(&user).map_err(|e| {
                error!("Failed to clear timestamp cookies: {e}");
                SrError::InsufficientPrivileges
            })?;
            if args.cmd_path.as_os_str().is_empty() {
                return Ok(());
            }
        }
    }
    register_plugins();
    let mut execcfg = find_best_exec_settings(
        &args,
        &user,
        RAR_CFG_PATH,
        RAR_CFG_DATA_PATH,
        RAR_CFG_TYPE,
        utf8_vars(env::vars_os()),
        env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .collect::<Vec<_>>()
            .as_slice(),
    )?;

    debug!("Best exec settings: {execcfg:?}");

    // Let the PAM session live until the end of the program
    let session = start_session(
        execcfg.auth,
        &execcfg.timeout,
        execcfg.password,
        &user,
        &args,
    )?;
    // The variables that PAM modules set go through the filter of the policy, like the user's
    execcfg
        .env_filter
        .add_vars(&mut execcfg.env, session_env(&session));

    if !execcfg.score.fully_matching() {
        println_ignore_io_error!(
            "You are not allowed to execute this command, this incident will be reported."
        );
        error!(
            "User {} tried to execute command : {} {:?} without the permission.",
            &user.user.name,
            args.cmd_path.display(),
            args.cmd_args
        );

        std::process::exit(1);
    }

    // after authentication, so that the policy is not revealed, but before the execution is
    // logged as granted: these capabilities can never be granted in this session
    let missing = caps_outside_bounding(execcfg.cred.caps, capctl::bounding::probe());
    if !missing.is_empty() {
        let names = missing
            .iter()
            .map(|cap| cap.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        eprintln_ignore_io_error!(
            "dosr: the task needs capabilities that this session cannot obtain anymore: {names}"
        );
        error!(
            "User {} cannot run {} with the task {:?} of the role {}: {names} are not in the bounding set (a container, or a session started with a strict bounding set)",
            &user.user.name,
            execcfg.final_path.display(),
            execcfg.task,
            execcfg.role
        );
        std::process::exit(1);
    }

    if args.info {
        println_ignore_io_error!(
            "Role: {}",
            if execcfg.role.is_empty() {
                "None"
            } else {
                &execcfg.role
            }
        );
        println_ignore_io_error!("Task: {}", execcfg.task.as_ref().map_or("None", |v| v));
        print_ignore_io_error!(
            "Execute as user: {}",
            if let Some(u) = execcfg.cred.setuid {
                format!("{} ({})", u.name, u.uid)
            } else {
                "Your current user".to_string()
            }
        );
        if let Some(gids) = execcfg.cred.setgroups.as_ref() {
            print_ignore_io_error!(" and group(s): ");
            let groups = gids
                .iter()
                .map(|g| format!("{} ({})", g.name, g.gid))
                .collect::<Vec<_>>()
                .join(", ");
            println_ignore_io_error!("{groups}");
        } else {
            println_ignore_io_error!(" your current group(s)");
        }
        println_ignore_io_error!(
            "With capabilities: {}",
            capabilities_display(execcfg.cred.caps)
        );
        println_ignore_io_error!(
            "Command: {} {:?}",
            execcfg.final_path.display(),
            args.cmd_args
        );
        std::process::exit(0);
    }

    info!("{}", execution_log_line(&user, &execcfg, &args));

    // Build the command
    let mut command_builder = Command::new(&execcfg.final_path);

    // The command runs in the directory asked with -D, else in the one forced by the policy.
    // It is entered by the pre-exec steps, once the target user is set.
    let workdir = args
        .opt_filter
        .as_ref()
        .and_then(|f| f.workdir.as_ref())
        .map(PathBuf::from)
        .or_else(|| execcfg.workdir.clone())
        .map(|dir| CString::new(dir.into_os_string().into_vec()))
        .transpose()
        .map_err(|_| {
            error!("The working directory contains a NUL character");
            SrError::InvalidAgruments
        })?;
    configure_pre_exec(
        execcfg.umask.0,
        execcfg.cred.clone(),
        execcfg.bounding,
        execcfg.root.is_user(),
        workdir,
    );

    debug!("setuid : {:?}", execcfg.cred.setuid);

    let cargs = args.cmd_args.clone();
    let cfinal_path = execcfg.final_path.clone();
    let cfinal_env = execcfg.clone().env;

    Api::notify(finder::api::ApiEvent::PreExec(&args, &execcfg))?;

    command_builder.args(cargs.iter());
    command_builder.env_clear();
    command_builder.envs(cfinal_env);
    // We don't set stdin/out/err here, the runner handles it via PTY

    debug!(
        "Command (via Runner): {} {:?}",
        cfinal_path.display(),
        cargs.join(" ")
    );

    let status = match rootasrole_exec::runner::run(command_builder, PRE_EXEC_ORCHESTRATOR, None) {
        Ok(status) => status,
        Err(e) => {
            error!("{e}");
            eprintln_ignore_io_error!("dosr: {} : {}", cfinal_path.display(), e);
            std::process::exit(1);
        }
    };
    // drop PAM session here for underlining to the compiler that the session ends here.
    drop(session);
    exit_like(status)
}

/// How the command ended: its exit code, or the signal that killed it.
#[derive(Debug, PartialEq, Eq)]
enum CommandEnd {
    Code(i32),
    Signal(i32),
}

impl From<std::process::ExitStatus> for CommandEnd {
    fn from(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt;
        status
            .signal()
            .map_or_else(|| Self::Code(status.code().unwrap_or(1)), Self::Signal)
    }
}

/// End dosr like the command: with its exit code, or killed by the same signal, so that the
/// shell reports it (128+n), like sudo.
fn exit_like(status: std::process::ExitStatus) -> ! {
    use nix::sys::signal::{SigHandler, SigSet, Signal, raise, signal};
    match CommandEnd::from(status) {
        CommandEnd::Code(code) => std::process::exit(code),
        CommandEnd::Signal(number) => {
            if let Ok(sig) = Signal::try_from(number) {
                // SAFETY: SIG_DFL installs no handler, no code of dosr runs in a signal context
                let _ = unsafe { signal(sig, SigHandler::SigDfl) };
                let mut set = SigSet::empty();
                set.add(sig);
                let _ = set.thread_unblock();
                let _ = raise(sig);
            }
            // the signal did not end dosr: the status that a shell reports for it
            std::process::exit(128 + number)
        }
    }
}

/// The arguments of dosr: an argument that is not UTF-8 is refused, the policy matches text.
fn utf8_args(args: impl IntoIterator<Item = OsString>) -> SrResult<Vec<String>> {
    args.into_iter()
        .map(OsString::into_string)
        .collect::<Result<_, _>>()
        .map_err(|_| {
            error!("The arguments must be valid UTF-8");
            SrError::InvalidAgruments
        })
}

/// The environment of the user: a variable that is not UTF-8 is never passed to the command.
fn utf8_vars(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) -> impl Iterator<Item = (String, String)> {
    vars.into_iter()
        .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
}

/// The command line of dosr for the logs, whatever its encoding.
fn command_line() -> String {
    escape_log(
        &std::env::args_os()
            .skip(1)
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Control characters are escaped, so a user-controlled value cannot forge another log line.
fn escape_log(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| -> Box<dyn Iterator<Item = char>> {
            if c.is_control() {
                Box::new(c.escape_default())
            } else {
                Box::new(std::iter::once(c))
            }
        })
        .collect()
}

/// Name of the terminal device `dev` (e.g. `/dev/pts/3`), for the logs.
fn tty_name(dev: Option<nix::libc::dev_t>) -> String {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let Some(dev) = dev else {
        return "unknown".to_string();
    };
    ["/dev/pts", "/dev"]
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .flatten()
        .find(|entry| {
            entry
                .metadata()
                .is_ok_and(|meta| meta.file_type().is_char_device() && meta.rdev() == dev)
        })
        .map_or_else(
            || "unknown".to_string(),
            |entry| entry.path().display().to_string(),
        )
}

/// Audit line of a granted execution, in the format of sudo plus the role, task and capabilities.
fn execution_log_line(user: &Cred, execcfg: &finder::BestExecSettings, args: &Cli) -> String {
    let workdir = args
        .opt_filter
        .as_ref()
        .and_then(|f| f.workdir.as_ref())
        .map(PathBuf::from)
        .or_else(|| execcfg.workdir.clone())
        .unwrap_or_else(|| user.curdir.clone());
    let target = execcfg
        .cred
        .setuid
        .as_ref()
        .map_or_else(|| user.user.name.clone(), |u| u.name.clone());
    let groups = execcfg.cred.setgroups.as_ref().map_or_else(
        || "unchanged".to_string(),
        |groups| {
            groups
                .iter()
                .map(|g| g.name.as_str())
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    let caps = execcfg.cred.caps.map_or_else(
        || "none".to_string(),
        |caps| {
            caps.iter()
                .map(|cap| cap.to_string())
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    let command = std::iter::once(execcfg.final_path.display().to_string())
        .chain(args.cmd_args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{} : TTY={} ; PWD={} ; ROLE={} ; TASK={} ; USER={} ; GROUPS={} ; CAPS={} ; COMMAND={}",
        escape_log(&user.user.name),
        tty_name(user.tty),
        escape_log(&workdir.display().to_string()),
        escape_log(&execcfg.role),
        escape_log(execcfg.task.as_deref().unwrap_or("none")),
        escape_log(&target),
        escape_log(&groups),
        caps,
        escape_log(&command),
    )
}

fn make_cred() -> std::io::Result<Cred> {
    Ok(Cred::builder()
        .user()?
        .groups()?
        .curdir()?
        .maybe_tty(procfs::controlling_tty())
        .build())
}

/// The capabilities of the command, as `dosr -i` shows them: a task without capabilities
/// shows `None`, like a task that does not set them.
fn capabilities_display(caps: Option<capctl::CapSet>) -> String {
    match caps {
        Some(caps) if caps == !capctl::CapSet::empty() => "All capabilities".to_string(),
        Some(caps) if !caps.is_empty() => caps
            .into_iter()
            .map(|cap| cap.to_string())
            .collect::<Vec<_>>()
            .join(" "),
        _ => "None".to_string(),
    }
}

/// The capabilities of the task that the bounding set does not have anymore: no process of
/// this session can obtain them, in a container or under a strict bounding set.
fn caps_outside_bounding(caps: Option<capctl::CapSet>, bounding: capctl::CapSet) -> capctl::CapSet {
    caps.unwrap_or_default() & !bounding
}

fn set_capabilities(cred: &CredOwnedData, bounding: SBounding) -> SrResult<()> {
    //set capabilities
    let caps = cred.caps.unwrap_or_default();
    // case where capabilities are more than bounding set
    let sbounding = capctl::bounding::probe();
    if sbounding & caps != caps {
        error!(
            "Unable to setup the execution environment: There are more capabilities in this task than the current bounding set! You may are in a container or already in a RootAsRole session."
        );
        return Err(SrError::InsufficientPrivileges);
    }
    initialize_capabilities(&[Cap::SETPCAP])
        .inspect_err(|_| error!("{}", cap_effective_error("setpcap")))?;
    let mut capstate = CapState::empty();
    if bounding.is_strict() {
        for cap in (!caps).iter() {
            capctl::bounding::drop(cap)?;
        }
    }
    capstate.effective.clear();
    capstate.permitted = caps;
    capstate.inheritable = caps;
    debug!("caps : {caps:?}");
    capstate.set_current()?;
    for cap in caps.iter() {
        capctl::ambient::raise(cap)?;
    }
    Ok(())
}

fn setuid_setgid(cred: &CredOwnedData) -> SrResult<()> {
    let gid = cred
        .setgroups
        .as_ref()
        .and_then(|g| g.first().cloned())
        .map(|g| g.gid.as_raw());
    with_privileges(&[Cap::SETUID, Cap::SETGID], || {
        capctl::cap_set_ids(
            cred.setuid.as_ref().map(|u| u.uid.as_raw()),
            gid,
            cred.setgroups
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

/// Mark every file descriptor above stderr as close-on-exec, like sudo-rs `mark_fds_as_cloexec`
/// (sudo-rs/src/system/mod.rs). Unlike closing them, this keeps working the descriptor used by
/// `Command` to report an exec failure.
fn close_restrictive_fds() -> io::Result<()> {
    let lowfd: libc::c_uint = 3;
    // SAFETY: close_range only changes the flags of file descriptors, it does not touch memory.
    // The raw syscall is used because close_range is not in glibc < 2.34 nor in musl.
    let res = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            lowfd,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if res == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if !matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) {
        return Err(err);
    }
    // The kernel is older than 5.11, fall back to the list of open file descriptors
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let fd = entry?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::c_int>().ok())
            .ok_or_else(|| io::Error::other("procfs returned a non-integer fd name"))?;
        if fd >= 3 {
            // SAFETY: fcntl only sets the close-on-exec flag of this file descriptor,
            // an fd that was closed in the meantime only makes it fail with EBADF.
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
    }
    Ok(())
}

#[allow(clippy::undocumented_unsafe_blocks)]
#[cfg(test)]
mod tests {
    use std::fs;

    use crate::finder::BestExecSettings;

    use super::finder::de::cred::CredOwnedData;
    use capctl::{Cap, CapSet};
    use libc::getgid;
    use nix::unistd::{Group, Pid, User, getgroups, getuid};
    use rootasrole_core::database::options::SBounding;

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
    fn test_getopt_keeps_the_arguments_as_given() {
        // the shell already removed its quoting: the quotes that remain belong to the arguments
        let args = getopt([
            "dosr", "-r", "\"role\"", "-D", "'/tmp'", "echo", "\"a\"", "'b'", "'\"c\"'",
        ])
        .unwrap();
        let filter = args.opt_filter.unwrap();
        assert_eq!(filter.role.as_deref(), Some("\"role\""));
        assert_eq!(filter.workdir.as_deref(), Some("'/tmp'"));
        assert_eq!(args.cmd_args, ["\"a\"", "'b'", "'\"c\"'"]);
    }

    #[test]
    fn test_getopt_double_dash_ends_the_options() {
        let args = getopt(["dosr", "-r", "r1", "--", "-weird", "-l", "--"]).unwrap();
        assert_eq!(args.cmd_path, PathBuf::from("-weird"));
        assert_eq!(args.cmd_args, vec!["-l".to_string(), "--".to_string()]);
        assert_eq!(
            args.opt_filter.as_ref().and_then(|f| f.role.as_deref()),
            Some("r1")
        );
        let args = getopt(["dosr", "--", "ls", "-l"]).unwrap();
        assert_eq!(args.cmd_path, PathBuf::from("ls"));
        assert_eq!(args.cmd_args, vec!["-l".to_string()]);
        // nothing after it: no command, as without it
        let args = getopt(["dosr", "-i", "--"]).unwrap();
        assert!(args.cmd_path.as_os_str().is_empty());
        assert!(args.info);
    }

    #[test]
    fn test_getopt_missing_prompt() {
        assert!(matches!(
            getopt(["dosr", "-p"]),
            Err(SrError::InvalidAgruments)
        ));
    }

    #[test]
    fn test_utf8_args_and_vars() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = OsString::from_vec(vec![b'a', 0xff]);
        assert_eq!(
            utf8_args([OsString::from("dosr"), OsString::from("ls")]).unwrap(),
            ["dosr", "ls"]
        );
        // an argument that is not UTF-8 is refused, instead of a panic
        assert!(matches!(
            utf8_args([OsString::from("dosr"), invalid.clone()]),
            Err(SrError::InvalidAgruments)
        ));
        // a variable that is not UTF-8 is never passed to the command
        let vars: Vec<_> = utf8_vars([
            (OsString::from("KEPT"), OsString::from("value")),
            (OsString::from("BAD_VALUE"), invalid.clone()),
            (invalid, OsString::from("value")),
        ])
        .collect();
        assert_eq!(vars, [("KEPT".to_string(), "value".to_string())]);
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
    fn test_execution_log_line() {
        assert_eq!(escape_log("a\nb\tc"), "a\\nb\\tc");
        let user = Cred::builder()
            .user()
            .unwrap()
            .groups()
            .unwrap()
            .curdir()
            .unwrap()
            .build();
        let execcfg = BestExecSettings::builder()
            .final_path("/usr/bin/echo".into())
            .role("r1".into())
            .task("t1".to_string())
            .cred(
                CredOwnedData::builder()
                    .setuid(User::from_uid(0.into()).unwrap().unwrap())
                    .caps(CapSet::from_iter([Cap::NET_RAW]))
                    .build(),
            )
            .build();
        let args = getopt(["dosr", "echo", "x\nfake : TTY=pts/9 ; COMMAND=/bin/sh"]).unwrap();
        let line = execution_log_line(&user, &execcfg, &args);
        // a single line, the argument cannot forge another entry
        assert!(!line.contains('\n'));
        assert!(line.starts_with(&format!("{} : TTY=", user.user.name)));
        assert!(
            line.contains(
                " ; ROLE=r1 ; TASK=t1 ; USER=root ; GROUPS=unchanged ; CAPS=CAP_NET_RAW ; "
            )
        );
        assert!(line.ends_with("COMMAND=/usr/bin/echo x\\nfake : TTY=pts/9 ; COMMAND=/bin/sh"));
    }

    #[test]
    fn test_make_cred() {
        let user = make_cred().unwrap();
        assert_eq!(user.user.uid, getuid());
        let groups = getgroups()
            .unwrap()
            .iter()
            .map(|g| Group::from_gid(*g).unwrap().unwrap())
            .collect::<Vec<_>>();
        assert!(!user.groups.is_empty());
        assert_eq!(
            user.groups
                .iter()
                .map(|e| e.left().unwrap().clone())
                .collect::<Vec<_>>(),
            groups
        );
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
                        .setgroups(vec![
                            Group::from_gid(get_non_root_gid(0).unwrap().into())
                                .unwrap()
                                .unwrap(),
                        ])
                        .build(),
                )
                .build();
            setuid_setgid(&execcfg.cred).unwrap();
            assert_eq!(getuid(), execcfg.cred.setuid.unwrap().uid);
            if let Some(gid) = execcfg.cred.setgroups.as_ref().and_then(|g| g.first()) {
                assert_eq!(unsafe { getgid() }, gid.gid.as_raw());
            }
            capset.effective.clear();
            capset.set_current().unwrap();
        }
    }

    #[test]
    fn test_command_end() {
        use std::os::unix::process::ExitStatusExt;
        // wait statuses: exit code in the second byte, terminating signal in the low bits
        assert_eq!(
            CommandEnd::from(std::process::ExitStatus::from_raw(0)),
            CommandEnd::Code(0)
        );
        assert_eq!(
            CommandEnd::from(std::process::ExitStatus::from_raw(3 << 8)),
            CommandEnd::Code(3)
        );
        assert_eq!(
            CommandEnd::from(std::process::ExitStatus::from_raw(libc::SIGTERM)),
            CommandEnd::Signal(libc::SIGTERM)
        );
    }

    #[test]
    fn test_exit_like_a_command_killed_by_a_signal() {
        use nix::sys::{
            signal::Signal,
            wait::{WaitStatus, waitpid},
        };
        use nix::unistd::{ForkResult, fork};
        let status = std::process::Command::new("sh")
            .args(["-c", "kill -TERM $$"])
            .status()
            .unwrap();
        // SAFETY: the child only calls async-signal-safe functions (signal, pthread_sigmask,
        // raise) before the signal ends it
        match unsafe { fork() }.unwrap() {
            ForkResult::Child => exit_like(status),
            ForkResult::Parent { child } => assert_eq!(
                waitpid(child, None).unwrap(),
                WaitStatus::Signaled(child, Signal::SIGTERM, false)
            ),
        }
    }

    #[test]
    fn test_missing_privileges_reason() {
        let all = CapSet::from_iter([
            Cap::SETPCAP,
            Cap::SETUID,
            Cap::SETGID,
            Cap::DAC_READ_SEARCH,
            Cap::DAC_OVERRIDE,
        ]);
        assert_eq!(missing_privileges_reason(false, all, all), None);
        // one of the two DAC capabilities is enough to read the policy
        let only_override = CapSet::from_iter([Cap::SETPCAP, Cap::SETUID, Cap::DAC_OVERRIDE]);
        assert_eq!(
            missing_privileges_reason(false, only_override, only_override),
            None
        );
        // the file capabilities are ignored under no_new_privs
        let reason = missing_privileges_reason(true, CapSet::empty(), all).unwrap();
        assert!(reason.contains("no_new_privs"), "{reason}");
        // a reduced bounding set names what it lacks
        let bounding = CapSet::from_iter([Cap::SETPCAP, Cap::DAC_READ_SEARCH]);
        let reason = missing_privileges_reason(false, bounding, bounding).unwrap();
        assert!(reason.contains("bounding set"), "{reason}");
        assert!(reason.contains(&Cap::SETUID.to_string()), "{reason}");
        assert!(!reason.contains(&Cap::SETPCAP.to_string()), "{reason}");
        // in the bounding set but not permitted: the file of dosr
        let reason = missing_privileges_reason(false, CapSet::empty(), all).unwrap();
        assert!(reason.contains("setcap"), "{reason}");
    }

    #[test]
    fn test_capabilities_display() {
        assert_eq!(capabilities_display(None), "None");
        // "capabilities": "none" or [] in the policy
        assert_eq!(capabilities_display(Some(CapSet::empty())), "None");
        assert_eq!(
            capabilities_display(Some(!CapSet::empty())),
            "All capabilities"
        );
        let caps: CapSet = [Cap::NET_RAW, Cap::SYS_BOOT].into_iter().collect();
        assert_eq!(
            capabilities_display(Some(caps)),
            format!("{} {}", Cap::NET_RAW, Cap::SYS_BOOT)
        );
    }

    #[test]
    fn test_caps_outside_bounding() {
        use capctl::{Cap, CapSet};
        let bounding = CapSet::from_iter([Cap::NET_RAW, Cap::SETUID]);
        assert!(caps_outside_bounding(None, bounding).is_empty());
        assert!(
            caps_outside_bounding(Some(CapSet::from_iter([Cap::NET_RAW])), bounding).is_empty()
        );
        assert_eq!(
            caps_outside_bounding(
                Some(CapSet::from_iter([Cap::NET_RAW, Cap::SYS_ADMIN])),
                bounding
            ),
            CapSet::from_iter([Cap::SYS_ADMIN])
        );
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
            set_capabilities(&execcfg.cred, execcfg.bounding).unwrap();
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
            set_capabilities(&execcfg.cred, execcfg.bounding).unwrap();
            let capset = CapState::get_current().unwrap();
            assert!(!capset.permitted.has(Cap::SETUID));
        }
    }

    #[test]
    fn test_setuid_setgid_coverage() {
        let execcfg = BestExecSettings::builder()
            .cred(
                CredOwnedData::builder()
                    .setuid(
                        User::from_uid(get_non_root_uid(0).unwrap().into())
                            .unwrap()
                            .unwrap(),
                    )
                    .setgroups(vec![
                        Group::from_gid(get_non_root_gid(0).unwrap().into())
                            .unwrap()
                            .unwrap(),
                    ])
                    .build(),
            )
            .build();
        // We expect this to fail if we don't have privileges, but we want to execute the code before the failure.
        let _ = setuid_setgid(&execcfg.cred);
    }

    #[test]
    fn test_close_restrictive_fds_marks_cloexec() {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};
        let file = fs::File::open("/dev/null").unwrap();
        // dup does not keep the close-on-exec flag
        let fd = nix::unistd::dup(&file).unwrap();
        let flags = |fd| FdFlag::from_bits_truncate(fcntl(fd, FcntlArg::F_GETFD).unwrap());
        assert!(!flags(&fd).contains(FdFlag::FD_CLOEXEC));
        close_restrictive_fds().unwrap();
        assert!(flags(&fd).contains(FdFlag::FD_CLOEXEC));
    }

    #[test]
    fn test_set_capabilities_coverage() {
        let mut execcfg = BestExecSettings::default();
        let mut capset = CapSet::empty();
        capset.add(Cap::SETUID);
        execcfg.cred.caps = Some(capset);
        // We expect this to fail or succeed depending on environment, but we want to execute the code.
        let _ = set_capabilities(&execcfg.cred, execcfg.bounding);
    }
}
