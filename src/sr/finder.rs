use std::{
    cell::RefCell,
    cmp::Ordering,
    error::Error,
    fmt::{Display, Formatter},
    path::PathBuf,
    rc::{Rc, Weak},
};

use capctl::CapSet;
use glob::Pattern;
use nix::{
    libc::dev_t,
    unistd::{Group, Pid, User},
};
use pcre2::bytes::RegexBuilder;
use tracing::{debug, warn};

use crate::{
    command::parse_conf_command,
    config::{
        options::{Opt, OptStack},
        structs::{Config, Groups, Role, Task},
    },
    util::capabilities_are_exploitable,
};
use bitflags::bitflags;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MatchError {
    NoMatch,
    Conflict,
}

impl<'a> Display for MatchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchError::NoMatch => write!(f, "No match"),
            MatchError::Conflict => write!(f, "Conflict"),
        }
    }
}

impl<'a> Error for MatchError {
    fn description(&self) -> &str {
        match self {
            MatchError::NoMatch => "No match",
            MatchError::Conflict => "Conflict",
        }
    }
}

#[derive(Debug)]
pub struct Cred {
    pub user: User,
    pub groups: Vec<Group>,
    pub tty: Option<dev_t>,
    pub ppid: Pid,
}

#[derive(Clone, Debug)]
struct ExecSettings<'a> {
    exec_path: String,
    exec_args: Vec<String>,
    opt: Option<OptStack<'a>>,
    setuid: Option<String>,
    setgroups: Option<Groups>,
    caps: Option<CapSet>,
    task: Weak<RefCell<Task<'a>>>,
}

impl<'a> ExecSettings<'a> {
    fn new() -> ExecSettings<'a> {
        ExecSettings {
            exec_path: String::new(),
            exec_args: Vec::new(),
            opt: None,
            setuid: None,
            setgroups: None,
            caps: None,
            task: Weak::new(),
        }
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
#[repr(u32)]
enum UserMin {
    UserMatch,
    GroupMatch(usize),
    NoMatch,
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
#[repr(u32)]
enum SetuidMin {
    Undefined,
    NoSetuidNoSetgid,
    Setgid(usize),
    Setuid,
    SetuidSetgid(usize),
    SetgidRoot(usize),
    SetuidNotrootSetgidRoot(usize),
    SetuidRoot,
    SetuidRootSetgid(usize),
    SetuidSetgidRoot(usize),
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
pub struct CmdMin(u32);

bitflags! {

    impl CmdMin: u32 {
        const Match = 0b00001;
        const WildcardPath = 0b00010;
        const RegexArgs = 0b00100;
        const FullRegexArgs = 0b01000;
        const FullWildcardPath = 0b10000;
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
enum CapsMin {
    Undefined,
    NoCaps,
    CapsNoAdmin(usize),
    CapsAdmin(usize),
    CapsAll,
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
pub struct SecurityMin(u32);

bitflags! {

    impl SecurityMin: u32 {
        const DisableBounding = 0b00001;
        const EnableRoot = 0b00010;
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
struct Score {
    user_min: UserMin,
    cmd_min: CmdMin,
    caps_min: CapsMin,
    setuid_min: SetuidMin,
    security_min: SecurityMin,
}

impl Score {
    pub fn prettyprint(&self) -> String {
        format!(
            "{:?}, {:?}, {:?}, {:?}, {:?}",
            self.user_min, self.cmd_min, self.caps_min, self.setuid_min, self.security_min
        )
    }
}

impl<'a> PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for Score {
    fn cmp(&self, other: &Self) -> Ordering {
        self.user_min
            .cmp(&other.user_min)
            .then(self.cmd_min.cmp(&other.cmd_min))
            .then(self.caps_min.cmp(&other.caps_min))
            .then(self.setuid_min.cmp(&other.setuid_min))
            .then(self.security_min.cmp(&other.security_min))
    }

    fn max(self, other: Self) -> Self {
        std::cmp::max_by(self, other, Ord::cmp)
    }

    fn min(self, other: Self) -> Self {
        std::cmp::min_by(self, other, Ord::cmp)
    }

    fn clamp(self, min: Self, max: Self) -> Self {
        self.max(min).min(max)
    }
}

#[derive(Clone, Debug)]
pub struct TaskMatch<'a> {
    score: Score,
    settings: ExecSettings<'a>,
}

impl<'a> TaskMatch<'a> {
    pub fn file_exec_path(&self) -> &String {
        &self.settings.exec_path
    }

    pub fn exec_args(&self) -> &Vec<String> {
        &self.settings.exec_args
    }

    pub fn opt(&self) -> &Option<OptStack<'a>> {
        &self.settings.opt
    }

    pub fn setuid(&self) -> &Option<String> {
        &self.settings.setuid
    }

    pub fn setgroups(&self) -> &Option<Groups> {
        &self.settings.setgroups
    }

    pub fn caps(&self) -> &Option<CapSet> {
        &self.settings.caps
    }

    pub fn task(&self) -> Rc<RefCell<Task<'a>>> {
        self.settings.task.upgrade().expect("Internal Error")
    }

    pub fn role(&self) -> Rc<RefCell<Role<'a>>> {
        self.settings
            .task
            .upgrade()
            .expect("Internal Error")
            .as_ref()
            .borrow()
            .get_role()
            .expect("Internal Error")
    }
}

pub trait TaskMatcher<T> {
    fn matches(&self, user: &Cred, command: &[String]) -> Result<T, MatchError>;
}

trait CredMatcher {
    fn user_matches(&self, user: &Cred) -> UserMin;
}

trait RoleMatcher<'a> {
    fn command_matches(&self, user: &Cred, command: &[String])
        -> Result<TaskMatch<'a>, MatchError>;
}

fn find_from_envpath(needle: &PathBuf) -> Option<PathBuf> {
    let env_path = std::env::var_os("PATH").unwrap();
    for path in std::env::split_paths(&env_path) {
        let path = path.join(needle);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn match_path(
    input_path: &String,
    role_path: &String,
    match_status: &mut CmdMin,
) -> Result<PathBuf, Box<dyn Error>> {
    let mut new_path =
        std::fs::canonicalize(input_path).unwrap_or(PathBuf::from(input_path.clone()));
    if role_path == "**" {
        *match_status |= CmdMin::FullWildcardPath;
    }
    if !new_path.is_absolute() {
        if let Some(env_path) = find_from_envpath(&new_path) {
            new_path = env_path;
        }
    }
    let mut role_path =
        std::fs::canonicalize(role_path).unwrap_or(PathBuf::from(role_path.clone()));
    if !role_path.is_absolute() {
        if let Some(env_path) = find_from_envpath(&role_path) {
            role_path = env_path;
        }
    }
    if new_path == role_path {
        *match_status |= CmdMin::Match;
        return Ok(new_path);
    }
    if Pattern::new(role_path.to_str().unwrap())?.matches_path(&new_path) {
        *match_status |= CmdMin::WildcardPath;
        return Ok(new_path);
    }
    debug!("No match for path {:?}", new_path);
    Err(Box::new(MatchError::NoMatch))
}

/// Check if input args is matching with role args and return the score
/// role args can contains regex
/// input args is the command line args
fn match_args(input_args: &[String], role_args: &[String]) -> Result<CmdMin, Box<dyn Error>> {
    if role_args[0] == ".*" {
        return Ok(CmdMin::FullRegexArgs);
    }
    let commandline = shell_words::join(input_args);
    let role_args = shell_words::join(role_args);
    debug!("Matching args {:?} with {:?}", commandline, role_args);
    if commandline != role_args {
        debug!("test regex");
        let regex = RegexBuilder::new().build(&role_args)?;
        if regex.is_match(commandline.as_bytes())? {
            return Ok(CmdMin::RegexArgs);
        }
    } else {
        return Ok(CmdMin::Match);
    }
    debug!("No match for args {:?}", input_args);
    Err(Box::new(MatchError::NoMatch))
}

/// Check if input command line is matching with role command line and return the score
fn match_command_line(
    input_command: &[String],
    role_command: &[String],
    final_binary_path: &mut PathBuf,
) -> CmdMin {
    let mut result = CmdMin::empty();
    if !input_command.is_empty() {
        match match_path(&input_command[0], &role_command[0], &mut result) {
            Ok(final_path) => {
                *final_binary_path = final_path;
                if role_command.len() == 1 {
                    return result;
                }
            }
            Err(err) => {
                if err.downcast_ref::<MatchError>().is_none() {
                    warn!("Error: {}", err);
                }
                return CmdMin::empty();
            }
        }
        match match_args(&input_command[1..], &role_command[1..]) {
            Ok(args_result) => result |= args_result,
            Err(err) => {
                if err.downcast_ref::<MatchError>().is_none() {
                    warn!("Error: {}", err);
                }
                return CmdMin::empty();
            }
        }
    }
    result
}

/// Find the minimum score for all commands that match the input command line
fn get_cmd_min(
    input_command: &[String],
    commands: &[String],
    final_binary_path: &mut PathBuf,
) -> CmdMin {
    let mut min_score: CmdMin = CmdMin::empty();
    debug!("Commands : {:?}", commands);
    for command in commands {
        match parse_conf_command(command) {
            Ok(command) => {
                let new_score = match_command_line(input_command, &command, final_binary_path);
                debug!("Score for command {:?} is {:?}", command, new_score);
                if min_score.is_empty() || (new_score < min_score) {
                    debug!("New min score for command {:?} is {:?}", command, new_score);
                    min_score = new_score;
                }
            }
            Err(err) => {
                warn!("Error: {}", err);
            }
        }
    }
    min_score
}

fn get_caps_min(caps: &Option<CapSet>) -> CapsMin {
    match caps {
        Some(caps) => {
            if caps.is_empty() {
                CapsMin::NoCaps
            } else if *caps == !CapSet::empty() {
                CapsMin::CapsAll
            } else if capabilities_are_exploitable(caps) {
                CapsMin::CapsAdmin(caps.size())
            } else {
                CapsMin::CapsNoAdmin(caps.size())
            }
        }
        None => CapsMin::NoCaps,
    }
}

fn get_security_min(opt: &Option<Rc<RefCell<Opt>>>) -> SecurityMin {
    match opt {
        Some(opt) => {
            let opt = opt.as_ref().borrow();
            let mut result = SecurityMin::empty();
            if let Some(value) = opt.disable_bounding {
                if value {
                    result |= SecurityMin::DisableBounding;
                }
            }
            if let Some(value) = opt.allow_root {
                if value {
                    result |= SecurityMin::EnableRoot;
                }
            }
            result
        }
        None => SecurityMin::empty(),
    }
}

fn is_root(string: &String) -> bool {
    string.eq_ignore_ascii_case("root") || string == "0"
}

fn list_contains_root(list: &crate::config::structs::Groups) -> bool {
    list.groups.iter().any(is_root)
}

fn get_setuid_min(
    setuid: &Option<String>,
    setgid: &Option<crate::config::structs::Groups>,
    security_min: &SecurityMin,
) -> SetuidMin {
    match (setuid, setgid) {
        (Some(setuid), Some(setgid)) => {
            if security_min.contains(SecurityMin::EnableRoot) && is_root(setuid) {
                // user root
                if list_contains_root(setgid) {
                    //group has root
                    SetuidMin::SetuidSetgidRoot(setgid.len())
                } else {
                    SetuidMin::SetuidRootSetgid(setgid.len())
                }
            } else {
                // user not root
                if security_min.contains(SecurityMin::EnableRoot)
                    && setgid
                        .groups
                        .iter()
                        .any(|gid| gid.eq_ignore_ascii_case("root") || gid == "0")
                {
                    //group doesn't has root
                    SetuidMin::SetuidNotrootSetgidRoot(setgid.len())
                } else {
                    SetuidMin::SetuidSetgid(setgid.len())
                }
            }
        }
        (Some(setuid), None) => {
            if security_min.contains(SecurityMin::EnableRoot) && is_root(setuid) {
                SetuidMin::SetuidRoot
            } else if setuid.is_empty() {
                SetuidMin::NoSetuidNoSetgid
            } else {
                SetuidMin::Setuid
            }
        }
        (None, Some(setgid)) => {
            if security_min.contains(SecurityMin::EnableRoot) && list_contains_root(setgid) {
                SetuidMin::SetgidRoot(setgid.len())
            } else if setgid.is_empty() {
                SetuidMin::NoSetuidNoSetgid
            } else {
                SetuidMin::Setgid(setgid.len())
            }
        }
        (None, None) => SetuidMin::NoSetuidNoSetgid,
    }
}

impl<'a> TaskMatcher<TaskMatch<'a>> for Rc<RefCell<Task<'a>>> {
    fn matches(&self, _: &Cred, command: &[String]) -> Result<TaskMatch<'a>, MatchError> {
        let mut score = Score {
            user_min: UserMin::NoMatch,
            cmd_min: CmdMin::empty(),
            caps_min: CapsMin::Undefined,
            setuid_min: SetuidMin::Undefined,
            security_min: SecurityMin::empty(),
        };
        let mut final_binary_path = PathBuf::new();
        score.cmd_min = get_cmd_min(
            command,
            &self.as_ref().borrow().commands,
            &mut final_binary_path,
        );
        debug!(
            "= task {} =\nScore for command {:?} is {:?}",
            self.as_ref().borrow().id.to_string(),
            command,
            score.cmd_min
        );
        if score.cmd_min != CmdMin::empty() {
            score.caps_min = get_caps_min(&self.as_ref().borrow().capabilities);
            score.security_min = get_security_min(&self.as_ref().borrow().options);
            score.setuid_min = get_setuid_min(
                &self.as_ref().borrow().setuid,
                &self.as_ref().borrow().setgid,
                &score.security_min,
            );
            let mut settings = ExecSettings::new();
            settings.exec_path = final_binary_path.to_str().unwrap().to_string();
            settings.exec_args = command[1..].to_vec();
            settings.setuid = self.as_ref().borrow().setuid.clone();
            settings.setgroups = self.as_ref().borrow().setgid.clone();
            settings.caps = self.as_ref().borrow().capabilities;
            let stack = OptStack::from_task(self.clone());
            settings.opt = Some(stack);

            Ok(TaskMatch { score, settings })
        } else {
            Err(MatchError::NoMatch)
        }
    }
}

/// Check if user's groups is matching with any of the role's groups
fn match_groups(groups: &[Group], role_groups: &Vec<Groups>) -> bool {
    let str_groups: Groups = groups.iter().map(|g| g.name.to_string()).collect();
    for role_group in role_groups {
        if role_group.is_subset(&str_groups) {
            return true;
        }
    }
    false
}

impl CredMatcher for Rc<RefCell<crate::config::structs::Role<'_>>> {
    fn user_matches(&self, user: &Cred) -> UserMin {
        let borrow = self.as_ref().borrow();
        if borrow.user_is_forbidden(user.user.name.as_str())
            || borrow
                .groups_are_forbidden(&user.groups.iter().map(|g| g.name.to_string()).collect())
        {
            warn!("You are forbidden to use a role by a conflict of interest, please contact your administrator");
            UserMin::NoMatch
        } else if borrow.users.contains(&user.user.name) {
            UserMin::UserMatch
        } else if match_groups(&user.groups, &borrow.groups) {
            UserMin::GroupMatch(user.groups.len())
        } else {
            debug!(
                "Role {} : No match for user {} or for groups {:?}",
                self.as_ref().borrow().name,
                user.user.name,
                user.groups
            );
            UserMin::NoMatch
        }
    }
}

impl<'a> RoleMatcher<'a> for Rc<RefCell<crate::config::structs::Role<'a>>> {
    fn command_matches(
        &self,
        user: &Cred,
        command: &[String],
    ) -> Result<TaskMatch<'a>, MatchError> {
        let mut min_task = TaskMatch {
            score: Score {
                user_min: self.user_matches(user),
                cmd_min: CmdMin::empty(),
                caps_min: CapsMin::Undefined,
                setuid_min: SetuidMin::Undefined,
                security_min: SecurityMin::empty(),
            },
            settings: ExecSettings::new(),
        };
        let mut nmatch = 0;
        let borrow = self.as_ref().borrow();
        for task in borrow.tasks.iter() {
            match task.matches(user, command) {
                Ok(task_match) => {
                    debug!(
                        "if min_task.score.cmd_min.is_empty() : {}",
                        min_task.score.cmd_min.is_empty()
                    );
                    debug!(
                        "task_match.score < min_task.score : {:?} < {:?} -> {}",
                        task_match.score.prettyprint(),
                        min_task.score.prettyprint(),
                        task_match.score < min_task.score
                    );
                    if min_task.score.cmd_min.is_empty() || task_match.score < min_task.score {
                        debug!(
                            "Role {} : Match for task {}",
                            self.as_ref().borrow().name,
                            task.as_ref().borrow().id.to_string()
                        );
                        let mut task_match = task_match;
                        task_match.score.user_min = min_task.score.user_min;
                        task_match.settings.task = Rc::downgrade(task);
                        min_task = task_match;
                        nmatch = 1;
                    } else if task_match.score == min_task.score {
                        nmatch += 1;
                    }
                }
                Err(err) => match err {
                    MatchError::NoMatch => {
                        debug!(
                            "Role {} : No match for task {}",
                            self.as_ref().borrow().name,
                            task.as_ref().borrow().id.to_string()
                        );
                        continue;
                    }
                    MatchError::Conflict => {
                        debug!(
                            "Role {} : Conflict in task {}",
                            self.as_ref().borrow().name,
                            task.as_ref().borrow().id.to_string()
                        );
                        return Err(err);
                    }
                },
            };
        }
        if nmatch == 1 {
            Ok(min_task)
        } else if nmatch > 1 {
            Err(MatchError::Conflict)
        } else {
            Err(MatchError::NoMatch)
        }
    }
}

impl<'a> TaskMatcher<TaskMatch<'a>> for Rc<RefCell<crate::config::structs::Role<'a>>> {
    fn matches(&self, user: &Cred, command: &[String]) -> Result<TaskMatch<'a>, MatchError> {
        let borrow = self.as_ref().borrow();
        let mut min_role = TaskMatch {
            score: Score {
                user_min: self.user_matches(user),
                cmd_min: CmdMin::empty(),
                caps_min: CapsMin::Undefined,
                setuid_min: SetuidMin::Undefined,
                security_min: SecurityMin::empty(),
            },
            settings: ExecSettings::new(),
        };
        debug!(
            "==== Role {} ====\n score: {}",
            self.as_ref().borrow().name,
            min_role.score.prettyprint()
        );
        let mut nmatch = 0;
        if min_role.score.user_min == UserMin::NoMatch {
            return Err(MatchError::NoMatch);
        }
        match self.command_matches(user, command) {
            Ok(mut command_match) => {
                command_match.score.user_min = min_role.score.user_min;
                min_role = command_match;
                nmatch = 1;
            }
            Err(err) => {
                if err == MatchError::Conflict {
                    return Err(err);
                }
            }
        };
        debug!("search a better role in parents");
        if let Some(ref parent) = borrow.parents {
            for parent in parent.iter() {
                let parent = parent.upgrade().expect("Internal Error");
                debug!("Search in parent {}", parent.as_ref().borrow().name);
                match parent.command_matches(user, command) {
                    Ok(mut command_match) => {
                        command_match.score.user_min = min_role.score.user_min;
                        if min_role.score.cmd_min.is_empty() || command_match.score < min_role.score
                        {
                            min_role = command_match;
                            nmatch = 1;
                        } else if command_match.score == min_role.score
                            && !Rc::ptr_eq(
                                &command_match.settings.task.upgrade().unwrap(),
                                &min_role.settings.task.upgrade().unwrap(),
                            )
                        {
                            debug!("Conflict in parent {}", parent.as_ref().borrow().name);
                            debug!(
                                "{:?} == {:?}",
                                command_match
                                    .settings
                                    .task
                                    .upgrade()
                                    .unwrap()
                                    .as_ref()
                                    .borrow()
                                    .id,
                                min_role
                                    .settings
                                    .task
                                    .upgrade()
                                    .unwrap()
                                    .as_ref()
                                    .borrow()
                                    .id
                            );
                            nmatch += 1;
                        }
                    }
                    Err(err) => {
                        if err == MatchError::NoMatch {
                            continue;
                        } else {
                            return Err(err);
                        }
                    }
                }
            }
        }
        debug!("END search a better role in parents");
        if nmatch == 0 {
            Err(MatchError::NoMatch)
        } else if nmatch == 1 {
            debug!(
                "=== Role {} === : Match for task {}\nScore : {}",
                self.as_ref().borrow().name,
                min_role.task().as_ref().borrow().id.to_string(),
                min_role.score.prettyprint()
            );
            Ok(min_role)
        } else {
            Err(MatchError::Conflict)
        }
    }
}

impl<'a> TaskMatcher<TaskMatch<'a>> for Rc<RefCell<Config<'a>>> {
    fn matches(&self, user: &Cred, command: &[String]) -> Result<TaskMatch<'a>, MatchError> {
        debug!(
            "Config : Matching user {} with command {:?}",
            user.user.name, command
        );
        let mut tasks: Vec<TaskMatch<'_>> = Vec::new();
        for role in self.as_ref().borrow().roles.iter() {
            if let Ok(matched) = role.matches(user, command) {
                if tasks.is_empty() || matched.score < tasks[0].score {
                    tasks.clear();
                    tasks.push(matched);
                } else if matched.score == tasks[0].score
                    && !Rc::ptr_eq(
                        &matched.settings.task.upgrade().unwrap(),
                        &tasks[0].settings.task.upgrade().unwrap(),
                    )
                {
                    tasks.push(matched);
                }
            } // we ignore error, because it's not a match
        }
        if tasks.is_empty() {
            Err(MatchError::NoMatch)
        } else if tasks.len() > 1 {
            Err(MatchError::Conflict)
        } else {
            debug!(
                "Config : Matched user {}\n - command {:?}\n - with task {}\n - with role {}\n - with score {:?}",
                user.user.name,
                command,
                tasks[0].task().as_ref().borrow().id.to_string(),
                tasks[0].role().as_ref().borrow().name,
                tasks[0].score.prettyprint()
            );
            Ok(tasks[0].clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use capctl::Cap;
    use test_log::test;

    use crate::{config::structs::IdTask, xml_version::PACKAGE_VERSION};

    use super::*;

    #[test]
    fn test_match_path() {
        let mut result = CmdMin::empty();
        assert!(match_path(&"/bin/ls".to_string(), &"/bin/ls".to_string(), &mut result).is_ok());
        assert_eq!(result, CmdMin::Match);
    }

    #[test]
    fn test_match_args() {
        let result = match_args(
            &vec!["-l".to_string(), "-a".to_string()],
            &vec!["-l".to_string(), "-a".to_string()],
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::Match);
    }

    #[test]
    fn test_match_command_line() {
        let mut final_binary_path = PathBuf::new();
        let result = match_command_line(
            &vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()],
            &vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()],
            &mut final_binary_path,
        );
        assert_eq!(result, CmdMin::Match);
        assert_eq!(final_binary_path, PathBuf::from("/usr/bin/ls"));
    }

    #[test]
    fn test_get_cmd_min() {
        let mut final_binary_path = PathBuf::new();
        let result = get_cmd_min(
            &vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()],
            &vec![
                "/bin/l*".to_string(),
                "/bin/ls .*".to_string(),
                "/bin/ls -l -a".to_string(),
            ],
            &mut final_binary_path,
        );
        assert_eq!(result, CmdMin::Match);
        assert_eq!(final_binary_path, PathBuf::from("/usr/bin/ls"));
    }

    #[test]
    fn test_get_caps_min_all() {
        let caps = !CapSet::empty();
        assert_eq!(get_caps_min(&Some(caps)), CapsMin::CapsAll);
    }

    #[test]
    fn test_get_caps_min_no_admin() {
        let mut caps = CapSet::empty();
        caps.add(Cap::NET_BIND_SERVICE);
        assert_eq!(get_caps_min(&Some(caps)), CapsMin::CapsNoAdmin(1));
    }

    #[test]
    fn test_get_caps_min_admin() {
        let mut caps = CapSet::empty();
        caps.add(Cap::SYS_ADMIN);
        assert_eq!(get_caps_min(&Some(caps)), CapsMin::CapsAdmin(1));
    }

    #[test]
    fn test_get_caps_min_no_caps() {
        assert_eq!(get_caps_min(&None), CapsMin::NoCaps);
    }

    #[test]
    fn test_get_security_min() {
        let mut opt = Opt::new(crate::config::options::Level::Default);
        opt.disable_bounding = Some(true);
        opt.allow_root = Some(true);
        assert_eq!(
            get_security_min(&Some(Rc::new(RefCell::new(opt)))),
            SecurityMin::DisableBounding | SecurityMin::EnableRoot
        );
    }

    #[test]
    fn test_is_root() {
        assert!(is_root(&"root".to_string()));
        assert!(is_root(&"0".to_string()));
        assert!(!is_root(&"1".to_string()));
    }

    #[test]
    fn test_list_contains_root() {
        let mut list = Groups { groups: Vec::new() };
        list.groups.push("root".to_string());
        assert!(list_contains_root(&list));
        list.groups.clear();
        list.groups.push("0".to_string());
        assert!(list_contains_root(&list));
        list.groups.clear();
        list.groups.push("1".to_string());
        assert!(!list_contains_root(&list));
    }

    #[test]
    fn test_get_setuid_min() {
        let mut setuid = Some("root".to_string());
        let mut setgid = Some(Groups {
            groups: vec!["root".to_string()],
        });
        let security_min = SecurityMin::EnableRoot;
        assert_eq!(
            get_setuid_min(&setuid, &setgid, &security_min),
            SetuidMin::SetuidSetgidRoot(1)
        );
        setuid = Some("1".to_string());
        assert_eq!(
            get_setuid_min(&setuid, &setgid, &security_min),
            SetuidMin::SetuidNotrootSetgidRoot(1)
        );
        setgid = Some(Groups {
            groups: vec!["1".to_string(), "2".to_string()],
        });
        assert_eq!(
            get_setuid_min(&setuid, &setgid, &security_min),
            SetuidMin::SetuidSetgid(2)
        );
        assert_eq!(
            get_setuid_min(&None, &setgid, &security_min),
            SetuidMin::Setgid(2)
        );
        assert_eq!(
            get_setuid_min(&None, &None, &security_min),
            SetuidMin::NoSetuidNoSetgid
        );
        assert_eq!(
            get_setuid_min(&setuid, &None, &security_min),
            SetuidMin::Setuid
        )
    }

    #[test]
    fn test_score_cmp() {
        let score1 = Score {
            user_min: UserMin::UserMatch,
            cmd_min: CmdMin::Match,
            caps_min: CapsMin::CapsAll,
            setuid_min: SetuidMin::SetuidSetgidRoot(1),
            security_min: SecurityMin::DisableBounding | SecurityMin::EnableRoot,
        };
        let mut score2 = Score {
            user_min: UserMin::UserMatch,
            cmd_min: CmdMin::Match,
            caps_min: CapsMin::CapsAll,
            setuid_min: SetuidMin::SetuidSetgidRoot(1),
            security_min: SecurityMin::DisableBounding,
        };
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        assert_eq!(score2.cmp(&score1), Ordering::Less);
        assert_eq!(score1.max(score2), score1);
        assert_eq!(score1.min(score2), score2);
        assert_eq!(score1.clamp(score2, score1), score1);
        assert_eq!(score1.clamp(score2, score2), score2);
        score2.security_min = SecurityMin::DisableBounding | SecurityMin::EnableRoot;
        assert_eq!(score1.cmp(&score2), Ordering::Equal);
        score2.setuid_min = SetuidMin::SetuidSetgidRoot(2);
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.setuid_min = SetuidMin::SetuidNotrootSetgidRoot(2);
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        score2.setuid_min = SetuidMin::SetuidRootSetgid(2);
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        score2.setuid_min = SetuidMin::SetuidSetgid(2);
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        score2.setuid_min = SetuidMin::SetuidSetgidRoot(1);
        score2.caps_min = CapsMin::CapsAdmin(1);
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        score2.caps_min = CapsMin::CapsNoAdmin(1);
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        score2.caps_min = CapsMin::NoCaps;
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        score2.caps_min = CapsMin::CapsAll;
        assert_eq!(score1.cmp(&score2), Ordering::Equal);
        score2.cmd_min = CmdMin::FullWildcardPath;
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.cmd_min = CmdMin::WildcardPath;
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.cmd_min = CmdMin::RegexArgs;
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.cmd_min = CmdMin::FullRegexArgs;
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.cmd_min = CmdMin::Match;
        assert_eq!(score1.cmp(&score2), Ordering::Equal);
        score2.user_min = UserMin::GroupMatch(1);
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.user_min = UserMin::NoMatch;
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.user_min = UserMin::UserMatch;
        assert_eq!(score1.cmp(&score2), Ordering::Equal);
    }

    fn setup_test_config(num_roles: usize) -> Rc<RefCell<Config<'static>>> {
        let config = Config::new(PACKAGE_VERSION);
        for i in 0..num_roles {
            let role = Role::new(format!("role{}", i), Some(Rc::downgrade(&config)));
            config.as_ref().borrow_mut().roles.push(role);
        }
        config
    }

    fn setup_test_role(
        num_tasks: usize,
        role: Option<Rc<RefCell<Role<'static>>>>,
        with_config: Option<Rc<RefCell<Config<'static>>>>,
    ) -> Rc<RefCell<Role<'static>>> {
        let role = role.unwrap_or(Role::new(
            "test".to_string(),
            with_config.and_then(|c| Some(Rc::downgrade(&c))),
        ));
        for i in 0..num_tasks {
            let task = Task::new(
                IdTask::Name(format!("{}_task_{}", role.as_ref().borrow().name, i)),
                Rc::downgrade(&role),
            );
            role.as_ref().borrow_mut().tasks.push(task);
        }
        role
    }

    #[test]
    fn test_matcher_matches() {
        let config = setup_test_config(2);
        let role1 = setup_test_role(2, Some(config.as_ref().borrow().roles[0].clone()), None);
        let r1_task1 = role1.as_ref().borrow().tasks[0].clone();
        let r1_task2 = role1.as_ref().borrow().tasks[1].clone();
        let role2 = setup_test_role(2, Some(config.as_ref().borrow().roles[1].clone()), None);
        let r2_task1 = role2.as_ref().borrow().tasks[0].clone();
        let r2_task2 = role2.as_ref().borrow().tasks[1].clone();

        // every tasks matches but not at the same score, so the least one is matched
        role1.as_ref().borrow_mut().users.push("root".to_string());
        role2.as_ref().borrow_mut().users.push("root".to_string());

        //resolve conflict if two roles returns same tasks because of parents
        role2.as_ref().borrow_mut().parents = Some(vec![Rc::downgrade(&role1)]);

        r1_task1
            .as_ref()
            .borrow_mut()
            .commands
            .push("/bin/ls -l -a".to_string()); // candidate
        r1_task2
            .as_ref()
            .borrow_mut()
            .commands
            .push("/bin/ls .*".to_string()); // regex args > r1_task1

        r2_task1
            .as_ref()
            .borrow_mut()
            .commands
            .push("/bin/ls -l -a".to_string()); //AllCaps > r1_task1
        r2_task2
            .as_ref()
            .borrow_mut()
            .commands
            .push("/bin/ls -l -a".to_string()); //One Capability > r1_task1

        r2_task1.as_ref().borrow_mut().capabilities = Some(!CapSet::empty());
        let mut capset = CapSet::empty();
        capset.add(Cap::SYS_ADMIN);
        r2_task2.as_ref().borrow_mut().capabilities = Some(capset);

        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(),
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };

        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];

        let result = config.matches(&cred, &command);
        debug!("Result : {:?}", result);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(
            result.task().as_ref().borrow().id,
            IdTask::Name("role0_task_0".to_string())
        );
        assert_eq!(result.role().as_ref().borrow().name, "role0");
    }
}
