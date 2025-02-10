use std::{
    cell::RefCell,
    cmp::Ordering,
    error::Error,
    fmt::{Display, Formatter},
    path::PathBuf,
    rc::{Rc, Weak},
};

use bon::Builder;
use capctl::CapSet;
use glob::Pattern;
use log::{debug, warn};
use nix::{
    libc::dev_t,
    unistd::{Gid, Group, Pid, Uid, User},
};
#[cfg(feature = "pcre2")]
use pcre2::bytes::RegexBuilder;

use strum::EnumIs;

use crate::database::{
    actor::SActor,
    options::{Opt, OptStack},
    structs::{SCommand, SCommands, SConfig, SRole, STask, SUserChooser, SetBehavior},
};
use crate::util::{capabilities_are_exploitable, final_path, parse_conf_command};
use crate::{
    api::{PluginManager, PluginResultAction},
    as_borrow,
};
use bitflags::bitflags;

use super::{
    actor::{SGroupType, SGroups, SUserType},
    options::EnvBehavior,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MatchError {
    NoMatch,
    Conflict,
}

impl Display for MatchError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchError::NoMatch => write!(f, "No match"),
            MatchError::Conflict => write!(f, "Conflict"),
        }
    }
}

impl Error for MatchError {
    fn description(&self) -> &str {
        match self {
            MatchError::NoMatch => "No match",
            MatchError::Conflict => "Conflict",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExecSettings {
    pub exec_path: PathBuf,
    pub exec_args: Vec<String>,
    pub opt: OptStack,
    pub setuid: Option<SUserType>,
    pub setgroups: Option<SGroups>,
    pub caps: Option<CapSet>,
    pub task: Weak<RefCell<STask>>,
}

impl ExecSettings {
    fn new() -> ExecSettings {
        ExecSettings {
            exec_path: PathBuf::new(),
            exec_args: Vec::new(),
            opt: OptStack::default(),
            setuid: None,
            setgroups: None,
            caps: None,
            task: Weak::new(),
        }
    }

    pub fn task(&self) -> Rc<RefCell<STask>> {
        self.task.upgrade().expect("Internal Error")
    }

    pub fn role(&self) -> Rc<RefCell<SRole>> {
        self.task()
            .as_ref()
            .borrow()
            .role()
            .expect("Internal Error")
    }
}

impl PartialEq for ExecSettings {
    fn eq(&self, other: &Self) -> bool {
        // We ignore the task field
        let res = self.exec_path == other.exec_path
            && self.exec_args == other.exec_args
            && self.opt == other.opt
            && self.setuid == other.setuid
            && self.setgroups == other.setgroups
            && self.caps == other.caps;
        debug!(
            "Comparing self.exec_path == other.exec_path : {}
        && self.exec_args == other.exec_args : {}
        && self.opt == other.opt : {}
        && self.setuid == other.setuid : {}
        && self.setgroups == other.setgroups : {}
        && self.caps == other.caps : {}",
            self.exec_path == other.exec_path,
            self.exec_args == other.exec_args,
            self.opt == other.opt,
            self.setuid == other.setuid,
            self.setgroups == other.setgroups,
            self.caps == other.caps
        );
        res
    }
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug, EnumIs)]
#[repr(u32)]
// Matching user groups for the role
pub enum ActorMatchMin {
    UserMatch,
    GroupMatch(usize),
    NoMatch,
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]

// Matching setuid and setgid for the role
struct SetuidMin {
    is_root: bool,
}
#[derive(PartialEq, PartialOrd, Eq, Clone, Copy, Debug)]
struct SetgidMin {
    is_root: bool,
    nb_groups: usize,
}
impl Ord for SetgidMin {
    fn cmp(&self, other: &Self) -> Ordering {
        self.is_root
            .cmp(&other.is_root)
            .then_with(|| self.nb_groups.cmp(&other.nb_groups))
    }
}
#[derive(PartialEq, PartialOrd, Eq, Clone, Copy, Debug, Default)]
pub struct SetUserMin {
    uid: Option<SetuidMin>,
    gid: Option<SetgidMin>,
}
impl Ord for SetUserMin {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uid
            .cmp(&other.uid)
            .then_with(|| self.gid.cmp(&other.gid))
    }
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
pub enum CapsMin {
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
        const DisableBounding   = 0b000001;
        const EnableRoot        = 0b000010;
        const KeepEnv           = 0b000100;
        const KeepPath          = 0b001000;
        const KeepUnsafePath    = 0b010000;
        const SkipAuth          = 0b100000;
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct Score {
    pub user_min: ActorMatchMin,
    pub cmd_min: CmdMin,
    pub caps_min: CapsMin,
    pub setuser_min: SetUserMin,
    pub security_min: SecurityMin,
}

impl Score {
    pub fn prettyprint(&self) -> String {
        format!(
            "{:?}, {:?}, {:?}, {:?}, {:?}",
            self.user_min, self.cmd_min, self.caps_min, self.setuser_min, self.security_min
        )
    }

    pub fn user_cmp(&self, other: &Score) -> Ordering {
        self.user_min.cmp(&other.user_min)
    }

    /// Compare the score of tasks results
    pub fn cmd_cmp(&self, other: &Score) -> Ordering {
        self.cmd_min
            .cmp(&other.cmd_min)
            .then(self.caps_min.cmp(&other.caps_min))
            .then(self.setuser_min.cmp(&other.setuser_min))
            .then(self.security_min.cmp(&other.security_min))
    }
}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Score {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmd_cmp(other).then(self.user_cmp(other))
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

#[derive(Debug, Builder)]
pub struct Cred {
    #[builder(field)]
    pub groups: Vec<Group>,
    #[builder(field = User::from_uid(Uid::current()).unwrap().unwrap())]
    pub user: User,
    pub tty: Option<dev_t>,
    #[builder(default = nix::unistd::getppid(), into)]
    pub ppid: Pid,
}

impl<S: cred_builder::State> CredBuilder<S> {
    pub fn user_id(mut self, uid: impl Into<Uid>) -> Self {
        self.user = User::from_uid(uid.into()).unwrap().unwrap();
        self
    }
    pub fn user_name(mut self, name: impl Into<String>) -> Self {
        self.user = User::from_name(&name.into()).unwrap().unwrap();
        self
    }
    pub fn group_id(mut self, gid: impl Into<Gid>) -> Self {
        self.groups
            .push(Group::from_gid(gid.into()).unwrap().unwrap());
        self
    }
    pub fn group_name(mut self, name: impl Into<String>) -> Self {
        self.groups
            .push(Group::from_name(&name.into()).unwrap().unwrap());
        self
    }
    pub fn groups(mut self, groups: Vec<Gid>) -> Self {
        self.groups = groups
            .iter()
            .map(|gid| Group::from_gid(*gid).unwrap().unwrap())
            .collect();
        self
    }
}

#[derive(Clone, Debug)]
pub struct TaskMatch {
    pub score: Score,
    pub settings: ExecSettings,
}

impl TaskMatch {
    pub fn fully_matching(&self) -> bool {
        self.user_matching() && self.command_matching()
    }

    pub fn user_matching(&self) -> bool {
        self.score.user_min != ActorMatchMin::NoMatch
    }

    pub fn command_matching(&self) -> bool {
        !self.score.cmd_min.is_empty()
    }

    pub fn task(&self) -> Rc<RefCell<STask>> {
        self.settings.task.upgrade().expect("Internal Error")
    }

    pub fn role(&self) -> Rc<RefCell<SRole>> {
        self.task()
            .as_ref()
            .borrow()
            .role()
            .expect("Internal Error")
    }
}

impl Default for TaskMatch {
    fn default() -> Self {
        TaskMatch {
            score: Score {
                user_min: ActorMatchMin::NoMatch,
                cmd_min: CmdMin::empty(),
                caps_min: CapsMin::Undefined,
                setuser_min: SetUserMin::default(),
                security_min: SecurityMin::empty(),
            },
            settings: ExecSettings::new(),
        }
    }
}

#[derive(Debug, Default, Builder)]
#[builder(on(_, overwritable))]
pub struct FilterMatcher {
    pub role: Option<String>,
    pub task: Option<String>,
    pub env_behavior: Option<EnvBehavior>,
    #[builder(into)]
    pub user: Option<SUserType>,
}

pub trait TaskMatcher<T> {
    fn matches(
        &self,
        user: &Cred,
        cmd_opt: &Option<FilterMatcher>,
        command: &[String],
    ) -> Result<T, MatchError>;
}

pub trait CredMatcher {
    fn user_matches(&self, user: &Cred) -> ActorMatchMin;
}

fn find_from_envpath(needle: &PathBuf) -> Option<PathBuf> {
    if needle.is_absolute() {
        return None;
    }
    let env_path = std::env::var_os("PATH").unwrap();
    for path in std::env::split_paths(&env_path) {
        let path = path.join(needle);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

fn match_path(input_path: &String, role_path: &String) -> CmdMin {
    if role_path == "**" {
        return CmdMin::FullWildcardPath;
    }
    let mut match_status = CmdMin::empty();
    let new_path = final_path(input_path);
    let role_path = final_path(role_path);
    debug!("Matching path {:?} with {:?}", new_path, role_path);
    if new_path == role_path {
        match_status |= CmdMin::Match;
    } else if let Ok(pattern) = Pattern::new(role_path.to_str().unwrap()) {
        if pattern.matches_path(&new_path) {
            match_status |= CmdMin::WildcardPath;
        }
    }
    if match_status.is_empty() {
        debug!(
            "No match for path ``{:?}`` for evaluated path : ``{:?}``",
            new_path, role_path
        );
    }
    match_status
}

/// Check if input args is matching with role args and return the score
/// role args can contains regex
/// input args is the command line args
fn match_args(input_args: &[String], role_args: &[String]) -> Result<CmdMin, Box<dyn Error>> {
    if role_args[0] == ".*" {
        return Ok(CmdMin::FullRegexArgs);
    }
    let commandline = input_args.join(" ");
    let role_args = role_args.join(" ");
    debug!("Matching args {:?} with {:?}", commandline, role_args);
    if commandline != role_args {
        debug!("test regex");
        evaluate_regex_cmd(role_args, commandline).inspect_err(|e| {
            debug!("{:?},No match for args {:?}", e, input_args);
        })
    } else {
        Ok(CmdMin::Match)
    }
}

#[cfg(feature = "pcre2")]
fn evaluate_regex_cmd(role_args: String, commandline: String) -> Result<CmdMin, Box<dyn Error>> {
    let regex = RegexBuilder::new().build(&role_args)?;
    if regex.is_match(commandline.as_bytes())? {
        Ok(CmdMin::RegexArgs)
    } else {
        Err(Box::new(MatchError::NoMatch))
    }
}

#[cfg(not(feature = "pcre2"))]
fn evaluate_regex_cmd(_role_args: String, _commandline: String) -> Result<CmdMin, Box<dyn Error>> {
    Err(Box::new(MatchError::NoMatch))
}

/// Check if input command line is matching with role command line and return the score
fn match_command_line(input_command: &[String], role_command: &[String]) -> CmdMin {
    let mut result = CmdMin::empty();
    if !input_command.is_empty() {
        result = match_path(&input_command[0], &role_command[0]);
        if result.is_empty() || role_command.len() == 1 {
            return result;
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
fn get_cmd_min(input_command: &[String], commands: &[SCommand]) -> CmdMin {
    let mut min_score: CmdMin = CmdMin::empty();
    debug!("Input {:?} matches with {:?}", input_command, commands);
    for command in commands {
        match parse_conf_command(command) {
            Ok(command) => {
                let new_score = match_command_line(input_command, &command);
                debug!("Score for command {:?} is {:?}", command, new_score);
                if !new_score.is_empty() && (min_score.is_empty() || (new_score < min_score)) {
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
            if let Some(value) = opt.bounding {
                if value.is_strict() {
                    result |= SecurityMin::DisableBounding;
                }
            }
            if let Some(value) = opt.root {
                if value.is_privileged() {
                    result |= SecurityMin::EnableRoot;
                }
            }
            if let Some(value) = &opt.path {
                if value.default_behavior.is_keep_unsafe() {
                    result |= SecurityMin::KeepUnsafePath;
                } else if value.default_behavior.is_keep_safe() {
                    result |= SecurityMin::KeepPath;
                }
            }
            if let Some(value) = &opt.env {
                if value.default_behavior.is_keep() {
                    result |= SecurityMin::KeepEnv;
                }
            }
            if opt.authentication.is_some_and(|auth| auth.is_skip()) {
                result |= SecurityMin::SkipAuth;
            }
            result
        }
        None => SecurityMin::empty(),
    }
}

fn group_is_root(actortype: &SGroupType) -> bool {
    (*actortype).fetch_id().map_or(false, |id| id == 0)
}

fn user_is_root(actortype: &SUserType) -> bool {
    (*actortype).fetch_id().map_or(false, |id| id == 0)
}

fn groups_contains_root(list: Option<&SGroups>) -> bool {
    if let Some(list) = list {
        match list {
            SGroups::Single(group) => group_is_root(&group),
            SGroups::Multiple(groups) => groups.iter().any(group_is_root),
        }
    } else {
        false
    }
}

fn groups_len(groups: Option<&SGroups>) -> usize {
    match groups {
        Some(groups) => groups.len(),
        None => 0,
    }
}

fn get_setuid_min(
    setuid: Option<&SUserType>,
    setgid: Option<&SGroups>,
    security_min: &SecurityMin,
) -> SetUserMin {
    match (setuid, setgid) {
        (Some(setuid), setgid) => {
            if security_min.contains(SecurityMin::EnableRoot) {
                // root is privileged
                if user_is_root(setuid) {
                    if groups_contains_root(setgid) {
                        SetUserMin {
                            uid: Some(SetuidMin { is_root: true }),
                            gid: Some(SetgidMin {
                                is_root: true,
                                nb_groups: (groups_len(setgid)),
                            }),
                        }
                    } else if setgid.is_none() || groups_len(setgid) == 0 {
                        SetUserMin {
                            uid: Some(SetuidMin { is_root: true }),
                            gid: None,
                        }
                    } else {
                        SetUserMin {
                            uid: Some(SetuidMin { is_root: true }),
                            gid: Some(SetgidMin {
                                is_root: false,
                                nb_groups: (groups_len(setgid)),
                            }),
                        }
                    }
                } else if groups_contains_root(setgid) {
                    SetUserMin {
                        uid: Some(SetuidMin { is_root: false }),
                        gid: Some(SetgidMin {
                            is_root: true,
                            nb_groups: (groups_len(setgid)),
                        }),
                    }
                } else if setgid.is_none() || groups_len(setgid) == 0 {
                    SetUserMin {
                        uid: Some(SetuidMin { is_root: false }),
                        gid: None,
                    }
                } else {
                    SetUserMin {
                        uid: Some(SetuidMin { is_root: false }),
                        gid: Some(SetgidMin {
                            is_root: false,
                            nb_groups: (groups_len(setgid)),
                        }),
                    }
                }
            } else {
                // root is a user
                SetUserMin {
                    uid: Some(SetuidMin { is_root: false }),
                    gid: Some(SetgidMin {
                        is_root: false,
                        nb_groups: (groups_len(setgid)),
                    }),
                }
            }
        }
        (None, setgid) => {
            let len = groups_len(setgid);
            if len == 0 {
                SetUserMin {
                    uid: None,
                    gid: None,
                }
            } else if security_min.contains(SecurityMin::EnableRoot) && groups_contains_root(setgid)
            {
                SetUserMin {
                    uid: None,
                    gid: Some(SetgidMin {
                        is_root: true,
                        nb_groups: len,
                    }),
                }
            } else {
                SetUserMin {
                    uid: None,
                    gid: Some(SetgidMin {
                        is_root: false,
                        nb_groups: len,
                    }),
                }
            }
        }
    }
}

impl TaskMatcher<TaskMatch> for Rc<RefCell<STask>> {
    fn matches(
        &self,
        user: &Cred,
        cmd_opt: &Option<FilterMatcher>,
        command: &[String],
    ) -> Result<TaskMatch, MatchError> {
        if let Some(cmd_opt) = cmd_opt {
            if let Some(task) = &cmd_opt.task {
                if task != &self.as_ref().borrow().name.to_string() {
                    debug!("Task {} does not match", self.as_ref().borrow().name);
                    return Err(MatchError::NoMatch);
                }
            }
        }
        debug!("Matching task {}", self.as_ref().borrow().name);

        // Match initial task commands
        let TaskMatch {
            mut score,
            mut settings,
        } = self
            .as_ref()
            .borrow()
            .commands
            .matches(user, cmd_opt, command)?;

        // Process capabilities and security
        let capset = self
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .map(|caps| caps.to_capset());
        score.caps_min = get_caps_min(&capset);
        score.security_min = get_security_min(&self.as_ref().borrow().options);
        if cmd_opt
            .as_ref()
            .and_then(|filter| filter.env_behavior) // if the command wants to override the behavior
            .as_ref()
            .is_some_and(|behavior| {
                settings
                    .opt
                    .to_opt() // at this point we own the opt structure
                    .as_ref()
                    .borrow()
                    .env
                    .as_ref()
                    .is_some_and(|env| !env.override_behavior || env.default_behavior == *behavior)
                // but the polcy deny it and the behavior is not the same as the default one
                // we return NoMatch
                // (explaination: if the behavior is the same as the default one, we don't override it)
            })
        {
            return Err(MatchError::NoMatch);
        }
        // Processing setuid
        let setuid: Option<SUserChooser> = self.as_ref().borrow().cred.setuid.clone();
        let setuid_result = match setuid {
            Some(SUserChooser::Actor(s)) => Some(s),
            Some(SUserChooser::ChooserStruct(t)) => {
                match cmd_opt.as_ref().and_then(|cmd| cmd.user.as_ref()) {
                    None => {
                        println!(
                            "Aucun utilisateur spécifié dans la commande, fallback utilisé : {:?}",
                            t.fallback
                        );
                        Some(t.fallback.clone()) // Retourne le fallback si aucun utilisateur n'est spécifié
                    }
                    Some(user) => {
                        println!("Utilisateur spécifié dans la commande : {}", user);

                        // Comparer l'utilisateur spécifié avec le fallback
                        if user.fetch_eq(&t.fallback) {
                            println!(
                                "L'utilisateur spécifié dans la commande correspond au fallback !"
                            );
                            Some(t.fallback.clone()) // Si l'utilisateur correspond au fallback, utiliser le fallback
                        } else if t.sub.iter().any(|s| s.fetch_eq(&user)) {
                            // Si l'utilisateur est explicitement autorisé dans `add`
                            return Err(MatchError::NoMatch);
                        } else if t.add.iter().any(|s| s.fetch_eq(&user)) {
                            // Si l'utilisateur est explicitement interdit dans `sub`
                            println!("L'utilisateur est interdit dans sub.");
                            Some(user.clone()) // Retourner une erreur immédiate
                        } else {
                            // Aucun match explicite, appliquer le comportement par défaut
                            match t.default {
                                SetBehavior::None => {
                                    println!("Aucun comportement par défaut applicable.");
                                    return Err(MatchError::NoMatch); // Aucun utilisateur par défaut
                                }
                                SetBehavior::All => {
                                    println!("Tous les utilisateurs sont acceptés.");
                                    Some(user.clone()) // Tout utilisateur accepté
                                }
                            }
                        }
                    }
                }
            }
            None => None,
        };

        // Set gid processing
        let setgid = &self.as_ref().borrow().cred.setgid;

        // Calculate setuid and setgid minimum
        score.setuser_min =
            get_setuid_min(setuid_result.as_ref(), setgid.as_ref(), &score.security_min);

        // Update task settings
        settings.setuid = setuid_result.clone();
        settings.setgroups = setgid.clone();
        settings.caps = capset;

        // Get options stack from the task
        let stack = OptStack::from_task(self.clone());
        settings.opt = stack;

        // Return the final TaskMatch
        Ok(TaskMatch { score, settings })
    }
}

fn get_default_behavior(commands: &Option<SetBehavior>) -> &SetBehavior {
    match commands.as_ref() {
        Some(commands) => commands,
        None => &SetBehavior::None,
    }
}

impl TaskMatcher<TaskMatch> for SCommands {
    fn matches(
        &self,
        _: &Cred,
        _: &Option<FilterMatcher>,
        input_command: &[String],
    ) -> Result<TaskMatch, MatchError> {
        let min_score: CmdMin;
        let mut settings = ExecSettings::new();
        // if the command is forbidden, we return NoMatch
        debug!("Checking if command is forbidden");
        let is_forbidden = get_cmd_min(input_command, &self.sub);
        if !is_forbidden.is_empty() {
            debug!("Command is forbidden");
            return Err(MatchError::NoMatch);
        }
        // otherwise, we check if behavior is No command allowed by default
        if get_default_behavior(&self.default_behavior).is_none() {
            debug!("Checking if command is allowed by default");
            // if the behavior is No command by default, we check if the command is allowed explicitly.
            min_score = get_cmd_min(input_command, &self.add);
            if min_score.is_empty() {
                return Err(MatchError::NoMatch);
            }
        } else {
            min_score = CmdMin::all();
            debug!("Command is allowed by default");
        }

        if let Some(program) =
            find_from_envpath(&input_command[0].parse().expect("The path is not valid"))
        {
            settings.exec_path = program;
            settings.exec_args = input_command[1..].to_vec();
        } else {
            // encapsulate the command in sh command
            settings.exec_path = PathBuf::from("/bin/sh");
            settings.exec_args = vec!["-c".to_string(), shell_words::join(input_command)];
        }

        Ok(TaskMatch {
            score: Score {
                user_min: ActorMatchMin::NoMatch,
                cmd_min: min_score,
                caps_min: CapsMin::Undefined,
                setuser_min: SetUserMin::default(),
                security_min: SecurityMin::empty(),
            },
            settings,
        })
    }
}

/// Check if user's groups is matching with any of the role's groups
fn match_groups(groups: &[Group], role_groups: &[SGroups]) -> bool {
    for role_group in role_groups {
        if match role_group {
            SGroups::Single(group) => {
                debug!(
                    "Checking group {}, with {:?}, it must be {}",
                    group,
                    groups,
                    groups.iter().any(|g| group == g)
                );
                groups.iter().any(|g| group == g)
            }
            SGroups::Multiple(multiple_actors) => multiple_actors.iter().all(|actor| {
                debug!("Checking group {}, with {:?}", actor, groups);
                groups.iter().any(|g| actor == g)
            }),
        } {
            return true;
        }
    }
    false
}

impl CredMatcher for Rc<RefCell<SRole>> {
    fn user_matches(&self, user: &Cred) -> ActorMatchMin {
        let borrow = self.as_ref().borrow();
        if PluginManager::notify_duty_separation(&self.as_ref().borrow(), user).is_deny() {
            warn!("You are forbidden to use a role due to a conflict of interest, please contact your administrator");
            return ActorMatchMin::NoMatch;
        }
        let matches = borrow.actors.iter().filter_map(|actor| {
            match actor {
                SActor::User { id, .. } => {
                    if let Some(id) = id {
                        if *id == user.user {
                            return Some(ActorMatchMin::UserMatch);
                        }
                    }
                }
                SActor::Group { groups, .. } => {
                    if let Some(groups) = groups.as_ref() {
                        if match_groups(&user.groups, &[groups.clone()]) {
                            return Some(ActorMatchMin::GroupMatch(groups.len()));
                        }
                    }
                }
                SActor::Unknown(element) => {
                    let min = PluginManager::notify_user_matcher(&as_borrow!(self), user, &element);
                    if !min.is_no_match() {
                        return Some(min);
                    }
                }
            }
            None
        });
        let min = matches.min().unwrap_or(ActorMatchMin::NoMatch);
        debug!(
            "Role {} : User {} matches with {:?}",
            borrow.name, user.user.name, min
        );
        min
    }
}

impl TaskMatcher<TaskMatch> for Vec<Rc<RefCell<STask>>> {
    fn matches(
        &self,
        user: &Cred,
        cmd_opt: &Option<FilterMatcher>,
        command: &[String],
    ) -> Result<TaskMatch, MatchError> {
        let mut min_task = TaskMatch::default();
        let mut nmatch = 0;
        for task in self.iter() {
            match task.matches(user, cmd_opt, command) {
                Ok(mut task_match) => {
                    if !min_task.command_matching()
                        || task_match.score.cmd_cmp(&min_task.score) == Ordering::Less
                    {
                        task_match.score.user_min = min_task.score.user_min;
                        task_match.settings.task = Rc::downgrade(task);
                        min_task = task_match;
                        nmatch = 1;
                    } else if task_match.score == min_task.score
                        && task_match.settings != min_task.settings
                    {
                        nmatch += 1;
                    }
                }
                Err(err) => match err {
                    MatchError::NoMatch => {
                        continue;
                    }
                    MatchError::Conflict => {
                        return Err(err);
                    }
                },
            }
        }
        debug!("nmatch = {}", nmatch);
        if nmatch == 0 {
            Err(MatchError::NoMatch)
        } else if nmatch == 1 {
            Ok(min_task)
        } else {
            Err(MatchError::Conflict)
        }
    }
}

impl TaskMatcher<TaskMatch> for Vec<Rc<RefCell<SRole>>> {
    fn matches(
        &self,
        user: &Cred,
        cmd_opt: &Option<FilterMatcher>,
        command: &[String],
    ) -> Result<TaskMatch, MatchError> {
        let mut min_role = TaskMatch::default();
        let mut nmatch = 0;
        for role in self.iter() {
            match role.matches(user, cmd_opt, command) {
                Ok(mut role_match) => {
                    role_match.score.user_min = min_role.score.user_min;
                    if min_role.score.cmd_min.is_empty() || role_match.score < min_role.score {
                        min_role = role_match;
                        nmatch = 1;
                    } else if role_match.score == min_role.score
                        && !Rc::ptr_eq(
                            &role_match.settings.task.upgrade().unwrap(),
                            &min_role.settings.task.upgrade().unwrap(),
                        )
                    {
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
        if nmatch == 0 {
            Err(MatchError::NoMatch)
        } else if nmatch == 1 {
            Ok(min_role)
        } else {
            Err(MatchError::Conflict)
        }
    }
}

impl TaskMatcher<TaskMatch> for Rc<RefCell<SRole>> {
    fn matches(
        &self,
        user: &Cred,
        cmd_opt: &Option<FilterMatcher>,
        command: &[String],
    ) -> Result<TaskMatch, MatchError> {
        if let Some(cmd_opt) = cmd_opt {
            if let Some(role) = &cmd_opt.role {
                if role != &self.as_ref().borrow().name {
                    return Err(MatchError::NoMatch);
                }
            }
        }
        let borrow = self.as_ref().borrow();
        let mut min_role = TaskMatch::default();
        let user_min = self.user_matches(user);
        min_role.score.user_min = user_min;

        let mut nmatch = 0;

        match borrow.tasks.matches(user, cmd_opt, command) {
            Ok(task_match) => {
                if !min_role.fully_matching()
                    || (task_match.command_matching() && task_match.score < min_role.score)
                {
                    min_role = task_match;
                    nmatch = 1;
                }
            }
            Err(MatchError::NoMatch) => {
                nmatch = 0;
            }
            Err(MatchError::Conflict) => {
                return Err(MatchError::Conflict);
            }
        }
        min_role.score.user_min = user_min;
        plugin_role_match(
            user_min,
            borrow,
            user,
            cmd_opt,
            command,
            &mut min_role,
            &mut nmatch,
        );
        debug!(
            "==== Role {} ====\n score: {}",
            self.as_ref().borrow().name,
            min_role.score.prettyprint()
        );
        if nmatch == 0 {
            Err(MatchError::NoMatch)
        } else if nmatch == 1 {
            debug!(
                "=== Role {} === : Match for task {}\nScore : {}",
                self.as_ref().borrow().name,
                min_role.task().as_ref().borrow().name.to_string(),
                min_role.score.prettyprint()
            );
            Ok(min_role)
        } else {
            Err(MatchError::Conflict)
        }
    }
}

fn plugin_role_match(
    user_min: ActorMatchMin,
    borrow: std::cell::Ref<'_, SRole>,
    user: &Cred,
    cmd_opt: &Option<FilterMatcher>,
    command: &[String],
    min_role: &mut TaskMatch,
    nmatch: &mut i32,
) {
    let mut matcher = TaskMatch::default();
    matcher.score.user_min = user_min;
    // notify plugins
    match PluginManager::notify_role_matcher(&borrow, user, cmd_opt, command, &mut matcher) {
        PluginResultAction::Override => {
            *min_role = matcher;
            *nmatch = if min_role.fully_matching() { 1 } else { 0 };
        }
        PluginResultAction::Edit => {
            debug!("Plugin edit");
            if !min_role.command_matching()
                || (matcher.command_matching() && matcher.score.cmd_min < min_role.score.cmd_min)
            {
                *min_role = matcher;
                *nmatch = 1;
            } else if matcher.score == min_role.score {
                *nmatch += 1;
            } else if !matcher.fully_matching() {
                *nmatch = 0;
            }
        }
        PluginResultAction::Ignore => {}
    }
    debug!("nmatch = {}", nmatch);
}

impl TaskMatcher<TaskMatch> for Rc<RefCell<SConfig>> {
    fn matches(
        &self,
        user: &Cred,
        cmd_opt: &Option<FilterMatcher>,
        command: &[String],
    ) -> Result<TaskMatch, MatchError> {
        debug!(
            "Config : Matching user {} with command {:?}",
            user.user.name, command
        );
        let mut tasks: Vec<TaskMatch> = Vec::new();
        for role in self.as_ref().borrow().roles.iter() {
            if let Ok(matched) = role.matches(user, cmd_opt, command) {
                if matched.fully_matching() {
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
                tasks[0].task().as_ref().borrow().name.to_string(),
                tasks[0].role().as_ref().borrow().name,
                tasks[0].score.prettyprint()
            );
            Ok(tasks[0].clone())
        }
    }
}

#[cfg(test)]
mod tests {

    use std::fs;

    use capctl::Cap;
    use nix::unistd::getuid;
    use test_log::test;

    use crate::{
        database::{
            make_weak_config,
            options::{EnvBehavior, PathBehavior, SAuthentication, SBounding, SPrivileged},
            structs::{IdTask, RoleGetter, SCredentials, SSetuidSet},
            versionning::Versioning,
        },
        rc_refcell,
    };

    use super::*;

    #[test]
    fn test_match_path() {
        let result = match_path(&"/bin/ls".to_string(), &"/bin/ls".to_string());
        assert_eq!(result, CmdMin::Match);
    }

    #[test]
    fn test_match_args() {
        let result = match_args(
            &["-l".to_string(), "-a".to_string()],
            &["-l".to_string(), "-a".to_string()],
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::Match);
    }

    #[test]
    fn test_match_command_line() {
        let result = match_command_line(
            &["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()],
            &["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()],
        );
        assert_eq!(result, CmdMin::Match);
    }

    #[test]
    fn test_get_cmd_min() {
        let result = get_cmd_min(
            &["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()],
            &[
                "/bin/l*".into(),
                "/bin/ls .*".into(),
                "/bin/ls -l -a".into(),
            ],
        );
        assert_eq!(result, CmdMin::Match);
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
        let rcopt = Rc::new(RefCell::new(Opt::default()));
        {
            let opt = &mut rcopt.as_ref().borrow_mut();
            opt.bounding = Some(SBounding::Strict);
            opt.root = Some(SPrivileged::Privileged);
            opt.path.as_mut().unwrap().default_behavior = PathBehavior::KeepUnsafe;
            opt.env.as_mut().unwrap().default_behavior = EnvBehavior::Keep;
            opt.authentication = Some(SAuthentication::Skip);
        }

        assert_eq!(
            get_security_min(&Some(rcopt.clone())),
            SecurityMin::DisableBounding
                | SecurityMin::EnableRoot
                | SecurityMin::KeepUnsafePath
                | SecurityMin::KeepEnv
                | SecurityMin::SkipAuth
        );
        rcopt
            .as_ref()
            .borrow_mut()
            .path
            .as_mut()
            .unwrap()
            .default_behavior = PathBehavior::KeepSafe;
        assert_eq!(
            get_security_min(&Some(rcopt.clone())),
            SecurityMin::DisableBounding
                | SecurityMin::EnableRoot
                | SecurityMin::KeepPath
                | SecurityMin::KeepEnv
                | SecurityMin::SkipAuth
        );
    }

    #[test]
    fn test_is_root() {
        assert!(user_is_root(&"root".into()));
        assert!(user_is_root(&0.into()));
        assert!(!user_is_root(&1.into()));
        assert!(group_is_root(&"root".into()));
        assert!(group_is_root(&0.into()));
        assert!(!group_is_root(&1.into()));
    }

    #[test]
    fn test_list_contains_root() {
        let mut list = SGroups::Single("root".into());
        assert!(groups_contains_root(Some(&list)));
        list = SGroups::Multiple(vec!["root".into(), 1.into()]);
        assert!(groups_contains_root(Some(&list)));
        list = SGroups::Multiple(vec![1.into(), 2.into()]);
        assert!(!groups_contains_root(Some(&list)));
    }

    #[test]
    fn test_get_setuid_min() {
        let mut setuid: Option<SUserType> = Some("root".into());
        let mut setgid = Some(SGroups::Single("root".into()));
        let security_min = SecurityMin::EnableRoot;
        assert_eq!(
            get_setuid_min(setuid.as_ref(), setgid.as_ref(), &security_min),
            SetUserMin {
                uid: Some(SetuidMin { is_root: true }),
                gid: Some(SetgidMin {
                    is_root: true,
                    nb_groups: 1
                })
            }
        );
        setuid = Some("1".into());
        assert_eq!(
            get_setuid_min(setuid.as_ref(), setgid.as_ref(), &security_min),
            SetUserMin {
                uid: Some(SetuidMin { is_root: false }),
                gid: Some(SetgidMin {
                    is_root: true,
                    nb_groups: 1
                })
            }
        );
        setgid = Some(SGroups::Multiple(vec![1.into(), 2.into()]));
        assert_eq!(
            get_setuid_min(setuid.as_ref(), setgid.as_ref(), &security_min),
            SetUserMin {
                uid: Some(SetuidMin { is_root: false }),
                gid: Some(SetgidMin {
                    is_root: false,
                    nb_groups: 2
                })
            }
        );
        assert_eq!(
            get_setuid_min(None, setgid.as_ref(), &security_min),
            SetUserMin {
                uid: None,
                gid: Some(SetgidMin {
                    is_root: false,
                    nb_groups: 2
                })
            }
        );
        assert_eq!(
            get_setuid_min(None, None, &security_min),
            SetUserMin {
                uid: None,
                gid: None
            }
        );
        assert_eq!(
            get_setuid_min(setuid.as_ref(), None, &security_min),
            SetUserMin {
                uid: Some(SetuidMin { is_root: false }),
                gid: None
            }
        )
    }

    #[test]
    fn test_score_cmp() {
        let score1 = Score {
            user_min: ActorMatchMin::UserMatch,
            cmd_min: CmdMin::Match,
            caps_min: CapsMin::CapsAll,
            setuser_min: SetUserMin {
                uid: Some(SetuidMin { is_root: true }),
                gid: Some(SetgidMin {
                    is_root: true,
                    nb_groups: 1,
                }),
            },
            security_min: SecurityMin::DisableBounding | SecurityMin::EnableRoot,
        };
        let mut score2 = Score {
            user_min: ActorMatchMin::UserMatch,
            cmd_min: CmdMin::Match,
            caps_min: CapsMin::CapsAll,
            setuser_min: SetUserMin {
                uid: Some(SetuidMin { is_root: true }),
                gid: Some(SetgidMin {
                    is_root: true,
                    nb_groups: 1,
                }),
            },
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
        score2.setuser_min = SetUserMin {
            uid: Some(SetuidMin { is_root: true }),
            gid: Some(SetgidMin {
                is_root: true,
                nb_groups: 2,
            }),
        };
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.setuser_min = SetUserMin {
            uid: Some(SetuidMin { is_root: false }),
            gid: Some(SetgidMin {
                is_root: true,
                nb_groups: 2,
            }),
        };
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        score2.setuser_min = SetUserMin {
            uid: Some(SetuidMin { is_root: true }),
            gid: Some(SetgidMin {
                is_root: false,
                nb_groups: 2,
            }),
        };
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        score2.setuser_min = SetUserMin {
            uid: Some(SetuidMin { is_root: false }),
            gid: Some(SetgidMin {
                is_root: false,
                nb_groups: 2,
            }),
        };
        assert_eq!(score1.cmp(&score2), Ordering::Greater);
        score2.setuser_min = SetUserMin {
            uid: Some(SetuidMin { is_root: true }),
            gid: Some(SetgidMin {
                is_root: true,
                nb_groups: 1,
            }),
        };
        assert_eq!(score1.cmp(&score2), Ordering::Equal);
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
        score2.user_min = ActorMatchMin::GroupMatch(1);
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.user_min = ActorMatchMin::NoMatch;
        assert_eq!(score1.cmp(&score2), Ordering::Less);
        score2.user_min = ActorMatchMin::UserMatch;
        assert_eq!(score1.cmp(&score2), Ordering::Equal);
    }

    fn setup_test_config(num_roles: usize) -> Rc<RefCell<SConfig>> {
        SConfig::builder()
            .roles((0..num_roles).map(|i| SRole::builder(format!("role{}", i)).build()))
            .build()
    }

    fn setup_test_role(
        num_tasks: usize,
        role: Option<Rc<RefCell<SRole>>>,
        with_config: Option<Rc<RefCell<SConfig>>>,
    ) -> Rc<RefCell<SRole>> {
        let role = role.unwrap_or_else(|| {
            let mut role = SRole::default();
            role.name = "test".to_string();
            role._config = with_config.map(|config| Rc::downgrade(&config));
            Rc::new(RefCell::new(role))
        });
        for i in 0..num_tasks {
            let mut task = STask::default();
            task.name = IdTask::Name(format!("{}_task_{}", role.as_ref().borrow().name, i));
            task._role = Some(Rc::downgrade(&role));
            role.as_ref().borrow_mut().tasks.push(Rc::new(task.into()));
        }
        role
    }

    #[test]
    fn test_matcher_matches() {
        let config = setup_test_config(2);
        let role0 = setup_test_role(2, Some(config.as_ref().borrow().roles[0].clone()), None);
        let r0_task0 = role0.as_ref().borrow().tasks[0].clone();
        let r0_task1 = role0.as_ref().borrow().tasks[1].clone();
        let role1 = setup_test_role(2, Some(config.as_ref().borrow().roles[1].clone()), None);
        let r1_task0 = role1.as_ref().borrow().tasks[0].clone();
        let r1_task1 = role1.as_ref().borrow().tasks[1].clone();

        // every tasks matches but not at the same score, so the least one is matched
        role0
            .as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());
        role1
            .as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());

        r0_task0
            .as_ref()
            .borrow_mut()
            .commands
            .add
            .push("/bin/ls -l -a".into()); // candidate
        r0_task1
            .as_ref()
            .borrow_mut()
            .commands
            .add
            .push("/bin/ls .*".into()); // regex args > r1_task1

        r1_task0
            .as_ref()
            .borrow_mut()
            .commands
            .add
            .push("/bin/ls -l -a".into()); //AllCaps > r1_task1
        r1_task1
            .as_ref()
            .borrow_mut()
            .commands
            .add
            .push("/bin/ls -l -a".into()); //One Capability > r1_task1

        r1_task0.as_ref().borrow_mut().cred.capabilities = Some((!CapSet::empty()).into());
        let mut capset = CapSet::empty();
        capset.add(Cap::SYS_ADMIN);
        r1_task1.as_ref().borrow_mut().cred.capabilities = Some(capset.into());

        let cred = Cred {
            user: User::from_uid(Uid::from_raw(0)).unwrap().unwrap(),
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };

        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];
        let result = config.matches(&cred, &None, &command);
        debug!("Result : {:?}", result);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(
            result.task().as_ref().borrow().name,
            IdTask::Name("role0_task_0".to_string())
        );
        assert_eq!(result.role().as_ref().borrow().name, "role0");
    }

    #[test]
    //echec
    fn test_setuid_fallback_valid() {
        // Configuration de test
        let config = setup_test_config(1); // Un seul rôle pour simplifier
        let role = setup_test_role(1, Some(config.as_ref().borrow().roles[0].clone()), None);
        let task = role.as_ref().borrow().tasks[0].clone();

        // Ajout d'un acteur autorisé
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());

        task.as_ref().borrow_mut().commands.default_behavior = Some(SetBehavior::All);

        // Définition du `setuid` avec un `fallback`
        let fallback_user = SUserType::from(getuid().as_raw());
        let chooser_struct = SSetuidSet {
            fallback: fallback_user.clone(),
            default: SetBehavior::None,
            add: vec![], // Pas d'ajout explicite
            sub: vec![], // Pas de restriction explicite
        };
        task.as_ref().borrow_mut().cred.setuid = Some(SUserChooser::ChooserStruct(chooser_struct));

        // Création des credentials avec l'utilisateur correspondant au `fallback`
        let cred = Cred::builder().user_name("root").group_name("root").build();

        // Commande de test
        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];
        // Exécution du match
        let filter_matcher = FilterMatcher::builder().user(fallback_user.clone()).build();

        let result = config.matches(&cred, &Some(filter_matcher), &command);
        println!("Résultat matches: {:?}", result);

        // Vérification que le match est réussi
        assert!(result.is_ok());
        let result = result.unwrap();

        // Vérification que l'utilisateur assigné est bien celui du fallback
        assert_eq!(result.settings.setuid, Some(fallback_user.clone()));

        println!("Test réussi : L'utilisateur spécifié correspond bien au fallback.");
    }

    #[test]
    //echec
    fn test_setuid_fallback_nonarg_valid() {
        // Configuration de test
        let config = setup_test_config(1);
        let role = setup_test_role(1, Some(config.as_ref().borrow().roles[0].clone()), None);
        let task = role.as_ref().borrow().tasks[0].clone();

        // Ajout d'un acteur autorisé
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());

        task.as_ref().borrow_mut().commands.default_behavior = Some(SetBehavior::All);

        // Définition du `setuid` avec un `fallback`
        let fallback_user = SUserType::from(getuid().as_raw());
        let chooser_struct = SSetuidSet {
            fallback: fallback_user.clone(),
            default: SetBehavior::None,
            add: vec![],
            sub: vec![],
        };
        task.as_ref().borrow_mut().cred.setuid = Some(SUserChooser::ChooserStruct(chooser_struct));

        // Création des credentials sans spécifier d'utilisateur
        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(), // Utilisateur non spécifié
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };

        // Commande de test
        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];

        // Exécution du match
        let result = config.matches(&cred, &None, &command);

        // Vérification que le match est réussi
        assert!(result.is_ok());
        let result = result.unwrap();

        // Vérification que l'utilisateur assigné est bien celui du fallback
        assert_eq!(result.settings.setuid, Some(fallback_user.clone()));

        println!("Test réussi : L'utilisateur spécifié correspond bien au fallback lorsqu'aucun utilisateur valide n'est fourni.");
    }

    #[test]
    //echec
    fn test_setuid_add_valid() {
        // Configuration de test
        let config = setup_test_config(1); // Un seul rôle pour simplifier
        let role = setup_test_role(1, Some(config.as_ref().borrow().roles[0].clone()), None);
        let task = role.as_ref().borrow().tasks[0].clone();

        // Ajout d'un acteur autorisé
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());

        task.as_ref().borrow_mut().commands.default_behavior = Some(SetBehavior::All);

        // Définition du `setuid` avec un `fallback`
        let fallback_user = SUserType::from(getuid().as_raw());
        let chooser_struct = SSetuidSet {
            fallback: fallback_user.clone(),
            default: SetBehavior::None,
            add: vec![SUserType::from("root")], // Ajout d'un utilisateur
            sub: vec![],                        // Pas de restriction explicite
        };
        task.as_ref().borrow_mut().cred.setuid = Some(SUserChooser::ChooserStruct(chooser_struct));

        // Création des credentials avec l'utilisateur correspondant à l'ajout
        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(), // Même nom que l'ajout
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };

        // Commande de test
        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];

        // Exécution du match
        let filter_matcher = FilterMatcher::builder().user("root").build();

        let result = config.matches(&cred, &Some(filter_matcher), &command);

        // Vérification que le match est réussi
        assert!(result.is_ok());
        let result = result.unwrap();

        // Vérification que l'utilisateur assigné est bien celui de l'ajout
        assert_eq!(result.settings.setuid, Some(SUserType::from("root")));

        println!("Test réussi : L'utilisateur spécifié correspond bien à l'ajout.");
    }

    #[test]
    fn test_setuid_add_sub_invalid() {
        // Configuration de test
        let config = setup_test_config(1); // Un seul rôle pour simplifier
        let role = setup_test_role(1, Some(config.as_ref().borrow().roles[0].clone()), None);
        let task = role.as_ref().borrow().tasks[0].clone();

        // Ajout d'un acteur autorisé
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());

        task.as_ref().borrow_mut().commands.default_behavior = Some(SetBehavior::All);

        // Définition du `setuid` avec un `fallback`
        let fallback_user = SUserType::from(getuid().as_raw());
        let chooser_struct = SSetuidSet {
            fallback: fallback_user.clone(),
            default: SetBehavior::None,
            add: vec![SUserType::from("root")], // Ajout d'un utilisateur
            sub: vec![SUserType::from("root")], // Restriction d'un utilisateur
        };
        task.as_ref().borrow_mut().cred.setuid = Some(SUserChooser::ChooserStruct(chooser_struct));

        // Création des credentials avec l'utilisateur correspondant à l'ajout
        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(), // Même nom que l'ajout
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };

        // Commande de test
        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];
        // Exécution du match
        let filter_matcher = FilterMatcher::builder().user("root").build();

        let result = config.matches(&cred, &Some(filter_matcher), &command);
        println!("Résultat matches: {:?}", result);
        // Vérification que le match est réussi
        assert!(result.is_err());
        let result = result.unwrap_err();

        // Vérification que l'erreur est bien de type `NoMatch`
        assert_eq!(result, MatchError::NoMatch);

        println!("Test réussi : L'utilisateur spécifié ne correspond pas à la restriction.");
    }

    #[test]
    fn test_setuid_all_sub_invalid() {
        // Configuration de test
        let config = setup_test_config(1); // Un seul rôle pour simplifier
        let role = setup_test_role(1, Some(config.as_ref().borrow().roles[0].clone()), None);
        let task = role.as_ref().borrow().tasks[0].clone();

        // Ajout d'un acteur autorisé
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());
        task.as_ref().borrow_mut().commands.default_behavior = Some(SetBehavior::All);

        // Définition du `setuid` avec un `fallback`
        let fallback_user = SUserType::from(getuid().as_raw());
        let chooser_struct = SSetuidSet {
            fallback: fallback_user.clone(),
            default: SetBehavior::All,
            add: vec![],
            sub: vec![SUserType::from("root")], // Restriction d'un utilisateur
        };
        task.as_ref().borrow_mut().cred.setuid = Some(SUserChooser::ChooserStruct(chooser_struct));

        // Création des credentials avec l'utilisateur correspondant à l'ajout
        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(), // Même nom que l'ajout
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };
        // Commande de test
        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];
        // Exécution du match
        let filter_matcher = FilterMatcher::builder().user("root").build();

        let result = config.matches(&cred, &Some(filter_matcher), &command);

        // Vérification que le match est réussi
        assert!(result.is_err());
        let result = result.unwrap_err();

        // Vérification que l'erreur est bien de type `NoMatch`
        assert_eq!(result, MatchError::NoMatch);

        println!("Test réussi : L'utilisateur spécifié ne correspond pas ");
    }

    #[test]
    //echec
    fn test_setuid_all_valid() {
        // Configuration de test
        let config = setup_test_config(1); // Un seul rôle pour simplifier
        let role = setup_test_role(1, Some(config.as_ref().borrow().roles[0].clone()), None);
        let task = role.as_ref().borrow().tasks[0].clone();

        // Ajout d'un acteur autorisé
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());

        task.as_ref().borrow_mut().commands.default_behavior = Some(SetBehavior::All);

        // Définition du `setuid` avec un `fallback`
        let fallback_user = SUserType::from(getuid().as_raw());
        let chooser_struct = SSetuidSet {
            fallback: fallback_user.clone(),
            default: SetBehavior::All,
            add: vec![],
            sub: vec![],
        };
        task.as_ref().borrow_mut().cred.setuid = Some(SUserChooser::ChooserStruct(chooser_struct));

        // Création des credentials avec l'utilisateur correspondant à l'ajout
        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(), // Même nom que l'ajout
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };

        // Commande de test
        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];
        // Exécution du match
        let filter_matcher = FilterMatcher::builder().user("root").build();

        let result = config.matches(&cred, &Some(filter_matcher), &command);

        // Vérification que le match est réussi
        assert!(result.is_ok());
        let result = result.unwrap();

        // Vérification que l'utilisateur assigné est bien celui de l'ajout
        assert_eq!(result.settings.setuid, Some(SUserType::from("root")));

        println!("Test réussi : L'utilisateur spécifié correspond bien à l'ajout.");
    }

    #[test]
    fn test_setuid_none_invalid() {
        // Configuration de test
        let config = setup_test_config(1); // Un seul rôle pour simplifier
        let role = setup_test_role(1, Some(config.as_ref().borrow().roles[0].clone()), None);
        let task = role.as_ref().borrow().tasks[0].clone();

        // Ajout d'un acteur autorisé
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());

        // Définition du `setuid` avec un `fallback`
        let fallback_user = SUserType::from(getuid().as_raw());
        let chooser_struct = SSetuidSet {
            fallback: fallback_user.clone(),
            default: SetBehavior::None,
            add: vec![],
            sub: vec![],
        };
        task.as_ref().borrow_mut().cred.setuid = Some(SUserChooser::ChooserStruct(chooser_struct));

        // Création des credentials avec l'utilisateur correspondant à l'ajout
        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(), // Même nom que l'ajout
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };

        // Commande de test
        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];
        // Exécution du match
        let filter_matcher = FilterMatcher::builder().user("root").build();
        let result = config.matches(&cred, &Some(filter_matcher), &command);

        // Vérification que le match est réussi
        assert!(result.is_err());
        let result = result.unwrap_err();

        // Vérification que l'erreur est bien de type `NoMatch`
        assert_eq!(result, MatchError::NoMatch);

        println!("Test réussi : L'utilisateur spécifié ne correspond pas ");
    }

    #[test]
    fn test_setuid_all_add_valid() {
        // Configuration de test
        let config = setup_test_config(1); // Un seul rôle pour simplifier
        let role = setup_test_role(1, Some(config.as_ref().borrow().roles[0].clone()), None);
        let task = role.as_ref().borrow().tasks[0].clone();

        task.as_ref().borrow_mut().commands.default_behavior = Some(SetBehavior::All);

        // Ajout d'un acteur autorisé
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());

        task.as_ref().borrow_mut().commands.default_behavior = Some(SetBehavior::All);

        // Définition du `setuid` avec un `fallback`
        let fallback_user = SUserType::from(getuid().as_raw());
        let chooser_struct = SSetuidSet {
            fallback: fallback_user.clone(),
            default: SetBehavior::All,
            add: vec![SUserType::from("root")], // Ajout d'un utilisateur
            sub: vec![],
        };
        task.as_ref().borrow_mut().cred.setuid = Some(SUserChooser::ChooserStruct(chooser_struct));

        // Création des credentials avec l'utilisateur correspondant à l'ajout
        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(), // Même nom que l'ajout
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };

        // Commande de test
        let command = vec!["/bin/ls".to_string(), "-l".to_string(), "-a".to_string()];
        // Exécution du match
        let filter_matcher = FilterMatcher::builder().user("root").build();

        let result = config.matches(&cred, &Some(filter_matcher), &command);

        // Vérification que le match est réussi
        assert!(result.is_ok());
        let result = result.unwrap();

        // Vérification que l'utilisateur assigné est bien celui de l'ajout
        assert_eq!(result.settings.setuid, Some(SUserType::from("root")));

        println!("Test réussi : L'utilisateur spécifié correspond bien à l'ajout.");
    }

    #[test]
    fn test_equal_settings() {
        let mut settings1 = ExecSettings::new();
        let mut settings2 = ExecSettings::new();
        assert_eq!(settings1, settings2);
        settings1.exec_path = PathBuf::from("/bin/ls");
        assert_ne!(settings1, settings2);
        settings2.exec_path = PathBuf::from("/bin/ls");
        assert_eq!(settings1, settings2);
        settings1.exec_args = vec!["-l".to_string()];
        assert_ne!(settings1, settings2);
        settings2.exec_args = vec!["-l".to_string()];
        assert_eq!(settings1, settings2);
        settings1.setuid = Some("root".into());
        assert_ne!(settings1, settings2);
        settings2.setuid = Some("root".into());
        assert_eq!(settings1, settings2);
        settings1.setgroups = Some(SGroups::Single("root".into()));
        assert_ne!(settings1, settings2);
        settings2.setgroups = Some(SGroups::Single("root".into()));
        assert_eq!(settings1, settings2);
        settings1.caps = Some(CapSet::empty());
        assert_ne!(settings1, settings2);
        settings2.caps = Some(CapSet::empty());
        assert_eq!(settings1, settings2);
    }

    #[test]
    fn test_two_task_matches_equals() {
        let config = rc_refcell!(SConfig::default());
        let role = rc_refcell!(SRole::default());
        role.as_ref().borrow_mut()._config = Some(Rc::downgrade(&config));
        role.as_ref().borrow_mut().name = "test".to_string();
        role.as_ref()
            .borrow_mut()
            .actors
            .push(SActor::user("root").build());
        let mut task1 = STask::default();
        let mut task2 = STask::default();
        task1.name = IdTask::Name("task1".to_string());
        task2.name = IdTask::Name("task2".to_string());
        task1.commands.add.push("/bin/ls".into());
        task2.commands.add.push("/bin/ls".into());
        task1.options = Some(Rc::new(RefCell::new(Opt::default())));
        task2.options = Some(Rc::new(RefCell::new(Opt::default())));
        task1._role = Some(Rc::downgrade(&role));
        task2._role = Some(Rc::downgrade(&role));
        task1.cred.capabilities = Some((!CapSet::empty()).into());
        task2.cred.capabilities = Some((!CapSet::empty()).into());
        role.as_ref().borrow_mut().tasks.push(Rc::new(task1.into()));
        role.as_ref().borrow_mut().tasks.push(Rc::new(task2.into()));
        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(),
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };
        let command = vec!["/bin/ls".to_string()];
        let result = role.matches(&cred, &None, &command);
        assert!(result.is_ok());
        assert!(role.as_ref().borrow_mut()[0]
            .as_ref()
            .borrow_mut()
            .options
            .as_mut()
            .unwrap()
            .as_ref()
            .borrow_mut()
            .path
            .as_mut()
            .unwrap()
            .add
            .insert("/test".to_string()));
        let result = role.matches(&cred, &None, &command);
        assert!(result.is_err());
    }

    #[test]
    fn test_two_role_default() {
        let config: Versioning<Rc<RefCell<SConfig>>> =
            serde_json::from_str(&fs::read_to_string("../resources/rootasrole.json").unwrap())
                .unwrap();
        let config = config.data;
        make_weak_config(&config);
        config.as_ref().borrow_mut()[0].as_ref().borrow_mut().actors[0] =
            SActor::user("root").build();
        let cred = Cred {
            user: User::from_name("root").unwrap().unwrap(),
            groups: vec![Group::from_name("root").unwrap().unwrap()],
            ppid: Pid::from_raw(0),
            tty: None,
        };
        let command = vec!["/bin/ls".to_string()];
        let result = config.matches(&cred, &None, &command);
        assert!(result.is_ok());
        // must match the r_root role and t_root task
        let result = result.unwrap();
        assert_eq!(result.role().as_ref().borrow().name, "r_root");
        assert_eq!(
            result.task().as_ref().borrow().name,
            IdTask::Name("t_root".to_string())
        );
        let command = vec!["/usr/bin/chsr".to_string(), "show".to_string()];
        let result = config.matches(&cred, &None, &command);
        assert!(result.is_ok());
        // must match the r_root role and t_chsr task
        let result = result.unwrap();
        assert_eq!(result.role().as_ref().borrow().name, "r_root");
        assert_eq!(
            result.task().as_ref().borrow().name,
            IdTask::Name("t_chsr".to_string())
        );
    }
    #[test]

    fn test_schooseruser_setuid_types() {
        let config = SConfig::builder()
            .role(
                SRole::builder("test")
                    .actor(SActor::user("root").build())
                    .task(
                        STask::builder(1)
                            .cred(
                                SCredentials::builder()
                                    .setuid(SUserChooser::ChooserStruct(
                                        SSetuidSet::builder(SUserType::from(0), SetBehavior::None)
                                            .build(),
                                    ))
                                    .build(),
                            )
                            .commands(
                                SCommands::builder(SetBehavior::None)
                                    .add(["/bin/ls".into()])
                                    .build(),
                            )
                            .build(),
                    )
                    .task(
                        STask::builder(2)
                            .cred(SCredentials::builder().setuid("root").build())
                            .commands(
                                SCommands::builder(SetBehavior::None)
                                    .add(["/bin/pwd".into()])
                                    .build(),
                            )
                            .build(),
                    )
                    .task(
                        STask::builder(3)
                            .cred(SCredentials::builder().setuid(0).build())
                            .commands(
                                SCommands::builder(SetBehavior::None)
                                    .add(["/bin/cat".into()])
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .build();

        // Vérifier si les tâches existent avant d’appeler unwrap()

        let t1 = config
            .task("test", 1)
            .expect(" Erreur : La tâche 1 n'existe pas !");
        let t2 = config
            .task("test", 2)
            .expect(" Erreur : La tâche 2 n'existe pas !");
        let t3 = config
            .task("test", 3)
            .expect(" Erreur : La tâche 3 n'existe pas !");

        // Affichage pour debug
        println!("Tâche 1 : {:?}", t1);
        println!("Tâche 2 : {:?}", t2);
        println!("Tâche 3 : {:?}", t3);

        let cred = Cred::builder().user_name("root").group_name("root").build();

        let chooser_struct2 = SUserType::from("root");
        let chooser_struct3 = SUserType::from(0);

        let command1 = vec!["/bin/ls".to_string()];
        let command2 = vec!["/bin/pwd".to_string()];
        let command3 = vec!["/bin/cat".to_string()];

        let filter_matcher = FilterMatcher::builder().user("root").build();
        let result = config.matches(&cred, &Some(filter_matcher), &command1);
        assert!(result.is_ok(), "Erreur : L !");
        let result1 = config.matches(&cred, &None, &command1);
        assert!(result1.is_ok(), "Erreur : La tâche 1 ne correspond pas !");
        let result2 = config.matches(&cred, &None, &command2);
        assert!(result2.is_ok(), "Erreur : La tâche 2 ne correspond pas !");
        let result3 = config.matches(&cred, &None, &command3);
        assert!(result3.is_ok(), "Erreur : La tâche 3 ne correspond pas !");

        let result1 = result1.unwrap();
        let result2 = result2.unwrap();
        let result3 = result3.unwrap();

        assert_eq!(result1.settings.setuid, Some(SUserType::from(0)));
        assert_eq!(result1.settings.task.upgrade(), Some(t1.clone()));
        println!(
            " Test réussi : L'utilisateur spécifié correspond bien à l'ajout pour la tâche 1."
        );

        assert_eq!(result2.settings.setuid, Some(chooser_struct2));
        assert_eq!(result2.settings.task.upgrade(), Some(t2.clone()));
        println!(
            " Test réussi : L'utilisateur spécifié correspond bien à l'ajout pour la tâche 2."
        );

        assert_eq!(result3.settings.setuid, Some(chooser_struct3));
        assert_eq!(result3.settings.task.upgrade(), Some(t3.clone()));
        println!(
            " Test réussi : L'utilisateur spécifié correspond bien à l'ajout pour la tâche 3."
        );
    }
}
