/// This file implements a finder algorithm within deserialization of the settings
/// It is much more efficient to do it this way, way less memory allocation and manipulation
/// Only the settings that are needed are kept in memory
use std::{
    cmp::Ordering,
    collections::HashMap,
    ffi::CString,
    fs,
    io::BufReader,
    path::{Path, PathBuf},
};

use api::{Api, ApiEvent};
use bon::Builder;
use de::{ConfigFinderDeserializer, DConfigFinder, DLinkedCommand, DLinkedRole, DLinkedTask};
use log::{debug, error, warn};
use nix::{
    errno::Errno,
    unistd::{Group, User, getgrouplist},
};
use options::BorrowedOptStack;
use rootasrole_core::{
    Cred,
    database::{
        actor::{DGroupType, DGroups},
        env::EnvFilter,
        options::{SAuthentication, SBounding, SPrivileged, STimeout, SUMask},
        score::{ActorMatchMin, CmdMin, CmdOrder, HardenedBool, Score, hardened_bool_from_bool},
        structs::GroupsFrom,
        workdir::ResolvedWorkdir,
    },
    util::{StorageMethod, check_immutable, check_others_permissions, read_with_privileges},
};
use serde::de::DeserializeSeed;

use crate::{
    Cli,
    error::{SrError, SrResult},
    finder::de::{
        cred::{CredData, CredOwnedData},
        settings::read_storage,
    },
};

pub mod api;
pub mod cmd;
use cmd::resolve_any_command;
pub mod de;
mod options;

pub use options::PasswordSettings;

#[derive(Debug, Default, Clone, Builder)]
pub struct BestExecSettings {
    #[builder(default)]
    /// The final matching score. Evaluated over several fields, see `Score`
    pub score: Score,

    #[builder(default)]
    /// The execution path, canonalized and sanitized
    pub final_path: PathBuf,

    #[builder(default)]
    /// The Owned version of credentials needed for switching user and set capabilities
    pub cred: CredOwnedData,

    ///The task name matched in the policy
    pub task: Option<String>,

    #[builder(default)]
    /// The role name matched in the policy
    pub role: String,
    #[builder(default)]
    /// The final set of environment variable to keep/set
    pub env: HashMap<String, String>,
    #[builder(default)]
    /// The filter of the policy on the environment, for the variables that PAM modules set once
    /// the session is open
    pub env_filter: EnvFilter,
    #[builder(default)]
    /// The PATH variable is managed indepedently given the policy
    pub env_path: Vec<String>,
    /// The working directory to set, if specified in policy
    pub workdir: Option<PathBuf>,
    #[builder(default)]
    /// Whether the Linux Capabilities are [bounded](https://www.man7.org/linux/man-pages/man7/capabilities.7.html)
    pub bounding: SBounding,
    #[builder(default)]
    /// Information about whether the user should re-authenticate
    pub timeout: STimeout,
    #[builder(default)]
    /// Information about whether the user should authenticate or bypass it
    pub auth: SAuthentication,
    #[builder(default)]
    /// How many times the password is asked, and the delay after a wrong one
    pub password: PasswordSettings,
    #[builder(default)]
    /// Is root id has it's privileges or not? If not, root is going to be a simple user
    pub root: SPrivileged,
    #[builder(default)]
    /// Setting umask
    pub umask: SUMask,
    #[builder(skip)]
    /// The address of the best task, to tell another task as good as it from the same task
    /// reached again through the hierarchy plugin. It is only compared, never dereferenced.
    best_task: Option<usize>,
    #[builder(skip)]
    /// Another task as good as the best one (`role/task`): none of them needs fewer privileges,
    /// so dosr cannot choose and refuses (see [`BestExecSettings::refuse_tie`]).
    tie: Option<String>,
}

/// This functions is the main entrace to lookup at the security policy.
/// It efficiently check the policy based on the user args, skips unnecessary policy info etc.
/// The main focus here is to avoid at maximum any allocation.
/// # Returns
/// When a policy match was found, it returns all needed information, otherwise, it returns an ``SrError``.
pub fn find_best_exec_settings<'de: 'a, 'a, P>(
    cli: &'a Cli,
    cred: &'a Cred,
    rar_cfg_path: P,
    rar_cfg_data_path: P,
    rar_cfg_type: StorageMethod,
    env_vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    env_path: &[&str],
) -> SrResult<BestExecSettings>
where
    P: AsRef<Path>,
{
    let env_vars: Vec<(String, String)> = env_vars
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
    let settings_file = read_storage(rar_cfg_path, rar_cfg_type)?;
    let storage_settings = settings_file.data.data.settings.unwrap_or_default();
    let immutable = storage_settings.immutable.unwrap_or(false);
    let file_path = storage_settings
        .path
        .unwrap_or_else(|| rar_cfg_data_path.as_ref().to_path_buf());
    let parse_file = |file_path: &Path| -> SrResult<BestExecSettings> {
        let config_finder_deserializer = ConfigFinderDeserializer { cli, cred };
        let file = read_with_privileges(file_path)?;
        check_others_permissions(file_path, &file)?;
        if immutable {
            // a file added to the policy without CAP_LINUX_IMMUTABLE is not trusted
            check_immutable(file_path, &file)?;
        }
        let reader = BufReader::new(file);
        match settings_file.data.data.method {
            StorageMethod::CBOR => {
                let mut io_reader = cbor4ii::core::utils::IoReader::new(reader);
                Ok(BestExecSettings::evaluate(
                    cli,
                    cred,
                    &config_finder_deserializer
                        .deserialize(&mut cbor4ii::serde::Deserializer::new(&mut io_reader))
                        .map_err(|e| {
                            debug!("Error deserializing CBOR: {e}");
                            SrError::ConfigurationError
                        })?,
                    env_vars.iter().cloned(),
                    env_path,
                )?)
            }
            StorageMethod::JSON => {
                let io_reader = serde_json::de::IoRead::new(reader);
                Ok(BestExecSettings::evaluate(
                    cli,
                    cred,
                    &config_finder_deserializer
                        .deserialize(&mut serde_json::Deserializer::new(io_reader))
                        .map_err(|e| {
                            debug!("Error deserializing JSON: {e}");
                            SrError::ConfigurationError
                        })?,
                    env_vars.iter().cloned(),
                    env_path,
                )?)
            }
        }
    };

    if file_path.is_dir() {
        let mut entries: Vec<PathBuf> = fs::read_dir(&file_path)
            .map_err(|e| {
                debug!(
                    "Failed to read policy directory {}: {e}",
                    file_path.display()
                );
                SrError::ConfigurationError
            })?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect();
        entries.sort();

        let mut best: Option<BestExecSettings> = None;
        let mut parsed_any = false;

        for entry in entries {
            let result = parse_file(&entry);
            match result {
                Ok(settings) => {
                    parsed_any = true;
                    BestExecSettings::keep_best(&mut best, settings);
                }
                Err(SrError::PermissionDenied) => {
                    parsed_any = true;
                }
                Err(err) => {
                    debug!("Skipping policy file {}: {err}", entry.display());
                }
            }
        }

        // a tie is only refused once the best tasks of every file are compared: another file
        // can have a better task
        return best
            .ok_or({
                if parsed_any {
                    SrError::PermissionDenied
                } else {
                    SrError::ConfigurationError
                }
            })
            .and_then(BestExecSettings::refuse_tie)
            .and_then(BestExecSettings::with_target_groups);
    }

    parse_file(&file_path)
        .and_then(BestExecSettings::refuse_tie)
        .and_then(BestExecSettings::with_target_groups)
}

/// The user and the groups of the credentials of a task, or what does not resolve: a name that
/// nobody has, an id without an entry, or a lookup that fails. Before, such a user was dropped,
/// so the command ran as the caller, and such a group was dropped from the list, so the command
/// kept the primary group of the caller when no group was left.
fn resolve_cred(cred: &CredData<'_>) -> Result<(Option<User>, Option<Vec<Group>>), String> {
    let setuid = cred
        .setuid
        .as_ref()
        .map(|user| user.fetch_user().ok_or_else(|| format!("the user {user}")))
        .transpose()?;
    let group = |group: &DGroupType<'_>| {
        group
            .fetch_group()
            .ok_or_else(|| format!("the group {group}"))
    };
    let setgroups = match &cred.setgroups {
        None => None,
        Some(DGroups::Single(single)) => Some(vec![group(single)?]),
        Some(DGroups::Multiple(groups)) if groups.is_empty() => {
            return Err("an empty list of groups".into());
        }
        Some(DGroups::Multiple(groups)) => {
            Some(groups.iter().map(group).collect::<Result<_, _>>()?)
        }
    };
    Ok((setuid, setgroups))
}

/// The groups of `user` as a login gives them (`initgroups(3)`): its primary group first, then
/// the groups that list it as a member, like sudo-rs `User::from_libc` (sudo-rs/src/system/mod.rs).
/// A gid without a name is named by its number.
fn login_groups(user: &User) -> nix::Result<Vec<Group>> {
    let name = CString::new(user.name.as_bytes()).map_err(|_| Errno::EINVAL)?;
    let mut gids = vec![user.gid];
    for gid in getgrouplist(&name, user.gid)? {
        if !gids.contains(&gid) {
            gids.push(gid);
        }
    }
    gids.into_iter()
        .map(|gid| {
            Ok(Group::from_gid(gid)?.unwrap_or_else(|| Group {
                name: gid.to_string(),
                passwd: CString::default(),
                gid,
                mem: Vec::new(),
            }))
        })
        .collect()
}

impl BestExecSettings {
    /// The settings of the best task of the policy `data` for the command line, refused when
    /// another task is as good as the best one.
    pub(crate) fn retrieve_settings<'a>(
        cli: &'a Cli,
        cred: &'a Cred,
        data: &'a DConfigFinder<'a>,
        env_vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
        env_path: &[&str],
    ) -> SrResult<Self> {
        Self::evaluate(cli, cred, data, env_vars, env_path)
            .and_then(Self::refuse_tie)
            .and_then(Self::with_target_groups)
    }

    /// The task changes the user without giving the groups: the command gets the groups of the
    /// target user, as a login gives them, unless `from` names the groups of the caller. A task
    /// that keeps the user keeps the groups of the caller. A lookup that fails refuses the
    /// command, it never falls back on the groups of the caller.
    fn with_target_groups(mut self) -> SrResult<Self> {
        if self.cred.setgroups.is_none()
            && self.cred.groups_from != Some(GroupsFrom::Caller)
            && let Some(user) = &self.cred.setuid
        {
            let groups = login_groups(user).map_err(|e| {
                error!("Cannot read the groups of the user {}: {e}", user.name);
                SrError::SystemError
            })?;
            self.cred.setgroups = Some(groups);
        }
        Ok(self)
    }

    /// Refuse the settings when another task is as good as the best one: none of them needs
    /// fewer privileges, so dosr cannot choose. The policy must tell them apart, or the user
    /// selects one with -r and -t. A tie between tasks worse than the best one does not matter.
    fn refuse_tie(self) -> SrResult<Self> {
        if let Some(other) = &self.tie {
            warn!(
                "Permission denied: the tasks {} and {other} match the command equally, with the same privileges; the policy must tell them apart",
                self.task_name()
            );
            return Err(SrError::PermissionDenied);
        }
        Ok(self)
    }

    /// Keep the better of the best settings of two policy files, or record that their tasks
    /// are as good as each other.
    fn keep_best(best: &mut Option<Self>, settings: Self) {
        match best {
            Some(best) if !settings.score.better_fully(&best.score) => {
                if settings.score.cmp(&best.score) == Ordering::Equal {
                    best.tie.get_or_insert_with(|| settings.task_name());
                }
            }
            _ => *best = Some(settings),
        }
    }

    /// The best task, as `role/task`.
    fn task_name(&self) -> String {
        format!("{}/{}", self.role, self.task.as_deref().unwrap_or_default())
    }

    /// The settings of the best task of the policy `data`, even when another task is as good
    /// as it: the best tasks of the files of a policy directory are compared first.
    fn evaluate<'a>(
        cli: &'a Cli,
        cred: &'a Cred,
        data: &'a DConfigFinder<'a>,
        env_vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
        env_path: &[&str],
    ) -> SrResult<Self> {
        let mut result = Self::default();
        let mut matching = false;
        let mut opt_stack = BorrowedOptStack::new(data.options.as_ref());
        let role_filter = cli
            .opt_filter
            .as_ref()
            .and_then(|filter| filter.role.as_deref());
        for role in data.roles() {
            // the role asked with -r, the others were read for the plugins
            if role_filter.is_some_and(|name| name != role.role().role.as_ref()) {
                continue;
            }
            // only the roles that the user holds: their actors match and no plugin excludes
            // them (separation of duties), the hierarchy plugin relies on it
            if !result.actors_settings(&role)? {
                continue;
            }
            matching |= result.role_tasks_settings(cli, cred, &role, &mut opt_stack, env_path)?;
            Api::notify(ApiEvent::BestRoleSettingsFound(
                cli,
                cred,
                &role,
                &mut opt_stack,
                &env_path,
                &mut result,
                &mut matching,
            ))?;
        }
        if !matching {
            return Err(SrError::PermissionDenied);
        }
        let env =
            opt_stack.calc_temp_env(opt_stack.calc_override_behavior(), cli.opt_filter.as_ref());
        result.env_filter = env.filter();
        result.env = env
            .final_env(
                env_vars,
                opt_stack.calc_path(env_path),
                cred,
                result.cred.setuid.as_ref(),
                format!(
                    "{}{}",
                    cli.cmd_path.display(),
                    if cli.cmd_args.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", cli.cmd_args.join(" "))
                    }
                ),
            )
            .ok_or_else(|| {
                error!("Internal Error with environment behavior");
                SrError::ConfigurationError
            })?;
        result.auth = opt_stack.calc_authentication();
        result.bounding = opt_stack.calc_bounding();
        result.timeout = opt_stack.calc_timeout();
        result.password = opt_stack.calc_password();
        result.root = opt_stack.calc_privileged();
        result.umask = opt_stack.calc_umask();
        result.workdir = opt_stack.calc_workdir();
        Ok(result)
    }

    /// What `retrieve_settings` does for one role, for the tests.
    #[cfg(test)]
    pub fn role_settings<'c, 'a>(
        &mut self,
        cli: &'c Cli,
        cred: &'c Cred,
        data: &DLinkedRole<'c, 'a>,
        opt_stack: &mut BorrowedOptStack<'c, 'a>,
        env_path: &[&str],
    ) -> SrResult<bool> {
        debug!("role_settings: {:?}", data.role().role);
        if !self.actors_settings(data)? {
            return Ok(false);
        }
        self.role_tasks_settings(cli, cred, data, opt_stack, env_path)
    }

    /// The tasks of a role that the user holds.
    fn role_tasks_settings<'c, 'a>(
        &mut self,
        cli: &'c Cli,
        cred: &'c Cred,
        data: &DLinkedRole<'c, 'a>,
        opt_stack: &mut BorrowedOptStack<'c, 'a>,
        env_path: &[&str],
    ) -> SrResult<bool> {
        let mut res = false;
        for task in data.tasks() {
            res |= self.task_settings(cli, cred, &task, opt_stack, env_path)?;
        }
        Ok(res)
    }

    pub fn actors_settings(&mut self, data: &DLinkedRole<'_, '_>) -> SrResult<bool> {
        let mut res = !data.role().user_min.is_no_match();
        Api::notify(ApiEvent::ActorMatching(data, self, &mut res))?;
        Ok(res)
    }

    pub fn task_settings<'t, 'c, 'a>(
        &mut self,
        cli: &'t Cli,
        cred: &'t Cred,
        data: &DLinkedTask<'t, 'c, 'a>,
        opt_stack: &mut BorrowedOptStack<'c, 'a>,
        env_path: &[&str],
    ) -> SrResult<bool> {
        let held_through = data.role().role().user_min;
        self.task_settings_as(cli, cred, data, held_through, opt_stack, env_path)
    }

    /// `task_settings` for a task that the user holds through the actors `held_through`: those
    /// of its own role, or those of a senior role (hierarchy plugin). The task is scored with them.
    #[allow(clippy::too_many_lines)]
    pub fn task_settings_as<'t, 'c, 'a>(
        &mut self,
        cli: &'t Cli,
        cred: &'t Cred,
        data: &DLinkedTask<'t, 'c, 'a>,
        held_through: ActorMatchMin,
        opt_stack: &mut BorrowedOptStack<'c, 'a>,
        env_path: &[&str],
    ) -> SrResult<bool> {
        debug!("task_settings: {:?}", data.id);
        let temp_opt_stack = BorrowedOptStack::from_task(data);
        if let Some(entry) = temp_opt_stack.invalid_env_entry() {
            error!(
                "task_settings: deny task {:?}: invalid environment entry `{entry}`, it must be a variable name where `*` matches any characters",
                data.id
            );
            return Ok(false);
        }
        // the PATH of this task: its commands are resolved in it, and it is kept if the task wins
        let mut task_env_path = None;
        // We must do this check for each task as long they could have different options
        // These checks are a small optimization to avoid useless command checks
        if cli
            .opt_filter
            .as_ref()
            .is_some_and(|f| f.env_behavior.is_some() && !temp_opt_stack.calc_override_behavior())
        {
            debug!(
                "task_settings: deny task due to inherited from role or config env_override requirement"
            );
            return Ok(false);
        }
        // The command runs in the directory asked with -D, else in the fallback of the policy,
        // else in the current directory: only a directory chosen by the user is checked.
        let workdir = temp_opt_stack.get_workdir_temp();
        let requested = cli.opt_filter.as_ref().and_then(|f| f.workdir.as_ref());
        if let Some(requested) = requested {
            if Self::allowed_workdir(&workdir, requested).is_false() {
                debug!(
                    "task_settings: deny task due to the user wanted to execute to a specific folder, which do not match to settings"
                );
                return Ok(false);
            }
        } else if workdir.fallback.is_none()
            && Self::allowed_workdir(&workdir, cred.curdir.as_os_str().to_string_lossy().as_ref())
                .is_false()
        {
            debug!(
                "task_settings: deny task due to the current directory do not match to allowed settings"
            );
            return Ok(false);
        }
        if cli.info && temp_opt_stack.calc_info().is_hide() {
            debug!("task_settings: deny task due to inherited from role or config info hide");
            return Ok(false);
        }
        // The task is evaluated on its own: the best settings found so far are only replaced
        // if its full score is better, so a task cannot change how the next ones are compared.
        let mut task_cmd_min = CmdMin::empty();
        let mut task_final_path = None;
        if let Some(commands) = data.commands() {
            let t_env_path = temp_opt_stack.calc_path(env_path);
            let t_env_path_ref: Vec<&str> = t_env_path.iter().map(String::as_str).collect();
            for command in commands.del() {
                if Self::match_command(&t_env_path_ref, cli, &command)?.is_some() {
                    debug!("task_settings: deny task, the command is in its deny list");
                    return Ok(false);
                }
            }
            if commands.default_behavior.is_some_and(|b| b.is_all()) {
                debug!("default behavior is all");
                debug!("{}", &cli.cmd_path.display());
                task_final_path = Some(
                    resolve_any_command(&cli.cmd_path, &t_env_path_ref)
                        .ok_or(SrError::ExecutionFailed)?,
                );
                // any command with any arguments, like a "**" rule
                task_cmd_min = CmdMin::builder()
                    .matching()
                    .order(CmdOrder::FullWildcardPath | CmdOrder::FullRegexArgs)
                    .build();
            } else {
                for command in commands.add() {
                    if let Some((cmd_min, final_path)) =
                        Self::match_command(&t_env_path_ref, cli, &command)?
                        && cmd_min.better(task_cmd_min)
                    {
                        task_cmd_min = cmd_min;
                        task_final_path = Some(final_path);
                    }
                }
            }
            task_env_path = Some(t_env_path);
        }
        let found = task_cmd_min.matching();
        let mut score = data.score(task_cmd_min, temp_opt_stack.calc_security_min());
        score.set_role_score(&held_through);
        Api::notify(ApiEvent::BestTaskSettingsFound(
            cli, data, opt_stack, self, &mut score,
        ))?;
        let task_address = std::ptr::from_ref(data.task).addr();
        if found
            && task_final_path.is_some()
            && score.fully_matching()
            && !score.better_fully(&self.score)
            && score.cmp(&self.score) == Ordering::Equal
            && self.best_task != Some(task_address)
        {
            // as good as the best task, which is fully matching since this one is not better
            debug!("task {:?} is as good as the best task", data.id);
            self.tie
                .get_or_insert_with(|| format!("{}/{}", data.role().role().role, data.id));
        }
        if found
            && let Some(final_path) = task_final_path
            && score.better_fully(&self.score)
        {
            // a task whose user or groups do not exist cannot run as written: it is left out like
            // a task that does not match, so that it tells nothing more before the authentication
            let (setuid, setgroups) = match resolve_cred(&data.cred) {
                Ok(cred) => cred,
                Err(missing) => {
                    error!(
                        "The task {}/{} cannot run: {missing} does not exist or cannot be read",
                        data.role().role().role,
                        data.id
                    );
                    return Ok(found);
                }
            };
            debug!("found better task settings");
            self.best_task = Some(task_address);
            // a tie with the previous best task does not matter anymore
            self.tie = None;
            self.final_path = final_path;
            self.role = data.role().role().role.to_string();
            self.task = Some(data.id.to_string());
            self.env_path = task_env_path.unwrap_or_else(|| temp_opt_stack.calc_path(env_path));
            self.score = score;
            self.cred.setuid = setuid;
            self.cred.setgroups = setgroups;
            self.cred.groups_from = data.cred.groups_from;
            self.cred.caps = data.cred.caps;
            opt_stack.set_role(data);
            opt_stack.set_task(data);
            debug!("resulting settings: {self:?}");
        }

        Ok(found)
    }

    /// How a command of the policy matches the command line: its score and the path to run,
    /// or `None` if it does not match. The best settings found so far are not changed.
    pub fn match_command<'d>(
        env_path: &[&str],
        cli: &'d Cli,
        data: &DLinkedCommand<'d, '_, '_, '_, '_>,
    ) -> SrResult<Option<(CmdMin, PathBuf)>> {
        debug!("env_path: {env_path:?}");
        let mut final_path = None;
        let cmd_min = match &**data {
            de::DCommand::Simple(role_cmd) => cmd::evaluate_command_match(
                env_path,
                &cli.cmd_path,
                &cli.cmd_args,
                role_cmd,
                CmdMin::empty(),
                &mut final_path,
            ),
            de::DCommand::Complex(value) => {
                let mut cmd_min = CmdMin::empty();
                Api::notify(ApiEvent::ProcessComplexCommand(
                    value,
                    env_path,
                    &cli.cmd_path,
                    &cli.cmd_args,
                    &mut cmd_min,
                    &mut final_path,
                ))?;
                cmd_min
            }
        };
        Ok(final_path
            .filter(|_| cmd_min.matching())
            .map(|final_path| (cmd_min, final_path)))
    }

    /// This function takes a workdir path, and returns whether it is allowed based on the workdir settings.
    fn allowed_workdir(result: &ResolvedWorkdir<'_>, workdir: &str) -> HardenedBool {
        hardened_bool_from_bool(result.allows(workdir))
    }
}

#[cfg(test)]
mod tests {
    use super::de::{DCommand, DCommandList, DRoleFinder, DTaskFinder, IdTask};
    use super::*;
    use capctl::CapSet;
    use rootasrole_core::database::FilterMatcher;
    use rootasrole_core::database::options::{EnvBehavior, Level, SInfo};
    use rootasrole_core::database::score::{ActorMatchMin, CmdMin};
    use rootasrole_core::database::structs::SetBehavior;
    use serde_json::Value;
    use std::path::PathBuf;

    use crate::Cli;
    use crate::finder::de::cred::CredData;
    use crate::finder::options::{DEnvOptions, DPathOptions, Opt};
    use rootasrole_core::Cred;
    use test_log::test;

    // Helper: Dummy implementations for required traits/structs
    fn dummy_cli() -> Cli {
        Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .build()
    }

    fn dummy_cred() -> Cred {
        Cred::builder()
            .curdir()
            .unwrap()
            .groups()
            .unwrap()
            .user()
            .unwrap()
            .build()
    }

    fn dummy_dconfigfinder<'a>() -> DConfigFinder<'a> {
        DConfigFinder::builder()
            .roles(vec![
                DRoleFinder::builder()
                    .user_min(ActorMatchMin::UserMatch)
                    .role("test")
                    .tasks(vec![
                        DTaskFinder::builder()
                            .id(IdTask::Number(0))
                            .cred(CredData::builder().caps(!CapSet::empty()).build())
                            .commands(
                                DCommandList::builder(SetBehavior::None)
                                    .add(vec![DCommand::simple("/usr/bin/ls -l")])
                                    .build(),
                            )
                            .options(Opt::builder(Level::Task).execinfo(SInfo::Hide).build())
                            .build(),
                        DTaskFinder::builder()
                            .id(IdTask::Number(1))
                            .cred(CredData::builder().caps(CapSet::empty()).build())
                            .commands(
                                DCommandList::builder(SetBehavior::None)
                                    .add(vec![
                                        DCommand::simple("/usr/bin/ls ^.*$"),
                                        DCommand::complex(Value::Object(
                                            std::iter::once((
                                                "key".to_string(),
                                                Value::String("value".into()),
                                            ))
                                            .collect::<serde_json::Map<String, Value>>(),
                                        )),
                                    ])
                                    .build(),
                            )
                            .options(
                                Opt::builder(Level::Task)
                                    .execinfo(SInfo::Show)
                                    .env(
                                        DEnvOptions::builder(EnvBehavior::Delete)
                                            .override_behavior(true)
                                            .build(),
                                    )
                                    .build(),
                            )
                            .build(),
                    ])
                    .build(),
                DRoleFinder::builder()
                    .user_min(ActorMatchMin::UserMatch)
                    .role("test2")
                    .tasks(vec![
                        DTaskFinder::builder()
                            .id(IdTask::Number(0))
                            .cred(CredData::builder().caps(!CapSet::empty()).build())
                            .commands(
                                DCommandList::builder(SetBehavior::None)
                                    .add(vec![DCommand::simple("/usr/bin/ls -l")])
                                    .build(),
                            )
                            .options(
                                Opt::builder(Level::Task)
                                    .execinfo(SInfo::Show)
                                    .env(
                                        DEnvOptions::builder(EnvBehavior::Delete)
                                            .override_behavior(true)
                                            .build(),
                                    )
                                    .build(),
                            )
                            .build(),
                        DTaskFinder::builder()
                            .id(IdTask::Number(1))
                            .cred(CredData::builder().caps(CapSet::empty()).build())
                            .commands(
                                DCommandList::builder(SetBehavior::None)
                                    .add(vec![DCommand::simple("/usr/bin/ls ^.*$")])
                                    .build(),
                            )
                            .options(Opt::builder(Level::Task).execinfo(SInfo::Hide).build())
                            .build(),
                    ])
                    .build(),
            ])
            .build()
    }

    #[test]
    fn test_retrieve_settings_no_matching_role() {
        let cli = Cli::builder().cmd_path("/usr/bin/cat".to_string()).build();
        let cred = dummy_cred();
        let data = dummy_dconfigfinder();
        let env_vars = vec![("KEY", "VALUE")];
        let env_path = &["/bin"];
        let result = BestExecSettings::retrieve_settings(&cli, &cred, &data, env_vars, env_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_a_task_that_changes_the_user_gets_its_groups() {
        let root = User::from_uid(nix::unistd::Uid::from_raw(0))
            .unwrap()
            .unwrap();
        let settings = |setuid: Option<User>, groups_from, setgroups| BestExecSettings {
            cred: CredOwnedData::builder()
                .maybe_setuid(setuid)
                .maybe_groups_from(groups_from)
                .maybe_setgroups(setgroups)
                .build(),
            ..Default::default()
        };
        // setuid without setgid: the groups of the target user, its primary group first
        for groups_from in [None, Some(GroupsFrom::Target)] {
            let groups = settings(Some(root.clone()), groups_from, None)
                .with_target_groups()
                .unwrap()
                .cred
                .setgroups
                .unwrap();
            assert_eq!(groups[0].gid, root.gid, "{groups_from:?}");
            assert_eq!(groups, login_groups(&root).unwrap());
        }
        // from: caller, a task that keeps the user, and forced groups are left as they are
        let caller = settings(Some(root.clone()), Some(GroupsFrom::Caller), None);
        assert!(
            caller
                .with_target_groups()
                .unwrap()
                .cred
                .setgroups
                .is_none()
        );
        let same_user = settings(None, None, None);
        assert!(
            same_user
                .with_target_groups()
                .unwrap()
                .cred
                .setgroups
                .is_none()
        );
        let forced = Group::from_gid(root.gid).unwrap().unwrap();
        let forced_settings = settings(Some(root.clone()), None, Some(vec![forced.clone()]));
        assert_eq!(
            forced_settings.with_target_groups().unwrap().cred.setgroups,
            Some(vec![forced])
        );
        // a lookup that fails refuses the command instead of keeping the groups of the caller
        let mut broken = root;
        broken.name = "bro\0ken".into();
        assert!(
            settings(Some(broken), None, None)
                .with_target_groups()
                .is_err()
        );
    }

    #[test]
    fn test_retrieve_settings_with_matching_role() {
        let cli = dummy_cli();
        let cred = dummy_cred();
        let data = dummy_dconfigfinder();
        let env_vars = vec![("KEY", "VALUE")];
        let env_path = &["/UNWANTED"];
        let result = BestExecSettings::retrieve_settings(&cli, &cred, &data, env_vars, env_path);
        assert!(result.is_ok());
        let settings = result.unwrap();
        assert_eq!(settings.final_path, PathBuf::from("/usr/bin/ls"));
        assert_eq!(settings.role, "test");
        assert_eq!(settings.task, Some("0".to_string()));
        assert!(settings.cred.setuid.is_none());
        assert!(settings.cred.setgroups.is_none());
        assert!(settings.cred.caps.is_some());
        assert!(!settings.env.is_empty());
        assert!(!settings.env_path.is_empty());
        assert!(settings.env_path.iter().all(|p| p != "/UNWANTED"));
    }

    #[test]
    fn test_commands_are_resolved_with_the_path_of_their_task() {
        let path = |dir: &'static str| {
            Opt::builder(Level::Task)
                .path(
                    DPathOptions::builder(rootasrole_core::database::options::PathBehavior::Delete)
                        .add([dir])
                        .build(),
                )
                .build()
        };
        let data = DConfigFinder::builder()
            .options(path("/nonexistent"))
            .roles(vec![
                DRoleFinder::builder()
                    .user_min(ActorMatchMin::UserMatch)
                    .role("test")
                    .tasks(vec![
                        DTaskFinder::builder()
                            .id(IdTask::Number(0))
                            .cred(CredData::builder().build())
                            .commands(DCommandList::builder(SetBehavior::All).build())
                            .options(path("/usr/bin"))
                            .build(),
                    ])
                    .build(),
            ])
            .build();
        let cli = Cli::builder().cmd_path("ls".to_string()).build();
        let settings = BestExecSettings::retrieve_settings(
            &cli,
            &dummy_cred(),
            &data,
            vec![("KEY", "VALUE")],
            &["/bin"],
        )
        .expect("the task allows every command in its PATH");
        assert_eq!(settings.final_path, PathBuf::from("/usr/bin/ls"));
        assert_eq!(settings.env_path, ["/usr/bin"]);
    }

    /// A task allowing `commands` (JSON), with its capabilities, one kept variable and its PATH.
    fn task_json(name: &str, caps: &[&str], commands: &str, keep: &str, path: &str) -> String {
        format!(
            r#"{{"name":"{name}","cred":{{"caps":{caps}}},"commands":{commands},"options":{{"env":{{"default":"delete","keep":["{keep}"]}},"path":{{"default":"delete","add":["{path}"]}}}}}}"#,
            caps = serde_json::to_string(caps).unwrap()
        )
    }

    /// The best task found by dosr for `cmd`: the policy is deserialized first, which drops
    /// the tasks that cannot match, then the remaining tasks are compared.
    /// Returns the task, the command, the PATH and the variables kept among `A_VAR`, `B_VAR`, `C_VAR`.
    fn best_task(
        tasks: &[&String],
        cmd: &str,
    ) -> SrResult<(String, PathBuf, Vec<String>, Vec<String>)> {
        best_task_for(tasks, &Cli::builder().cmd_path(cmd.to_string()).build())
    }

    /// `best_task` for a command line with options.
    fn best_task_for(
        tasks: &[&String],
        cli: &Cli,
    ) -> SrResult<(String, PathBuf, Vec<String>, Vec<String>)> {
        use serde::de::DeserializeSeed;
        let policy = format!(
            r#"{{"roles":[{{"name":"r","actors":[{{"type":"user","id":{}}}],"tasks":[{}]}}]}}"#,
            nix::unistd::getuid(),
            tasks
                .iter()
                .map(|task| task.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        let cred = dummy_cred();
        let env_path = ["/usr/bin"];
        let data = super::de::ConfigFinderDeserializer { cli, cred: &cred }
            .deserialize(&mut serde_json::Deserializer::from_str(&policy))
            .expect("valid policy");
        let user_env = vec![("A_VAR", "a"), ("B_VAR", "b"), ("C_VAR", "c")];
        let settings = BestExecSettings::retrieve_settings(cli, &cred, &data, user_env, &env_path)?;
        let kept = ["A_VAR", "B_VAR", "C_VAR"]
            .into_iter()
            .filter(|var| settings.env.contains_key(*var))
            .map(ToString::to_string)
            .collect();
        Ok((
            settings.task.unwrap_or_default(),
            settings.final_path,
            settings.env_path,
            kept,
        ))
    }

    /// Every order of the tasks.
    fn orders<'t>(tasks: &[&'t String]) -> Vec<Vec<&'t String>> {
        if tasks.len() <= 1 {
            return vec![tasks.to_vec()];
        }
        (0..tasks.len())
            .flat_map(|first| {
                let mut rest = tasks.to_vec();
                let first = rest.remove(first);
                orders(&rest).into_iter().map(move |mut order| {
                    order.insert(0, first);
                    order
                })
            })
            .collect()
    }

    #[test]
    fn test_best_task_needs_the_fewest_privileges_in_any_order() {
        let a = task_json(
            "a",
            &["CAP_NET_RAW"],
            r#"["/usr/bin/ls"]"#,
            "A_VAR",
            "/usr/bin",
        );
        let b = task_json("b", &[], r#"["/usr/bin/ls"]"#, "B_VAR", "/usr/bin");
        for tasks in orders(&[&a, &b]) {
            let (task, _, _, kept) = best_task(&tasks, "/usr/bin/ls").unwrap();
            // same command, but b needs no capability
            assert_eq!(task, "b", "{tasks:?}");
            assert_eq!(kept, ["B_VAR"], "{tasks:?}");
        }
    }

    #[test]
    fn test_best_task_needs_no_critical_capability_in_any_order() {
        let a = task_json(
            "a",
            &["CAP_NET_BIND_SERVICE"],
            r#"["/usr/bin/ls"]"#,
            "A_VAR",
            "/usr/bin",
        );
        let b = task_json(
            "b",
            &["CAP_SYS_ADMIN"],
            r#"["/usr/bin/ls"]"#,
            "B_VAR",
            "/usr/bin",
        );
        let c = task_json("c", &[], r#"["/usr/bin/ls"]"#, "C_VAR", "/usr/bin")
            .replace(r#""caps":[]"#, r#""caps":"all""#);
        for tasks in orders(&[&a, &b, &c]) {
            let (task, _, _, kept) = best_task(&tasks, "/usr/bin/ls").unwrap();
            // CAP_NET_BIND_SERVICE is the only capability that is not critical
            assert_eq!(task, "a", "{tasks:?}");
            assert_eq!(kept, ["A_VAR"], "{tasks:?}");
        }
    }

    #[test]
    fn test_tie_between_the_best_tasks_is_refused_in_any_order() {
        // same command and same privileges: none of them is less privileged than the other
        let a = task_json("a", &[], r#"["/usr/bin/ls"]"#, "A_VAR", "/usr/bin");
        let b = task_json("b", &[], r#"["/usr/bin/ls"]"#, "B_VAR", "/usr/bin");
        // a worse task does not resolve it
        let c = task_json(
            "c",
            &["CAP_NET_RAW"],
            r#"["/usr/bin/ls"]"#,
            "C_VAR",
            "/usr/bin",
        );
        for tasks in orders(&[&a, &b, &c]) {
            assert!(
                matches!(
                    best_task(&tasks, "/usr/bin/ls"),
                    Err(SrError::PermissionDenied)
                ),
                "{tasks:?}"
            );
        }
        // the user selects one of them
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .opt_filter(
                FilterMatcher::builder()
                    .role("r".to_string())
                    .task("b".to_string())
                    .build(),
            )
            .build();
        for tasks in orders(&[&a, &b, &c]) {
            let (task, _, _, kept) = best_task_for(&tasks, &cli).unwrap();
            assert_eq!(task, "b", "{tasks:?}");
            assert_eq!(kept, ["B_VAR"], "{tasks:?}");
        }
    }

    #[test]
    fn test_tie_between_worse_tasks_does_not_matter() {
        // a and b are as good as each other, c needs fewer privileges than both
        let a = task_json(
            "a",
            &["CAP_NET_RAW"],
            r#"["/usr/bin/ls"]"#,
            "A_VAR",
            "/usr/bin",
        );
        let b = task_json(
            "b",
            &["CAP_NET_RAW"],
            r#"["/usr/bin/ls"]"#,
            "B_VAR",
            "/usr/bin",
        );
        let c = task_json("c", &[], r#"["/usr/bin/ls"]"#, "C_VAR", "/usr/bin");
        for tasks in orders(&[&a, &b, &c]) {
            let (task, _, _, kept) = best_task(&tasks, "/usr/bin/ls").unwrap();
            assert_eq!(task, "c", "{tasks:?}");
            assert_eq!(kept, ["C_VAR"], "{tasks:?}");
        }
    }

    #[test]
    fn test_losing_task_does_not_leak_into_the_result() {
        let a = task_json("a", &[], r#"["/usr/bin/ls"]"#, "A_VAR", "/usr/bin");
        // every command, with more privileges, its own variable and PATH
        let b = task_json(
            "b",
            &["CAP_NET_RAW"],
            r#"{"default":"all"}"#,
            "B_VAR",
            "/bin",
        );
        for tasks in orders(&[&a, &b]) {
            let (task, final_path, env_path, kept) = best_task(&tasks, "ls").unwrap();
            assert_eq!(task, "a", "{tasks:?}");
            assert_eq!(final_path, PathBuf::from("/usr/bin/ls"), "{tasks:?}");
            assert_eq!(env_path, ["/usr/bin"], "{tasks:?}");
            assert_eq!(kept, ["A_VAR"], "{tasks:?}");
        }
    }

    #[test]
    fn test_losing_task_does_not_degrade_the_best_score() {
        let a = task_json("a", &[], r#"["/usr/bin/ls -l"]"#, "A_VAR", "/usr/bin");
        let b = task_json(
            "b",
            &["CAP_NET_RAW"],
            r#"{"default":"all"}"#,
            "B_VAR",
            "/usr/bin",
        );
        // a regex on the arguments is a worse match than a exact command
        let c = task_json("c", &[], r#"["/usr/bin/ls ^.*$"]"#, "C_VAR", "/usr/bin");
        let cli = crate::getopt(["dosr", "ls", "-l"]).unwrap();
        for tasks in orders(&[&a, &b, &c]) {
            let (task, _, _, kept) = best_task_for(&tasks, &cli).unwrap();
            assert_eq!(task, "a", "{tasks:?}");
            assert_eq!(kept, ["A_VAR"], "{tasks:?}");
        }
    }

    #[test]
    fn test_command_without_arguments_allows_none() {
        let none = task_json("none", &[], r#"["/usr/bin/ls"]"#, "A_VAR", "/usr/bin");
        let any = task_json("any", &[], r#"["/usr/bin/ls ^.*$"]"#, "B_VAR", "/usr/bin");
        let with_args = crate::getopt(["dosr", "ls", "-l"]).unwrap();
        let without_args = crate::getopt(["dosr", "ls"]).unwrap();
        // alone, a command without arguments does not allow ls -l
        assert!(best_task_for(&[&none], &with_args).is_err());
        for tasks in orders(&[&none, &any]) {
            assert_eq!(
                best_task_for(&tasks, &with_args).unwrap().0,
                "any",
                "{tasks:?}"
            );
            // without arguments, the exact rule is more precise than any arguments
            assert_eq!(
                best_task_for(&tasks, &without_args).unwrap().0,
                "none",
                "{tasks:?}"
            );
        }
    }

    #[test]
    fn test_denied_command_only_denies_its_own_task() {
        // every command except ls
        let d = task_json(
            "d",
            &["CAP_NET_RAW"],
            r#"{"default":"all","del":["/usr/bin/ls"]}"#,
            "B_VAR",
            "/usr/bin",
        );
        let c = task_json("c", &[], r#"["/usr/bin/ls ^.*$"]"#, "C_VAR", "/usr/bin");
        for tasks in orders(&[&d, &c]) {
            let (task, final_path, _, _) = best_task(&tasks, "ls").unwrap();
            assert_eq!(task, "c", "{tasks:?}");
            assert_eq!(final_path, PathBuf::from("/usr/bin/ls"), "{tasks:?}");
        }
        // alone, d cannot run ls
        assert!(best_task(&[&d], "ls").is_err());
    }

    #[test]
    fn test_forced_workdir_is_not_checked_against_the_current_directory() {
        let task =
            r#"{"name":"w","cred":{},"commands":["/usr/bin/ls"],"options":{"workdir":"/srv"}}"#
                .to_string();
        // the current directory of the tests is not allowed, but the command runs in /srv
        let (task, final_path, _, _) = best_task(&[&task], "/usr/bin/ls").unwrap();
        assert_eq!(task, "w");
        assert_eq!(final_path, PathBuf::from("/usr/bin/ls"));
        // without a forced directory, the current directory must be allowed
        let task = r#"{"name":"w","cred":{},"commands":["/usr/bin/ls"],"options":{"workdir":{"default":"none","add":["/srv"]}}}"#
            .to_string();
        assert!(best_task(&[&task], "/usr/bin/ls").is_err());
    }

    #[test]
    fn test_any_binary_pattern() {
        let task = r#"{"name":"any","cred":{},"commands":["**"]}"#.to_string();
        let (name, final_path, _, _) = best_task(&[&task], "/usr/bin/ls").unwrap();
        assert_eq!(name, "any");
        assert_eq!(final_path, PathBuf::from("/usr/bin/ls"));
        // a name is resolved in the PATH of the task
        let (_, final_path, env_path, _) = best_task(&[&task], "ls").unwrap();
        assert!(
            env_path
                .iter()
                .any(|dir| final_path == Path::new(dir).join("ls"))
        );
        // a name that is not in PATH cannot be run
        assert!(best_task(&[&task], "rar-no-such-command").is_err());
        // an exact command is a better match than any binary
        let exact = task_json("exact", &[], r#"["/usr/bin/ls"]"#, "A_VAR", "/usr/bin");
        for tasks in orders(&[&task, &exact]) {
            assert_eq!(best_task(&tasks, "ls").unwrap().0, "exact");
        }
    }

    /// A directory that only the current user can write, removed with the test.
    struct PolicyDir(PathBuf);

    impl PolicyDir {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("rar-finder-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            set_mode(&dir, 0o700);
            Self(dir)
        }
    }

    impl Drop for PolicyDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Write `content` in the format of `method`, with the permissions `mode`.
    fn write_file(path: &Path, content: &Value, method: StorageMethod, mode: u32) {
        let bytes = match method {
            StorageMethod::JSON => serde_json::to_vec(content).unwrap(),
            StorageMethod::CBOR => cbor4ii::serde::to_vec(Vec::new(), content).unwrap(),
        };
        std::fs::write(path, bytes).unwrap();
        set_mode(path, mode);
    }

    /// Root settings whose policy is `data` (a file or a directory), with `roles` inline.
    fn root_settings(method: StorageMethod, data: &Path, roles: Value) -> Value {
        let mut settings = serde_json::json!({
            "version": rootasrole_core::PACKAGE_VERSION.to_string(),
            "storage": {
                "method": method,
                "settings": {"path": data, "immutable": false}
            }
        });
        settings["roles"] = roles;
        settings
    }

    /// A policy document with `roles`.
    fn policy(roles: Value) -> Value {
        let mut policy =
            serde_json::json!({ "version": rootasrole_core::PACKAGE_VERSION.to_string() });
        policy["roles"] = roles;
        policy
    }

    /// A role of the current user, with one task allowing `command` with `caps`.
    fn user_role(task: &str, command: &str, caps: &[&str]) -> Value {
        serde_json::json!([{
            "name": "r",
            "actors": [{"type": "user", "id": nix::unistd::getuid().as_raw()}],
            "tasks": [{"name": task, "cred": {"caps": caps}, "commands": [command]}]
        }])
    }

    /// The task that dosr chooses for `cmd`, from the root settings file `root`.
    fn find(root: &Path, method: StorageMethod, cmd: &str) -> SrResult<String> {
        let cli = Cli::builder().cmd_path(cmd.to_string()).build();
        find_best_exec_settings(
            &cli,
            &dummy_cred(),
            root,
            root,
            method,
            vec![("A", "B")],
            &["/usr/bin"],
        )
        .map(|settings| settings.task.unwrap_or_default())
    }

    /// The final policy of the book, under its heading in `book/src/configuration.md`, or `None`
    /// when the book is not in this source tree: the crate and the Debian sources leave it out.
    fn book_policy() -> Option<Value> {
        let page = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("book/src/configuration.md"),
        )
        .ok()?;
        let section = &page[page.find("## The complete WebOps policy")?..];
        let start = section.find("```json\n")? + "```json\n".len();
        let end = section[start..].find("\n```")? + start;
        Some(serde_json::from_str(&section[start..end]).expect("the policy of the book is JSON"))
    }

    #[test]
    fn test_the_policy_of_the_book() {
        let Some(mut policy) = book_policy() else {
            eprintln!("skipped: the book is not in this source tree");
            return;
        };
        rootasrole_core::database::migrations::migrate_document(&mut policy).unwrap();
        serde_json::from_value::<rootasrole_core::database::structs::SPolicy>(policy.clone())
            .expect("rootasrole-core reads the policy of the book");
        // the current user takes the place of the team, but not of sys-admin, which excludes
        // caddy-admin
        let uid = nix::unistd::getuid().as_raw();
        for role in policy["roles"].as_array_mut().unwrap() {
            if role["name"] != "sys-admin" {
                role["actors"] = serde_json::json!([{"type": "user", "id": uid}]);
            }
        }
        let dir = PolicyDir::new("book");
        let file = dir.0.join("default.json");
        write_file(&file, &policy, StorageMethod::JSON, 0o600);
        let root = dir.0.join("rootasrole.json");
        write_file(
            &root,
            &root_settings(StorageMethod::JSON, &file, serde_json::json!([])),
            StorageMethod::JSON,
            0o600,
        );
        let decide = |cmd: &str, args: &[&str]| -> Option<String> {
            let cli = Cli::builder()
                .cmd_path(cmd)
                .cmd_args(args.iter().map(ToString::to_string))
                .build();
            find_best_exec_settings(
                &cli,
                &dummy_cred(),
                &root,
                &root,
                StorageMethod::JSON,
                vec![("A", "B")],
                &["/usr/bin"],
            )
            .ok()
            .filter(|settings| settings.score.fully_matching())
            .and_then(|settings| settings.task)
        };
        let log = "/var/log/caddy/access.log";
        assert_eq!(
            decide("/usr/bin/tail", &["-n", "50", log]).as_deref(),
            Some("read-logs")
        );
        assert_eq!(
            decide("/usr/bin/tail", &["-f", log]).as_deref(),
            Some("read-logs")
        );
        assert_eq!(
            decide("/usr/bin/journalctl", &["--no-pager", "-u", "caddy"]).as_deref(),
            Some("read-logs")
        );
        // the path traversal of the chapter
        let traversal = "/var/log/caddy/../../../etc/shadow";
        assert_eq!(decide("/usr/bin/tail", &["-n", "50", traversal]), None);
        assert_eq!(decide("/usr/bin/less", &[traversal]), None);
        // the pager of systemctl, without --no-pager
        assert_eq!(decide("/usr/bin/systemctl", &["status", "caddy"]), None);
        assert_eq!(
            decide("/usr/bin/systemctl", &["status", "--no-pager", "caddy"]).as_deref(),
            Some("caddy-service")
        );
        assert_eq!(
            decide("/usr/bin/systemctl", &["restart", "caddy"]).as_deref(),
            Some("caddy-service")
        );
        assert_eq!(decide("/usr/bin/systemctl", &["restart", "sshd"]), None);
        // alice's escape: more arguments than the regular expression allows
        let escape = [
            "-d",
            "-m",
            "777",
            "-o",
            "alice",
            "-g",
            "alice",
            "/srv/www/x",
            "/etc",
        ];
        assert_eq!(decide("/usr/bin/install", &escape), None);
        // the user of web-push is www-data, which not every distribution has
        if User::from_name("www-data").ok().flatten().is_some() {
            assert_eq!(
                decide("/usr/bin/install", &["-d", "-m", "755", "/srv/www/site"]).as_deref(),
                Some("web-push")
            );
        }
        // the root-equivalent tasks of sys-admin are not held
        assert_eq!(decide("/usr/bin/systemctl", &["reboot"]), None);
    }

    #[test]
    fn test_a_task_whose_credentials_do_not_resolve_is_left_out() {
        let task = |name: &str, cred: Value| serde_json::json!({"name": name, "cred": cred, "commands": ["/usr/bin/ls -l"]});
        let role = |tasks: Vec<Value>| {
            serde_json::json!([{
                "name": "r",
                "actors": [{"type": "user", "id": nix::unistd::getuid().as_raw()}],
                "tasks": tasks
            }])
        };
        let decide = |roles: Value| {
            let dir = PolicyDir::new("unresolved");
            let root = dir.0.join("rootasrole");
            write_file(
                &root,
                &root_settings(StorageMethod::JSON, &root, roles),
                StorageMethod::JSON,
                0o600,
            );
            let cli = Cli::builder()
                .cmd_path("/usr/bin/ls")
                .cmd_args(vec!["-l".to_string()])
                .build();
            find_best_exec_settings(
                &cli,
                &dummy_cred(),
                &root,
                &root,
                StorageMethod::JSON,
                vec![("A", "B")],
                &["/usr/bin"],
            )
            .unwrap()
        };
        let broken = || {
            vec![
                task("no-user", serde_json::json!({"setuid": "rar-no-such-user"})),
                task(
                    "no-group",
                    serde_json::json!({"setgid": ["root", "rar-no-such-group"]}),
                ),
            ]
        };
        // the broken tasks are more precise than any, which is chosen
        let mut tasks = broken();
        tasks.push(serde_json::json!({"name": "any", "commands": ["/usr/bin/ls ^.*$"]}));
        assert_eq!(decide(role(tasks)).task.as_deref(), Some("any"));
        // without another task, none is chosen, and the command is refused after authentication
        let settings = decide(role(broken()));
        assert_eq!(settings.task, None);
        assert!(!settings.score.fully_matching());
    }

    #[test]
    fn test_find_best_exec_settings_single_file() {
        for method in [StorageMethod::JSON, StorageMethod::CBOR] {
            let dir = PolicyDir::new(&format!("single-{method}"));
            let root = dir.0.join("rootasrole");
            let roles = user_role("t", "/usr/bin/ls", &[]);
            write_file(&root, &root_settings(method, &root, roles), method, 0o600);
            assert_eq!(find(&root, method, "/usr/bin/ls").unwrap(), "t", "{method}");
            assert!(matches!(
                find(&root, method, "/usr/bin/cat"),
                Err(SrError::PermissionDenied)
            ));
        }
    }

    #[test]
    fn test_immutable_policy_refuses_a_mutable_file() {
        // a file added by someone who could not set the immutable flag (uid 0 without
        // capabilities owns /etc/security), in a policy directory or as the policy file
        let dir = PolicyDir::new("immutable");
        let policies = dir.0.join("policies");
        std::fs::create_dir(&policies).unwrap();
        set_mode(&policies, 0o700);
        let planted = policy(user_role("planted", "/usr/bin/ls", &[]));
        write_file(
            &policies.join("planted.json"),
            &planted,
            StorageMethod::JSON,
            0o600,
        );
        let single = dir.0.join("policy.json");
        write_file(&single, &planted, StorageMethod::JSON, 0o600);
        let root = dir.0.join("rootasrole.json");
        for data in [&policies, &single] {
            let mut settings = root_settings(StorageMethod::JSON, data, serde_json::json!([]));
            write_file(&root, &settings, StorageMethod::JSON, 0o600);
            assert_eq!(
                find(&root, StorageMethod::JSON, "/usr/bin/ls").unwrap(),
                "planted",
                "{}",
                data.display()
            );
            settings["storage"]["settings"]["immutable"] = serde_json::json!(true);
            write_file(&root, &settings, StorageMethod::JSON, 0o600);
            assert!(
                find(&root, StorageMethod::JSON, "/usr/bin/ls").is_err(),
                "{}",
                data.display()
            );
        }
    }

    #[test]
    fn test_find_best_exec_settings_policy_directory() {
        let dir = PolicyDir::new("directory");
        let policies = dir.0.join("policies");
        std::fs::create_dir(&policies).unwrap();
        set_mode(&policies, 0o700);
        let root = dir.0.join("rootasrole.json");
        let settings = root_settings(StorageMethod::JSON, &policies, serde_json::json!([]));
        write_file(&root, &settings, StorageMethod::JSON, 0o600);
        let admin = policy(user_role("admin", "/usr/bin/ls", &["CAP_NET_RAW"]));
        write_file(&policies.join("a.json"), &admin, StorageMethod::JSON, 0o600);
        let least = policy(user_role("least", "/usr/bin/ls", &[]));
        write_file(&policies.join("b.json"), &least, StorageMethod::JSON, 0o600);
        // not a policy: skipped
        std::fs::write(policies.join("c.json"), "not a policy").unwrap();
        set_mode(&policies.join("c.json"), 0o600);
        // the best task of all the files: the same command with fewer privileges
        assert_eq!(
            find(&root, StorageMethod::JSON, "/usr/bin/ls").unwrap(),
            "least"
        );
        // a file with a task as good as the best one: dosr cannot choose
        let tie = policy(user_role("tie", "/usr/bin/ls", &[]));
        write_file(&policies.join("b2.json"), &tie, StorageMethod::JSON, 0o600);
        assert!(matches!(
            find(&root, StorageMethod::JSON, "/usr/bin/ls"),
            Err(SrError::PermissionDenied)
        ));
        // a tie between the worse tasks does not matter
        std::fs::remove_file(policies.join("b2.json")).unwrap();
        let admin2 = policy(user_role("admin2", "/usr/bin/ls", &["CAP_NET_RAW"]));
        write_file(
            &policies.join("a2.json"),
            &admin2,
            StorageMethod::JSON,
            0o600,
        );
        assert_eq!(
            find(&root, StorageMethod::JSON, "/usr/bin/ls").unwrap(),
            "least"
        );
        // a file that other users can write is never used
        let writable = policy(user_role("writable", "/usr/bin/cat", &[]));
        write_file(
            &policies.join("d.json"),
            &writable,
            StorageMethod::JSON,
            0o646,
        );
        assert!(matches!(
            find(&root, StorageMethod::JSON, "/usr/bin/cat"),
            Err(SrError::PermissionDenied)
        ));
    }

    #[test]
    fn test_find_best_exec_settings_refuses_files_writable_by_others() {
        let dir = PolicyDir::new("writable");
        let root = dir.0.join("rootasrole.json");
        let settings = root_settings(
            StorageMethod::JSON,
            &root,
            user_role("t", "/usr/bin/ls", &[]),
        );
        write_file(&root, &settings, StorageMethod::JSON, 0o646);
        assert!(matches!(
            find(&root, StorageMethod::JSON, "/usr/bin/ls"),
            Err(SrError::PermissionDenied)
        ));
        // readable by other users is only a warning
        set_mode(&root, 0o644);
        assert_eq!(
            find(&root, StorageMethod::JSON, "/usr/bin/ls").unwrap(),
            "t"
        );
        // in a directory that other users can write
        set_mode(&dir.0, 0o757);
        let result = find(&root, StorageMethod::JSON, "/usr/bin/ls");
        set_mode(&dir.0, 0o700);
        assert!(matches!(result, Err(SrError::PermissionDenied)));
        // a separate policy file that other users can write
        let data = dir.0.join("policy.json");
        let settings = root_settings(StorageMethod::JSON, &data, serde_json::json!([]));
        write_file(&root, &settings, StorageMethod::JSON, 0o600);
        let roles = policy(user_role("t", "/usr/bin/ls", &[]));
        write_file(&data, &roles, StorageMethod::JSON, 0o646);
        assert!(matches!(
            find(&root, StorageMethod::JSON, "/usr/bin/ls"),
            Err(SrError::PermissionDenied)
        ));
    }

    #[test]
    fn test_find_best_exec_settings_invalid_files() {
        let dir = PolicyDir::new("invalid");
        let root = dir.0.join("rootasrole.json");
        // no root settings file
        assert!(find(&root, StorageMethod::JSON, "/usr/bin/ls").is_err());
        // root settings without their storage section
        let no_storage = policy(user_role("t", "/usr/bin/ls", &[]));
        write_file(&root, &no_storage, StorageMethod::JSON, 0o600);
        assert!(find(&root, StorageMethod::JSON, "/usr/bin/ls").is_err());
        // a policy that cannot be read
        let data = dir.0.join("policy.json");
        let settings = root_settings(StorageMethod::JSON, &data, serde_json::json!([]));
        write_file(&root, &settings, StorageMethod::JSON, 0o600);
        std::fs::write(&data, "not a policy").unwrap();
        set_mode(&data, 0o600);
        assert!(matches!(
            find(&root, StorageMethod::JSON, "/usr/bin/ls"),
            Err(SrError::ConfigurationError)
        ));
    }

    /// The role, task and command chosen for `cmd` with the plugins, from `roles`.
    fn choose(roles: &Value, cmd: &str) -> SrResult<(String, Option<String>, PathBuf)> {
        use serde::de::DeserializeSeed;
        api::register_plugins();
        let policy = serde_json::json!({ "roles": roles }).to_string();
        let cli = Cli::builder().cmd_path(cmd.to_string()).build();
        let cred = dummy_cred();
        let env_path = ["/usr/bin"];
        let data = super::de::ConfigFinderDeserializer {
            cli: &cli,
            cred: &cred,
        }
        .deserialize(&mut serde_json::Deserializer::from_str(&policy))
        .expect("valid policy");
        let settings =
            BestExecSettings::retrieve_settings(&cli, &cred, &data, vec![("A", "B")], &env_path)?;
        Ok((settings.role, settings.task, settings.final_path))
    }

    #[test]
    fn test_actors_in_short_form() {
        let uid = nix::unistd::getuid().as_raw();
        let mut cases = vec![
            (serde_json::json!([{"user": uid}]), true),
            (serde_json::json!([{"user": uid + 54_321}]), false),
        ];
        // the groups of the test process, as dosr sees them
        if let Some(gid) = nix::unistd::getgroups().unwrap().first() {
            let gid = gid.as_raw();
            cases.push((serde_json::json!([{"group": gid}]), true));
            cases.push((serde_json::json!([{"group": [gid]}]), true));
            // a short form is only recognized alone: this actor never matches
            cases.push((serde_json::json!([{"user": uid, "group": gid}]), false));
        }
        for (actors, allowed) in cases {
            let roles = serde_json::json!([role_json(
                "r",
                true,
                Some("/usr/bin/ls"),
                &serde_json::json!({ "actors": actors })
            )]);
            assert_eq!(choose(&roles, "/usr/bin/ls").is_ok(), allowed, "{actors}");
        }
    }

    /// A role with `actors`, one task allowing `command`, and extra fields.
    fn role_json(name: &str, member: bool, command: Option<&str>, extra: &Value) -> Value {
        let uid = nix::unistd::getuid().as_raw();
        // a user id that is not the current user
        let actor = if member { uid } else { uid + 54_321 };
        let mut role = serde_json::json!({
            "name": name,
            "actors": [{"type": "user", "id": actor}],
            "tasks": command.map_or_else(Vec::new, |command| {
                vec![serde_json::json!({"name": format!("{name}_task"), "cred": {}, "commands": [command]})]
            }),
        });
        if let (Some(role), Some(extra)) = (role.as_object_mut(), extra.as_object()) {
            role.extend(extra.clone());
        }
        role
    }

    #[cfg(feature = "ssd")]
    #[test]
    fn test_ssd_plugin() {
        let ssd = |value: Value| serde_json::json!({ "ssd": value });
        let none = serde_json::json!({});
        // the user is a member of both roles: dev is disabled
        for value in [serde_json::json!(["auditor"]), serde_json::json!("auditor")] {
            let roles = serde_json::json!([
                role_json("dev", true, Some("/usr/bin/ls"), &ssd(value)),
                role_json("auditor", true, None, &none),
            ]);
            assert!(matches!(
                choose(&roles, "/usr/bin/ls"),
                Err(SrError::PermissionDenied)
            ));
        }
        // the user is not a member of the conflicting role
        let roles = serde_json::json!([
            role_json(
                "dev",
                true,
                Some("/usr/bin/ls"),
                &ssd(serde_json::json!(["auditor"]))
            ),
            role_json("auditor", false, None, &none),
        ]);
        assert_eq!(choose(&roles, "/usr/bin/ls").unwrap().0, "dev");
        // roles excluding each other, the user is in neither: no endless loop
        let roles = serde_json::json!([
            role_json(
                "a",
                false,
                Some("/usr/bin/ls"),
                &ssd(serde_json::json!(["b"]))
            ),
            role_json("b", false, None, &ssd(serde_json::json!(["a"]))),
            role_json("c", true, Some("/usr/bin/ls"), &none),
        ]);
        assert_eq!(choose(&roles, "/usr/bin/ls").unwrap().0, "c");
        // an invalid value is a configuration error
        let roles = serde_json::json!([role_json(
            "dev",
            true,
            Some("/usr/bin/ls"),
            &ssd(serde_json::json!(3))
        )]);
        assert!(matches!(
            choose(&roles, "/usr/bin/ls"),
            Err(SrError::ConfigurationError)
        ));
    }

    /// The role chosen for `cmd`, after a failed lookup of the actors of the roles `failed`.
    #[cfg(feature = "ssd")]
    fn choose_after_failed_lookups(roles: &Value, cmd: &str, failed: &[&str]) -> SrResult<String> {
        api::register_plugins();
        let policy = serde_json::json!({ "roles": roles }).to_string();
        let cli = Cli::builder().cmd_path(cmd.to_string()).build();
        let cred = dummy_cred();
        let mut data = super::de::ConfigFinderDeserializer {
            cli: &cli,
            cred: &cred,
        }
        .deserialize(&mut serde_json::Deserializer::from_str(&policy))
        .expect("valid policy");
        for role in &mut data.roles {
            role.lookup_failed = failed.contains(&role.role.as_ref());
        }
        BestExecSettings::retrieve_settings(&cli, &cred, &data, vec![("A", "B")], &["/usr/bin"])
            .map(|settings| settings.role)
    }

    #[cfg(feature = "ssd")]
    #[test]
    fn test_a_failed_lookup_disables_the_roles_with_ssd() {
        let none = serde_json::json!({});
        let roles = serde_json::json!([
            role_json(
                "dev",
                true,
                Some("/usr/bin/ls"),
                &serde_json::json!({"ssd": ["auditor"]})
            ),
            role_json("auditor", false, None, &none),
            role_json("ops", true, Some("/usr/bin/cat"), &none),
            role_json("other", false, None, &none),
        ]);
        assert_eq!(
            choose_after_failed_lookups(&roles, "/usr/bin/ls", &[]).unwrap(),
            "dev"
        );
        // whatever role the failed lookup belongs to, the roles with an ssd are disabled
        for failed in ["auditor", "other", "dev"] {
            assert!(
                matches!(
                    choose_after_failed_lookups(&roles, "/usr/bin/ls", &[failed]),
                    Err(SrError::PermissionDenied)
                ),
                "{failed}"
            );
        }
        // the roles without one are not
        assert_eq!(
            choose_after_failed_lookups(&roles, "/usr/bin/cat", &["other"]).unwrap(),
            "ops"
        );
    }

    #[cfg(all(feature = "hierarchy", feature = "ssd"))]
    #[test]
    fn test_a_failed_lookup_disables_the_parents_of_a_role_with_ssd() {
        let none = serde_json::json!({});
        let roles = serde_json::json!([
            role_json(
                "senior",
                true,
                None,
                &serde_json::json!({"parents": ["junior"], "ssd": ["auditor"]})
            ),
            role_json("junior", false, Some("/usr/bin/ls"), &none),
            role_json("auditor", false, None, &none),
        ]);
        assert_eq!(
            choose_after_failed_lookups(&roles, "/usr/bin/ls", &[]).unwrap(),
            "junior"
        );
        assert!(matches!(
            choose_after_failed_lookups(&roles, "/usr/bin/ls", &["auditor"]),
            Err(SrError::PermissionDenied)
        ));
    }

    /// The role and task chosen for `cmd` with `dosr -r role`.
    fn choose_role(roles: &Value, cmd: &str, role: &str) -> SrResult<(String, Option<String>)> {
        api::register_plugins();
        let policy = serde_json::json!({ "roles": roles }).to_string();
        let cli = Cli::builder()
            .cmd_path(cmd.to_string())
            .opt_filter(FilterMatcher::builder().role(role.to_string()).build())
            .build();
        let cred = dummy_cred();
        let data = super::de::ConfigFinderDeserializer {
            cli: &cli,
            cred: &cred,
        }
        .deserialize(&mut serde_json::Deserializer::from_str(&policy))
        .expect("valid policy");
        BestExecSettings::retrieve_settings(&cli, &cred, &data, vec![("A", "B")], &["/usr/bin"])
            .map(|settings| (settings.role, settings.task))
    }

    #[test]
    fn test_role_filter_chooses_among_the_roles() {
        let none = serde_json::json!({});
        let roles = serde_json::json!([
            role_json("first", true, Some("/usr/bin/ls"), &none),
            role_json("second", true, Some("/usr/bin/ls"), &none),
            role_json("other", false, Some("/usr/bin/ls"), &none),
        ]);
        assert_eq!(
            choose_role(&roles, "/usr/bin/ls", "second").unwrap().0,
            "second"
        );
        assert_eq!(
            choose_role(&roles, "/usr/bin/ls", "first").unwrap().0,
            "first"
        );
        // a role that the user does not hold, or that does not exist
        for role in ["other", "nope"] {
            assert!(matches!(
                choose_role(&roles, "/usr/bin/ls", role),
                Err(SrError::PermissionDenied)
            ));
        }
    }

    #[cfg(feature = "ssd")]
    #[test]
    fn test_role_filter_does_not_lift_the_separation_of_duties() {
        let none = serde_json::json!({});
        let roles = serde_json::json!([
            role_json(
                "dev",
                true,
                Some("/usr/bin/ls"),
                &serde_json::json!({"ssd": ["auditor"]})
            ),
            role_json("auditor", true, None, &none),
        ]);
        // dosr -r dev read only the role dev: auditor, which the user holds, was not seen
        assert!(matches!(
            choose_role(&roles, "/usr/bin/ls", "dev"),
            Err(SrError::PermissionDenied)
        ));
    }

    #[cfg(feature = "hierarchy")]
    #[test]
    fn test_role_filter_keeps_the_tasks_of_the_parents() {
        let none = serde_json::json!({});
        let roles = serde_json::json!([
            role_json(
                "senior",
                true,
                None,
                &serde_json::json!({"parents": ["junior"]})
            ),
            role_json("junior", false, Some("/usr/bin/ls"), &none),
        ]);
        let (role, task) = choose_role(&roles, "/usr/bin/ls", "senior").unwrap();
        assert_eq!(task.as_deref(), Some("junior_task"), "{role}");
    }

    #[test]
    fn test_default_policy_runs_as_the_requested_user() {
        api::register_plugins();
        let policy = include_str!("../../../resources/rootasrole.json");
        let root = Cred {
            user: nix::unistd::User::from_uid(0.into()).unwrap().unwrap(),
            groups: Vec::new(),
            tty: None,
            ppid: nix::unistd::Pid::from_raw(1),
            curdir: PathBuf::from("/"),
        };
        let nobody = nix::unistd::User::from_name("nobody").unwrap().unwrap();
        let group = nix::unistd::Group::from_gid(nix::unistd::getgid())
            .unwrap()
            .unwrap();
        // an administrator drops its privileges with -u and -g: the command runs as asked, the
        // policy allows every user and group (`"default": "all"`)
        let cli = crate::getopt([
            "dosr",
            "-u",
            "nobody",
            "-g",
            group.name.as_str(),
            "/usr/bin/id",
        ])
        .unwrap();
        let data = de::ConfigFinderDeserializer {
            cli: &cli,
            cred: &root,
        }
        .deserialize(&mut serde_json::Deserializer::from_str(policy))
        .unwrap();
        let settings = BestExecSettings::retrieve_settings(
            &cli,
            &root,
            &data,
            Vec::<(String, String)>::new(),
            &["/usr/bin"],
        )
        .unwrap();
        assert_eq!(settings.task.as_deref(), Some("t_root"));
        assert_eq!(settings.cred.setuid.map(|user| user.uid), Some(nobody.uid));
        assert_eq!(
            settings
                .cred
                .setgroups
                .map(|groups| groups.iter().map(|g| g.gid).collect::<Vec<_>>()),
            Some(vec![group.gid])
        );
    }

    #[cfg(feature = "hierarchy")]
    #[test]
    fn test_hierarchy_plugin() {
        let parents = |value: Value| serde_json::json!({ "parents": value });
        let none = serde_json::json!({});
        // a member of the senior role gets the tasks of its parents
        for value in [serde_json::json!(["junior"]), serde_json::json!("junior")] {
            let roles = serde_json::json!([
                role_json("senior", true, None, &parents(value)),
                role_json("junior", false, Some("/usr/bin/ls"), &none),
            ]);
            let (_, task, final_path) = choose(&roles, "/usr/bin/ls").unwrap();
            assert_eq!(task.as_deref(), Some("junior_task"));
            assert_eq!(final_path, PathBuf::from("/usr/bin/ls"));
        }
        // the task of a parent that the user also holds directly is the same task, not a tie
        let roles = serde_json::json!([
            role_json(
                "senior",
                true,
                None,
                &parents(serde_json::json!(["junior"]))
            ),
            role_json("other", true, None, &parents(serde_json::json!(["junior"]))),
            role_json("junior", true, Some("/usr/bin/ls"), &none),
        ]);
        let (_, task, _) = choose(&roles, "/usr/bin/ls").unwrap();
        assert_eq!(task.as_deref(), Some("junior_task"));
        // a user that is a member of no role gets nothing, hierarchy or not
        let roles = serde_json::json!([
            role_json(
                "senior",
                false,
                None,
                &parents(serde_json::json!(["junior"]))
            ),
            role_json("junior", false, Some("/usr/bin/ls"), &none),
        ]);
        assert!(matches!(
            choose(&roles, "/usr/bin/ls"),
            Err(SrError::PermissionDenied)
        ));
        // an invalid value is a configuration error
        let roles = serde_json::json!([role_json(
            "senior",
            true,
            None,
            &parents(serde_json::json!(3))
        )]);
        assert!(matches!(
            choose(&roles, "/usr/bin/ls"),
            Err(SrError::ConfigurationError)
        ));
    }

    #[cfg(all(feature = "hierarchy", feature = "ssd"))]
    #[test]
    fn test_role_excluded_by_ssd_gives_no_task_of_its_parents() {
        let none = serde_json::json!({});
        let roles = serde_json::json!([
            role_json(
                "senior",
                true,
                None,
                &serde_json::json!({"parents": ["junior"], "ssd": ["auditor"]})
            ),
            role_json("junior", false, Some("/usr/bin/ls"), &none),
            role_json("auditor", true, None, &none),
        ]);
        assert!(matches!(
            choose(&roles, "/usr/bin/ls"),
            Err(SrError::PermissionDenied)
        ));
    }

    #[cfg(all(feature = "hierarchy", feature = "ssd"))]
    #[test]
    fn test_ssd_counts_the_roles_held_through_parents() {
        let none = serde_json::json!({});
        let roles = serde_json::json!([
            role_json(
                "senior",
                true,
                None,
                &serde_json::json!({"parents": ["junior"]})
            ),
            role_json("junior", false, Some("/usr/bin/ls"), &none),
            // the user holds junior through senior: auditor is excluded
            role_json(
                "auditor",
                true,
                Some("/usr/bin/cat"),
                &serde_json::json!({"ssd": ["junior"]})
            ),
        ]);
        assert!(matches!(
            choose(&roles, "/usr/bin/cat"),
            Err(SrError::PermissionDenied)
        ));
        assert!(choose(&roles, "/usr/bin/ls").is_ok());
    }

    #[cfg(all(feature = "hierarchy", feature = "ssd"))]
    #[test]
    fn test_conflicting_parents_give_no_conflicting_task() {
        let none = serde_json::json!({});
        let ssd = |other: &str| serde_json::json!({ "ssd": [other] });
        let senior = role_json(
            "senior",
            true,
            None,
            &serde_json::json!({"parents": ["a", "b"]}),
        );
        // a declares the conflict: its tasks are not inherited, those of b are
        let roles = serde_json::json!([
            senior,
            role_json("a", false, Some("/usr/bin/ls"), &ssd("b")),
            role_json("b", false, Some("/usr/bin/cat"), &none),
        ]);
        assert!(matches!(
            choose(&roles, "/usr/bin/ls"),
            Err(SrError::PermissionDenied)
        ));
        assert!(choose(&roles, "/usr/bin/cat").is_ok());
        // declared on both sides: no task of either
        let roles = serde_json::json!([
            senior,
            role_json("a", false, Some("/usr/bin/ls"), &ssd("b")),
            role_json("b", false, Some("/usr/bin/cat"), &ssd("a")),
        ]);
        for cmd in ["/usr/bin/ls", "/usr/bin/cat"] {
            assert!(
                matches!(choose(&roles, cmd), Err(SrError::PermissionDenied)),
                "{cmd}"
            );
        }
    }

    #[test]
    fn test_role_settings_calls_actors_and_tasks() {
        let mut best = BestExecSettings::default();
        let cli = dummy_cli();
        let cred = dummy_cred();
        let binding = dummy_dconfigfinder();
        let data = binding.roles().next().unwrap();
        let mut opt_stack = BorrowedOptStack::new(None);
        let env_path = &["/bin"];
        let result = best.role_settings(&cli, &cred, &data, &mut opt_stack, env_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_actors_settings_returns_bool() {
        let mut best = BestExecSettings::default();
        let binding = dummy_dconfigfinder();
        let data = binding.roles().next().unwrap();
        let result = best.actors_settings(&data);
        assert!(result.is_ok());
        assert!(result.is_ok());
    }

    #[test]
    fn test_task_settings_sets_fields_on_found() {
        let mut best = BestExecSettings::default();
        let cli = dummy_cli();
        let cred = dummy_cred();
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().next().unwrap();
        let data = binding.tasks().next().unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.as_ref());
        let env_path = &["/bin"];
        let result = best.task_settings(&cli, &cred, &data, &mut opt_stack, env_path);
        assert!(result.is_ok_and(|r| r));
        assert!(*best.final_path == *"/usr/bin/ls");
        assert!(best.role == "test");
        assert!(best.task == Some("0".to_string()));
        assert!(best.cred.caps.is_some());
        assert!(best.score.cmd_min == CmdMin::MATCH);
    }

    #[cfg(feature = "regex")]
    #[test]
    fn test_command_settings_simple_and_complex() {
        let cli = dummy_cli();
        let env_path = &["/usr/bin"];
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().next().unwrap();
        let binding = binding.tasks().nth(1).unwrap();
        let binding = binding.commands().unwrap();
        let data = binding.add().next().unwrap();
        let result = BestExecSettings::match_command(env_path, &cli, &data);
        assert!(result.as_ref().is_ok_and(|m| {
            m.as_ref()
                .is_some_and(|(_, path)| path == Path::new("/usr/bin/ls"))
        }));
        let data = binding.add().nth(1).unwrap();
        let result = BestExecSettings::match_command(env_path, &cli, &data);
        assert!(
            result.as_ref().is_ok_and(Option::is_none),
            "Failed to process complex command : {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_info_denied_due_to_inherited_hide_one() {
        let mut best = BestExecSettings::default();
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .info()
            .build();
        let cred = dummy_cred();
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().next().unwrap();
        let binding = binding.tasks().next().unwrap();
        // This task has info hide set in options, it should be denied
        let data = binding;
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.as_ref());
        let env_path = &["/usr/bin"];
        let result = best.task_settings(&cli, &cred, &data, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
    #[test]
    fn test_info_denied_due_to_inherited_hide_two() {
        let mut best = BestExecSettings::default();
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .info()
            .build();
        let cred = dummy_cred();
        // Now test with the second task which does not have info hide
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().next().unwrap();
        let binding = binding.tasks().nth(1).unwrap();
        // This task has info hide set in options, it should be denied
        let data = binding;
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.as_ref());
        let env_path = &["/usr/bin"];
        let result = best.task_settings(&cli, &cred, &data, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    #[test]
    fn test_info_denied_due_to_inherited_hide_three() {
        let mut best = BestExecSettings::default();
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .info()
            .build();
        let cred = dummy_cred();
        // Now try best.role_settings to ensure full flow works
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().next().unwrap();
        let data = binding.tasks().nth(1).unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.as_ref());
        let env_path = &["/usr/bin"];
        let result = best.role_settings(&cli, &cred, &binding, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(*best.final_path == *"/usr/bin/ls");
        assert!(best.role == "test", "role was {}", best.role);
        assert!(best.task == Some("1".to_string()));
    }
    #[test]
    fn test_info_denied_due_to_inherited_hide_four() {
        let mut best = BestExecSettings::default();
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .info()
            .build();
        let cred = dummy_cred();
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(1).unwrap();
        let data = binding.tasks().next().unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.as_ref());
        let env_path = &["/usr/bin"];
        let result = best.role_settings(&cli, &cred, &binding, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(*best.final_path == *"/usr/bin/ls");
        assert!(best.role == "test2", "role was {}", best.role);
        assert!(best.task == Some("0".to_string()));
    }

    #[test]
    fn test_info_denied_due_to_inherited_env_override_one() {
        let mut best = BestExecSettings::default();
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .opt_filter(
                FilterMatcher::builder()
                    .env_behavior(EnvBehavior::Keep)
                    .build(),
            )
            .build();
        let cred = dummy_cred();
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().next().unwrap();
        let binding = binding.tasks().next().unwrap();
        // This task has info hide set in options, it should be denied
        let data = binding;
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.as_ref());
        let env_path = &["/usr/bin"];
        let result = best.task_settings(&cli, &cred, &data, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
    #[test]
    fn test_info_denied_due_to_inherited_env_override_two() {
        let mut best = BestExecSettings::default();
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .opt_filter(
                FilterMatcher::builder()
                    .env_behavior(EnvBehavior::Keep)
                    .build(),
            )
            .build();
        let cred = dummy_cred();
        // Now test with the second task which does not have info hide
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().next().unwrap();
        let binding = binding.tasks().nth(1).unwrap();
        // This task has info hide set in options, it should be denied
        let data = binding;
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.as_ref());
        let env_path = &["/usr/bin"];
        let result = best.task_settings(&cli, &cred, &data, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
    #[test]
    fn test_info_denied_due_to_inherited_env_override_three() {
        let mut best = BestExecSettings::default();
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .opt_filter(
                FilterMatcher::builder()
                    .env_behavior(EnvBehavior::Keep)
                    .build(),
            )
            .build();
        let cred = dummy_cred();
        // Now try best.role_settings to ensure full flow works
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().next().unwrap();
        let data = binding.tasks().nth(1).unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.as_ref());
        let env_path = &["/usr/bin"];
        let result = best.role_settings(&cli, &cred, &binding, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(*best.final_path == *"/usr/bin/ls");
        assert!(best.role == "test", "role was {}", best.role);
        assert!(best.task == Some("1".to_string()));
    }
    #[test]
    fn test_info_denied_due_to_inherited_env_override_four() {
        let mut best = BestExecSettings::default();
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .opt_filter(
                FilterMatcher::builder()
                    .env_behavior(EnvBehavior::Keep)
                    .build(),
            )
            .build();
        let cred = dummy_cred();
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(1).unwrap();
        let data = binding.tasks().next().unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.as_ref());
        let env_path = &["/usr/bin"];
        let result = best.role_settings(&cli, &cred, &binding, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(*best.final_path == *"/usr/bin/ls");
        assert!(best.role == "test2", "role was {}", best.role);
        assert!(best.task == Some("0".to_string()));
    }

    #[test]
    fn test_resolve_any_command_ignores_current_directory() {
        // the tests run in the crate directory, which contains Cargo.toml
        assert!(Path::new("Cargo.toml").is_file());
        assert_eq!(resolve_any_command(Path::new("Cargo.toml"), &[]), None);
        assert_eq!(
            resolve_any_command(Path::new("Cargo.toml"), &[".", ""]),
            None
        );
        let dir = std::env::current_dir().unwrap();
        let dir = dir.to_str().unwrap();
        assert_eq!(
            resolve_any_command(Path::new("Cargo.toml"), &["/nonexistent", dir]),
            Some(Path::new(dir).join("Cargo.toml"))
        );
    }

    #[test]
    fn test_resolve_any_command_keeps_the_given_name() {
        let dir =
            std::env::temp_dir().join(format!("rar_resolve_any_command_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("pkill");
        std::os::unix::fs::symlink("/usr/bin/pgrep", &link).unwrap();
        // an explicit path is used as given, the symbolic link is not resolved
        assert_eq!(resolve_any_command(&link, &[]), Some(link.clone()));
        assert_eq!(
            resolve_any_command(Path::new("./Cargo.toml"), &[]),
            Some(std::env::current_dir().unwrap().join("./Cargo.toml"))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The environment that dosr decides for `cli`, completed with variables set by PAM.
    fn env_with_pam_vars(cli: &Cli, pam_vars: &[(&str, &str)]) -> HashMap<String, String> {
        use serde::de::DeserializeSeed;
        let policy = format!(
            r#"{{"roles":[{{"name":"r","actors":[{{"type":"user","id":{}}}],"tasks":[{{"name":"t","commands":["/usr/bin/true"],"options":{{"env":{{"default":"delete","override_behavior":true,"keep":["PAM_*"],"check":["CHECKED"],"delete":["LD_*"],"set":{{"SET":"policy"}}}}}}}}]}}]}}"#,
            nix::unistd::getuid()
        );
        let cred = dummy_cred();
        let data = super::de::ConfigFinderDeserializer { cli, cred: &cred }
            .deserialize(&mut serde_json::Deserializer::from_str(&policy))
            .expect("valid policy");
        let mut settings = BestExecSettings::retrieve_settings(
            cli,
            &cred,
            &data,
            [("PAM_USER_VAR", "user")],
            &["/usr/bin"],
        )
        .unwrap();
        settings.env_filter.add_vars(
            &mut settings.env,
            pam_vars
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string())),
        );
        settings.env
    }

    #[test]
    fn test_a_task_without_any_directory_gives_no_path() {
        // an empty PATH would be the working directory for a shell, which the user chooses
        let policy = format!(
            r#"{{"roles":[{{"name":"r","actors":[{{"type":"user","id":{}}}],"tasks":[{{"name":"t","commands":["/usr/bin/true"],"options":{{"path":{{"default":"delete","add":[".",""]}},"env":{{"default":"delete","keep":["PATH"]}}}}}}]}}]}}"#,
            nix::unistd::getuid()
        );
        let cli = Cli::builder().cmd_path("/usr/bin/true".to_string()).build();
        let cred = dummy_cred();
        let data = super::de::ConfigFinderDeserializer {
            cli: &cli,
            cred: &cred,
        }
        .deserialize(&mut serde_json::Deserializer::from_str(&policy))
        .expect("valid policy");
        let settings = BestExecSettings::retrieve_settings(
            &cli,
            &cred,
            &data,
            [("PATH", ".:/tmp")],
            &[".", "/usr/bin"],
        )
        .unwrap();
        assert!(!settings.env.contains_key("PATH"), "{:?}", settings.env);
        assert!(settings.env_path.is_empty(), "{:?}", settings.env_path);
    }

    #[test]
    fn test_pam_vars_go_through_the_env_filter_of_the_task() {
        let pam_vars = [
            ("PAM_NEW", "pam"),
            ("PAM_USER_VAR", "pam"),
            ("SET", "pam"),
            ("PATH", "/tmp/evil"),
            ("CHECKED", "/unsafe"),
            ("OTHER", "pam"),
            ("LD_PRELOAD", "/tmp/evil.so"),
        ];
        let cli = Cli::builder().cmd_path("/usr/bin/true".to_string()).build();
        let env = env_with_pam_vars(&cli, &pam_vars);
        assert_eq!(env.get("PAM_NEW").unwrap(), "pam");
        assert_eq!(env.get("PAM_USER_VAR").unwrap(), "user");
        assert_eq!(env.get("SET").unwrap(), "policy");
        assert!(!env.get("PATH").unwrap().contains("/tmp/evil"));
        assert!(!env.contains_key("CHECKED"));
        assert!(!env.contains_key("OTHER"));
        assert!(!env.contains_key("LD_PRELOAD"));
        // dosr -E, which this task allows: the PAM variables are kept but for the delete list
        let cli = Cli::builder()
            .cmd_path("/usr/bin/true".to_string())
            .opt_filter(
                FilterMatcher::builder()
                    .env_behavior(EnvBehavior::Keep)
                    .build(),
            )
            .build();
        let env = env_with_pam_vars(&cli, &pam_vars);
        assert_eq!(env.get("OTHER").unwrap(), "pam");
        assert!(!env.contains_key("CHECKED"));
        assert!(!env.contains_key("LD_PRELOAD"));
    }
}
