/// This file implements a finder algorithm within deserialization of the settings
/// It is much more efficient to do it this way, way less memory allocation and manipulation
/// Only the settings that are needed are kept in memory
use std::{
    collections::HashMap,
    fs,
    io::BufReader,
    path::{Path, PathBuf},
};

use api::{Api, ApiEvent};
use bon::Builder;
use de::{ConfigFinderDeserializer, DConfigFinder, DLinkedCommand, DLinkedRole, DLinkedTask};
use log::{debug, error};
use options::BorrowedOptStack;
use rootasrole_core::{
    Cred,
    database::{
        actor::{DGroupType, DGroups},
        options::{SAuthentication, SBounding, SPrivileged, STimeout, SUMask},
        score::{CmdMin, CmdOrder, HardenedBool, Score, hardened_bool_from_bool},
        workdir::ResolvedWorkdir,
    },
    util::{StorageMethod, check_others_permissions, read_with_privileges},
};
use serde::de::DeserializeSeed;

use crate::{
    Cli,
    error::{SrError, SrResult},
    finder::de::{cred::CredOwnedData, settings::read_storage},
};

pub mod api;
mod cmd;
use cmd::resolve_any_command;
pub mod de;
mod options;

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
    /// Is root id has it's privileges or not? If not, root is going to be a simple user
    pub root: SPrivileged,
    #[builder(default)]
    /// Setting umask
    pub umask: SUMask,
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
    let file_path = settings_file
        .data
        .data
        .settings
        .unwrap_or_default()
        .path
        .unwrap_or_else(|| rar_cfg_data_path.as_ref().to_path_buf());
    let parse_file = |file_path: &Path| -> SrResult<BestExecSettings> {
        let config_finder_deserializer = ConfigFinderDeserializer { cli, cred };
        let file = read_with_privileges(file_path)?;
        check_others_permissions(file_path, &file)?;
        let reader = BufReader::new(file);
        match settings_file.data.data.method {
            StorageMethod::CBOR => {
                let mut io_reader = cbor4ii::core::utils::IoReader::new(reader);
                Ok(BestExecSettings::retrieve_settings(
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
                Ok(BestExecSettings::retrieve_settings(
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
                    if best.as_ref().is_none_or(|best_settings| {
                        settings.score.better_fully(&best_settings.score)
                    }) {
                        best = Some(settings);
                    }
                }
                Err(SrError::PermissionDenied) => {
                    parsed_any = true;
                }
                Err(err) => {
                    debug!("Skipping policy file {}: {err}", entry.display());
                }
            }
        }

        return best.ok_or({
            if parsed_any {
                SrError::PermissionDenied
            } else {
                SrError::ConfigurationError
            }
        });
    }

    parse_file(&file_path)
}

impl BestExecSettings {
    fn retrieve_settings<'a>(
        cli: &'a Cli,
        cred: &'a Cred,
        data: &'a DConfigFinder<'a>,
        env_vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
        env_path: &[&str],
    ) -> SrResult<Self> {
        let mut result = Self::default();
        let mut matching = false;
        let mut opt_stack = BorrowedOptStack::new(data.options.as_ref());
        for role in data.roles() {
            matching |= result.role_settings(cli, cred, &role, &mut opt_stack, env_path)?;
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
        result.env = opt_stack
            .calc_temp_env(opt_stack.calc_override_behavior(), cli.opt_filter.as_ref())
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
        result.root = opt_stack.calc_privileged();
        result.umask = opt_stack.calc_umask();
        result.workdir = opt_stack.calc_workdir();
        Ok(result)
    }

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

    #[allow(clippy::too_many_lines)]
    pub fn task_settings<'t, 'c, 'a>(
        &mut self,
        cli: &'t Cli,
        cred: &'t Cred,
        data: &DLinkedTask<'t, 'c, 'a>,
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
                task_cmd_min = CmdMin::builder()
                    .matching()
                    .order(CmdOrder::FullWildcardPath | CmdOrder::RegexArgs)
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
        Api::notify(ApiEvent::BestTaskSettingsFound(
            cli, data, opt_stack, self, &mut score,
        ))?;
        if found
            && let Some(final_path) = task_final_path
            && score.better_fully(&self.score)
        {
            debug!("found better task settings");
            self.final_path = final_path;
            self.role = data.role().role().role.to_string();
            self.task = Some(data.id.to_string());
            self.env_path = task_env_path.unwrap_or_else(|| temp_opt_stack.calc_path(env_path));
            self.score = score;
            self.cred.setuid = data.cred.setuid.clone().and_then(|u| u.fetch_user());
            self.cred.setgroups = data.cred.setgroups.clone().map(|g| match g {
                DGroups::Single(g) => vec![g.fetch_group()].into_iter().flatten().collect(),
                DGroups::Multiple(g) => g.iter().filter_map(DGroupType::fetch_group).collect(),
            });
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
        let cli = Cli::builder().cmd_path(cmd.to_string()).build();
        let cred = dummy_cred();
        let env_path = ["/usr/bin"];
        let data = super::de::ConfigFinderDeserializer {
            cli: &cli,
            cred: &cred,
        }
        .deserialize(&mut serde_json::Deserializer::from_str(&policy))
        .expect("valid policy");
        let user_env = vec![("A_VAR", "a"), ("B_VAR", "b"), ("C_VAR", "c")];
        let settings =
            BestExecSettings::retrieve_settings(&cli, &cred, &data, user_env, &env_path)?;
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
        let a = task_json("a", &[], r#"["/usr/bin/ls"]"#, "A_VAR", "/usr/bin");
        let b = task_json(
            "b",
            &["CAP_NET_RAW"],
            r#"{"default":"all"}"#,
            "B_VAR",
            "/usr/bin",
        );
        // a regex on the arguments is a worse match than a exact command
        let c = task_json("c", &[], r#"["/usr/bin/ls ^.*$"]"#, "C_VAR", "/usr/bin");
        for tasks in orders(&[&a, &b, &c]) {
            let (task, _, _, kept) = best_task(&tasks, "ls").unwrap();
            assert_eq!(task, "a", "{tasks:?}");
            assert_eq!(kept, ["A_VAR"], "{tasks:?}");
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
}
