/// This file implements a finder algorithm within deserialization of the settings
/// It is much more efficient to do it this way, way less memory allocation and manipulation
/// Only the settings that are needed are kept in memory
use std::{
    collections::HashMap,
    io::BufReader,
    path::{Path, PathBuf},
};

use api::{register_plugins, Api, ApiEvent};
use capctl::CapSet;
use de::{ConfigFinderDeserializer, DConfigFinder, DLinkedCommand, DLinkedRole, DLinkedTask};
use log::debug;
use nix::unistd::User;
use options::BorrowedOptStack;
use rar_common::{
    database::{
        actor::DGroups,
        options::{SAuthentication, SBounding, SPrivileged, STimeout},
        score::{CmdMin, CmdOrder, Score},
    },
    util::{all_paths_from_env, read_with_privileges},
    Cred, StorageMethod,
};
use serde::de::DeserializeSeed;

use crate::{
    error::{SrError, SrResult},
    Cli,
};

mod api;
mod cmd;
mod de;
mod options;

#[derive(Debug, Default, Clone)]
pub struct BestExecSettings {
    pub score: Score,
    pub final_path: PathBuf,
    pub setuid: Option<u32>,
    pub setgroups: Option<Vec<u32>>,
    pub caps: Option<CapSet>,
    pub task: Option<String>,
    pub role: String,
    pub env: HashMap<String, String>,
    pub env_path: Vec<String>,
    pub bounding: SBounding,
    pub timeout: STimeout,
    pub auth: SAuthentication,
    pub root: SPrivileged,
}

pub fn find_best_exec_settings<'de: 'a, 'a, P>(
    cli: &'a Cli,
    cred: &'a Cred,
    path: &'a P,
    env_vars: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    env_path: &[&str],
) -> SrResult<BestExecSettings>
where
    P: AsRef<Path>,
{
    register_plugins();
    let settings_file = rar_common::get_settings(path).map_err(|e| {
        debug!("Policy unreachable: {}", e);
        SrError::ConfigurationError
    })?;
    let config_finder_deserializer = ConfigFinderDeserializer {
        cli,
        cred,
        env_path,
    };
    match settings_file.storage.method {
        StorageMethod::CBOR => {
            let file_path = settings_file
                .storage
                .settings
                .unwrap_or_default()
                .path
                .ok_or(SrError::ConfigurationError)?;
            let file = read_with_privileges(&file_path)?;
            let reader = BufReader::new(file); // Use BufReader for efficient streaming
            let mut io_reader = cbor4ii::core::utils::IoReader::new(reader); // Use IoReader for streaming
            Ok(BestExecSettings::retrieve_settings(
                cli,
                cred,
                &config_finder_deserializer
                    .deserialize(&mut cbor4ii::serde::Deserializer::new(&mut io_reader))
                    .map_err(|e| {
                        debug!("Error deserializing CBOR: {}", e);
                        SrError::ConfigurationError
                    })?,
                env_vars,
                &env_path,
            )?)
        }
        StorageMethod::JSON => {
            let file_path = settings_file
                .storage
                .settings
                .unwrap_or_default()
                .path
                .ok_or(SrError::ConfigurationError)?;
            let file = read_with_privileges(&file_path)?;
            let reader = BufReader::new(file);
            let io_reader = serde_json::de::IoRead::new(reader);
            Ok(BestExecSettings::retrieve_settings(
                cli,
                cred,
                &config_finder_deserializer
                    .deserialize(&mut serde_json::Deserializer::new(io_reader))
                    .map_err(|e| {
                        debug!("Error deserializing JSON: {}", e);
                        SrError::ConfigurationError
                    })?,
                env_vars,
                &env_path,
            )?)
        }
    }
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
        let mut opt_stack = BorrowedOptStack::new(data.options.clone());
        for role in data.roles() {
            matching |= result.role_settings(cli, &role, &mut opt_stack, env_path)?;
        }
        if !matching {
            return Err(SrError::PermissionDenied);
        }
        result.env = opt_stack
            .calc_temp_env(opt_stack.calc_override_behavior(), &cli.opt_filter)
            .calc_final_env(
                env_vars,
                opt_stack.calc_path(env_path),
                cred,
                result
                    .setuid
                    .and_then(|x| User::from_uid(x.into()).expect("Target user do not exist")),
                format!(
                    "{}{}",
                    cli.cmd_path.display(),
                    if cli.cmd_args.is_empty() {
                        "".into()
                    } else {
                        format!(" {}", cli.cmd_args.join(" "))
                    }
                ),
            )?;
        result.auth = opt_stack.calc_authentication();
        result.bounding = opt_stack.calc_bounding();
        result.timeout = opt_stack.calc_timeout();
        result.root = opt_stack.calc_privileged();
        Ok(result)
    }

    pub fn role_settings<'c, 'a>(
        &mut self,
        cli: &'c Cli,
        data: &DLinkedRole<'c, 'a>,
        opt_stack: &mut BorrowedOptStack<'a>,
        env_path: &[&str],
    ) -> SrResult<bool> {
        debug!("role_settings: {:?}", data.role().role);
        if !self.actors_settings(data)? {
            return Ok(false);
        }
        let mut res = false;
        for task in data.tasks() {
            res |= self.task_settings(cli, &task, opt_stack, env_path)?;
        }
        Ok(res)
    }

    pub fn actors_settings<'c, 'a>(&mut self, data: &DLinkedRole<'c, 'a>) -> SrResult<bool> {
        let mut res = !data.role().user_min.is_no_match();
        Api::notify(ApiEvent::ActorMatching(data, self, &mut res))?;
        Ok(res)
    }

    pub fn task_settings<'t, 'c, 'a>(
        &mut self,
        cli: &'t Cli,
        data: &DLinkedTask<'t, 'c, 'a>,
        opt_stack: &mut BorrowedOptStack<'a>,
        env_path: &[&str],
    ) -> SrResult<bool> {
        debug!("task_settings: {:?}", data.id);
        let temp_opt_stack = BorrowedOptStack::from_task(data);
        let mut found = false;
        let mut f_env_path = None;
        // We must do this check for each task as long they could have different options
        // These checks are a small optimization to avoid useless command checks
        if cli
            .opt_filter
            .as_ref()
            .is_some_and(|f| f.env_behavior.is_some() && !temp_opt_stack.calc_override_behavior())
        {
            debug!("task_settings: deny task due to inherited from role or config env_override requirement");
            return Ok(false);
        }
        if cli.info && temp_opt_stack.calc_info().is_hide() {
            debug!("task_settings: deny task due to inherited from role or config info hide");
            return Ok(false);
        }
        if let Some(commands) = data.commands() {
            let t_env_path = opt_stack.calc_path(env_path);
            for command in commands.del() {
                if self.command_settings(
                    &t_env_path.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                    cli,
                    &command,
                )? {
                    return Ok(false);
                }
            }
            if commands.default_behavior.is_some_and(|b| b.is_all()) {
                debug!("default behavior is all");
                let t_env_path = opt_stack.calc_path(env_path);
                found = true;
                debug!("{:?}", &cli.cmd_path);
                if let Ok(path) = cli.cmd_path.canonicalize() {
                    self.final_path = path;
                } else {
                    self.final_path = all_paths_from_env(
                        &t_env_path.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                        &cli.cmd_path,
                    )
                    .first()
                    .ok_or(SrError::ExecutionFailed)?
                    .to_path_buf();
                }
                self.score.cmd_min = CmdMin::builder()
                    .matching()
                    .order(CmdOrder::FullWildcardPath | CmdOrder::RegexArgs)
                    .build();
            } else {
                for command in commands.add() {
                    if self.command_settings(
                        &t_env_path.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                        cli,
                        &command,
                    )? {
                        found = true;
                        break;
                    }
                }
            }
            f_env_path = Some(t_env_path);
        } else if let Some(final_path) = &data.final_path {
            debug!("final_path already found: {:?}", final_path);
            found = self.update_command_score(final_path.to_path_buf(), data.score.cmd_min);
        }
        let mut score = data.score(self.score.cmd_min, temp_opt_stack.calc_security_min());
        Api::notify(ApiEvent::BestTaskSettingsFound(
            &cli, &data, opt_stack, self, &mut score,
        ))?;
        if found && score.better_fully(&self.score) {
            debug!("found better task settings");
            self.role = data.role().role().role.to_string();
            self.task = Some(data.id.to_string());
            self.env_path = f_env_path
                .unwrap_or(opt_stack.calc_path(env_path))
                .iter()
                .map(|s| s.to_string())
                .collect();
            self.score = score;
            self.setuid = data.setuid.clone().map(|u| u.fetch_id()).flatten();
            self.setgroups = data.setgroups.clone().and_then(|g| match g {
                DGroups::Single(g) => Some(vec![g.fetch_id()].into_iter().flatten().collect()),
                DGroups::Multiple(g) => Some(g.iter().filter_map(|g| g.fetch_id()).collect()),
            });
            self.caps = data.caps.clone();
            opt_stack.set_role(data);
            opt_stack.set_task(data);
            debug!("resulting settings: {:?}", self);
        }

        Ok(found)
    }

    pub fn command_settings<'d, 'l, 't, 'c, 'a>(
        &mut self,
        env_path: &[&str],
        cli: &'d Cli,
        data: &DLinkedCommand<'d, 'l, 't, 'c, 'a>,
    ) -> SrResult<bool> {
        debug!("env_path: {:?}", env_path);
        Ok(match &**data {
            de::DCommand::Simple(role_cmd) => {
                let mut final_path = None;
                let cmd_min = cmd::evaluate_command_match(
                    env_path,
                    &cli.cmd_path,
                    &cli.cmd_args,
                    role_cmd,
                    &self.score.cmd_min,
                    &mut final_path,
                );
                if let Some(final_path) = final_path {
                    self.update_command_score(final_path, cmd_min)
                } else {
                    false
                }
            }
            de::DCommand::Complex(value) => {
                let mut cmd_min = CmdMin::empty();
                let mut final_path = None;
                Api::notify(ApiEvent::ProcessComplexCommand(
                    value,
                    env_path,
                    &cli.cmd_path,
                    &cli.cmd_args,
                    &mut cmd_min,
                    &mut final_path,
                ))?;
                if let Some(final_path) = final_path {
                    self.update_command_score(final_path, cmd_min)
                } else {
                    false
                }
            }
        })
    }

    fn update_command_score(&mut self, final_path: PathBuf, res: CmdMin) -> bool {
        debug!(
            "update_command_score: current score {:?}, new score {:?}",
            self.score.cmd_min, res
        );
        if res.better(&self.score.cmd_min) {
            debug!("better");
            self.score.cmd_min = res;
            self.final_path = final_path;
            true
        } else {
            debug!("not better");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::de::{DCommand, DCommandList, DRoleFinder, DTaskFinder, IdTask};
    use super::*;
    use rar_common::database::options::{EnvBehavior, Level, SInfo};
    use rar_common::database::score::{ActorMatchMin, CmdMin, Score};
    use rar_common::database::structs::SetBehavior;
    use rar_common::database::FilterMatcher;
    use serde_json::Value;
    use std::path::PathBuf;

    use crate::finder::options::{DEnvOptions, Opt};
    use crate::Cli;
    use rar_common::Cred;

    // Helper: Dummy implementations for required traits/structs
    fn dummy_cli() -> Cli {
        Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .build()
    }

    fn dummy_cred() -> Cred {
        Cred::builder().build()
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
                            .caps(!CapSet::empty())
                            .commands(
                                DCommandList::builder(SetBehavior::None)
                                    .add(vec![DCommand::simple("/usr/bin/ls -l")])
                                    .build(),
                            )
                            .options(Opt::builder(Level::Task).execinfo(SInfo::Hide).build())
                            .build(),
                        DTaskFinder::builder()
                            .id(IdTask::Number(1))
                            .caps(CapSet::empty())
                            .commands(
                                DCommandList::builder(SetBehavior::None)
                                    .add(vec![
                                        DCommand::simple("/usr/bin/ls ^.*$"),
                                        DCommand::complex(Value::Object(
                                            [("key".to_string(), Value::String("value".into()))]
                                                .into_iter()
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
                            .caps(!CapSet::empty())
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
                            .caps(CapSet::empty())
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
        assert!(!result.is_ok());
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
        assert!(!settings.setuid.is_some());
        assert!(!settings.setgroups.is_some());
        assert!(settings.caps.is_some());
        assert!(!settings.env.is_empty());
        assert!(!settings.env_path.is_empty());
        assert!(settings.env_path.iter().all(|p| p != "/UNWANTED"));
    }

    #[test]
    fn test_role_settings_calls_actors_and_tasks() {
        let mut best = BestExecSettings::default();
        let cli = dummy_cli();
        let binding = dummy_dconfigfinder();
        let data = binding.roles().nth(0).unwrap();
        let mut opt_stack = BorrowedOptStack::new(None);
        let env_path = &["/bin"];
        let result = best.role_settings(&cli, &data, &mut opt_stack, env_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_actors_settings_returns_bool() {
        let mut best = BestExecSettings::default();
        let binding = dummy_dconfigfinder();
        let data = binding.roles().nth(0).unwrap();
        let result = best.actors_settings(&data);
        assert!(result.is_ok());
        assert!(matches!(result, Ok(_)));
    }

    #[test]
    fn test_task_settings_sets_fields_on_found() {
        let mut best = BestExecSettings::default();
        let cli = dummy_cli();
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(0).unwrap();
        let data = binding.tasks().nth(0).unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.clone());
        let env_path = &["/bin"];
        let result = best.task_settings(&cli, &data, &mut opt_stack, env_path);
        assert!(result.is_ok_and(|r| r));
        assert!(best.final_path == PathBuf::from("/usr/bin/ls"));
        assert!(best.role == "test");
        assert!(best.task == Some("0".to_string()));
        assert!(best.caps.is_some());
        assert!(best.score.cmd_min == CmdMin::MATCH);
    }

    #[cfg(feature = "pcre2")]
    #[test]
    fn test_command_settings_simple_and_complex() {
        let mut best = BestExecSettings::default();
        let cli = dummy_cli();
        let env_path = &["/usr/bin"];
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(0).unwrap();
        let binding = binding.tasks().nth(1).unwrap();
        let binding = binding.commands().unwrap();
        let data = binding.add().nth(0).unwrap();
        let result = best.command_settings(env_path, &cli, &data);
        assert!(result.as_ref().is_ok_and(|b| *b));
        let data = binding.add().nth(1).unwrap();
        let result = best.command_settings(env_path, &cli, &data);
        assert!(
            result.as_ref().is_ok_and(|b| !*b),
            "Failed to process complex command : {}",
            result.unwrap_err()
        );
    }

    #[test]
    fn test_update_command_score_better() {
        let mut settings = BestExecSettings {
            score: Score {
                cmd_min: CmdMin::builder()
                    .matching()
                    .order(CmdOrder::RegexArgs)
                    .build(),
                ..Default::default()
            },
            final_path: PathBuf::from("/old/path"),
            ..Default::default()
        };
        let new_cmd_min = CmdMin::MATCH;
        let new_path = PathBuf::from("/new/path");
        let updated = settings.update_command_score(new_path.clone(), new_cmd_min.clone());
        assert!(updated);
        assert_eq!(settings.score.cmd_min, new_cmd_min);
        assert_eq!(settings.final_path, new_path);
    }

    #[test]
    fn test_update_command_score_not_better() {
        let mut settings = BestExecSettings {
            score: Score {
                cmd_min: CmdMin::MATCH,
                ..Default::default()
            },
            final_path: PathBuf::from("/old/path"),
            ..Default::default()
        };
        let worse_cmd_min = CmdMin::builder()
            .matching()
            .order(CmdOrder::RegexArgs)
            .build();
        let new_path = PathBuf::from("/new/path");
        let updated = settings.update_command_score(new_path, worse_cmd_min);
        assert!(!updated);
        assert_eq!(settings.final_path, PathBuf::from("/old/path"));
    }

    #[test]
    fn test_info_denied_due_to_inherited_hide_one() {
        let mut best = BestExecSettings::default();
        let cli = Cli::builder()
            .cmd_path("/usr/bin/ls".to_string())
            .cmd_args(vec!["-l".to_string()])
            .info()
            .build();
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(0).unwrap();
        let binding = binding.tasks().nth(0).unwrap();
        // This task has info hide set in options, it should be denied
        let data = binding;
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.clone());
        let env_path = &["/usr/bin"];
        let result = best.task_settings(&cli, &data, &mut opt_stack, env_path);
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
        // Now test with the second task which does not have info hide
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(0).unwrap();
        let binding = binding.tasks().nth(1).unwrap();
        // This task has info hide set in options, it should be denied
        let data = binding;
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.clone());
        let env_path = &["/usr/bin"];
        let result = best.task_settings(&cli, &data, &mut opt_stack, env_path);
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
        // Now try best.role_settings to ensure full flow works
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(0).unwrap();
        let data = binding.tasks().nth(1).unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.clone());
        let env_path = &["/usr/bin"];
        let result = best.role_settings(&cli, &binding, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(best.final_path == PathBuf::from("/usr/bin/ls"));
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
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(1).unwrap();
        let data = binding.tasks().nth(0).unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.clone());
        let env_path = &["/usr/bin"];
        let result = best.role_settings(&cli, &binding, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(best.final_path == PathBuf::from("/usr/bin/ls"));
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
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(0).unwrap();
        let binding = binding.tasks().nth(0).unwrap();
        // This task has info hide set in options, it should be denied
        let data = binding;
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.clone());
        let env_path = &["/usr/bin"];
        let result = best.task_settings(&cli, &data, &mut opt_stack, env_path);
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
        // Now test with the second task which does not have info hide
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(0).unwrap();
        let binding = binding.tasks().nth(1).unwrap();
        // This task has info hide set in options, it should be denied
        let data = binding;
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.clone());
        let env_path = &["/usr/bin"];
        let result = best.task_settings(&cli, &data, &mut opt_stack, env_path);
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
        // Now try best.role_settings to ensure full flow works
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(0).unwrap();
        let data = binding.tasks().nth(1).unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.clone());
        let env_path = &["/usr/bin"];
        let result = best.role_settings(&cli, &binding, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(best.final_path == PathBuf::from("/usr/bin/ls"));
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
        let binding = dummy_dconfigfinder();
        let binding = binding.roles().nth(1).unwrap();
        let data = binding.tasks().nth(0).unwrap();
        let mut opt_stack = BorrowedOptStack::new(data.role().config().options.clone());
        let env_path = &["/usr/bin"];
        let result = best.role_settings(&cli, &binding, &mut opt_stack, env_path);
        assert!(result.is_ok());
        assert!(result.unwrap());
        assert!(best.final_path == PathBuf::from("/usr/bin/ls"));
        assert!(best.role == "test2", "role was {}", best.role);
        assert!(best.task == Some("0".to_string()));
    }
}
