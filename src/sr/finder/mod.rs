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
use options::BorrowedOptStack;
use rar_common::{
    database::{
        actor::DGroups,
        options::{SAuthentication, SBounding, SPrivileged, STimeout},
        score::{CmdMin, Score},
    },
    util::{all_paths_from_env, open_with_privileges},
    Cred, StorageMethod,
};
use serde::de::DeserializeSeed;

use crate::Cli;

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
) -> Result<BestExecSettings, Box<dyn std::error::Error>>
where
    P: AsRef<Path>,
{
    register_plugins();
    let settings_file = rar_common::get_settings(path)?;
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
                .ok_or("Settings file variable not found")?;
            let file = open_with_privileges(&file_path)?;
            let reader = BufReader::new(file); // Use BufReader for efficient streaming
            let mut io_reader = cbor4ii::core::utils::IoReader::new(reader); // Use IoReader for streaming
            Ok(BestExecSettings::retrieve_settings(
                cli,
                cred,
                &config_finder_deserializer
                    .deserialize(&mut cbor4ii::serde::Deserializer::new(&mut io_reader))?,
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
                .ok_or("Settings file variable not found")?;
            let file = open_with_privileges(&file_path)?;
            let reader = BufReader::new(file);
            let io_reader = serde_json::de::IoRead::new(reader);
            Ok(BestExecSettings::retrieve_settings(
                cli,
                cred,
                &config_finder_deserializer
                    .deserialize(&mut serde_json::Deserializer::new(io_reader))?,
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
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut result = Self::default();
        let mut matching = false;
        let mut opt_stack = BorrowedOptStack::new(data.options.clone());
        for role in data.roles() {
            matching |= result.role_settings(cli, &role, &mut opt_stack, env_path)?;
        }
        if !matching {
            return Err("No matching role found".into());
        }
        result.env = opt_stack
            .calc_temp_env(opt_stack.calc_override_behavior(), &cli.opt_filter)
            .calc_final_env(env_vars, opt_stack.calc_path(env_path), cred)?;
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
    ) -> Result<bool, Box<dyn std::error::Error>> {
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

    pub fn actors_settings<'c, 'a>(
        &mut self,
        data: &DLinkedRole<'c, 'a>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
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
    ) -> Result<bool, Box<dyn std::error::Error>> {
        debug!("task_settings: {:?}", data.id);
        let temp_opt_stack = BorrowedOptStack::from_task(data);
        let mut found = false;
        let mut f_env_path = None;
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
                    .ok_or_else::<Box<dyn std::error::Error>, _>(|| {
                        "No path found".to_string().into()
                    })?
                    .to_path_buf();
                }
                self.score.cmd_min = CmdMin::FullWildcardPath | CmdMin::RegexArgs;
            } else {
                for command in commands.add() {
                    found = self.command_settings(
                        &t_env_path.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                        cli,
                        &command,
                    )?;
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
            opt_stack.set_role(data.role().role().options.clone());
            opt_stack.set_task(data.task().options.clone());
        }

        Ok(found)
    }

    pub fn command_settings<'d, 'l, 't, 'c, 'a>(
        &mut self,
        env_path: &[&str],
        cli: &'d Cli,
        data: &DLinkedCommand<'d, 'l, 't, 'c, 'a>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
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
        if res.better(&self.score.cmd_min) {
            self.score.cmd_min = res;
            self.final_path = final_path;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::de::{DCommand, DCommandList, DRoleFinder, DTaskFinder, IdTask};
    use super::*;
    use rar_common::database::score::{ActorMatchMin, CmdMin, Score};
    use rar_common::database::structs::SetBehavior;
    use serde_json_borrow::Value;
    use std::path::PathBuf;

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
                            .build(),
                        DTaskFinder::builder()
                            .id(IdTask::Number(1))
                            .caps(CapSet::empty())
                            .commands(
                                DCommandList::builder(SetBehavior::None)
                                    .add(vec![
                                        DCommand::simple("/usr/bin/ls ^.*$"),
                                        DCommand::complex(Value::Object(
                                            [("key".into(), Value::Str("value".into()))]
                                                .into_iter()
                                                .collect::<Vec<_>>()
                                                .into(),
                                        )),
                                    ])
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
                            .build(),
                        DTaskFinder::builder()
                            .id(IdTask::Number(1))
                            .caps(CapSet::empty())
                            .commands(
                                DCommandList::builder(SetBehavior::None)
                                    .add(vec![DCommand::simple("/usr/bin/ls ^.*$")])
                                    .build(),
                            )
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
        let mut opt_stack = BorrowedOptStack::new(None);
        let env_path = &["/bin"];
        let result = best.task_settings(&cli, &data, &mut opt_stack, env_path);
        assert!(result.is_ok());
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
        assert!(result.is_ok());
        assert!(result.unwrap());
        let data = binding.add().nth(1).unwrap();
        let result = best.command_settings(env_path, &cli, &data);
        assert!(
            result.is_ok(),
            "Failed to process complex command : {}",
            result.unwrap_err()
        );
        assert!(!result.unwrap())
    }

    #[test]
    fn test_update_command_score_better() {
        let mut settings = BestExecSettings {
            score: Score {
                cmd_min: CmdMin::RegexArgs,
                ..Default::default()
            },
            final_path: PathBuf::from("/old/path"),
            ..Default::default()
        };
        let new_cmd_min = CmdMin::Match;
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
                cmd_min: CmdMin::Match,
                ..Default::default()
            },
            final_path: PathBuf::from("/old/path"),
            ..Default::default()
        };
        let worse_cmd_min = CmdMin::RegexArgs;
        let new_path = PathBuf::from("/new/path");
        let updated = settings.update_command_score(new_path, worse_cmd_min);
        assert!(!updated);
        assert_eq!(settings.final_path, PathBuf::from("/old/path"));
    }
}
