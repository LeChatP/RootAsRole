/// This file implements a finder algorithm within deserialization of the settings
/// It is much more efficient to do it this way, way less memory allocation and manipulation
/// Only the settings that are needed are kept in memory
use std::{
    env,
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
        actor::{SGroups, SUserType},
        score::{CmdMin, Score},
    },
    util::open_with_privileges,
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
    pub opt: rar_common::database::options::Opt,
    pub final_path: PathBuf,
    pub setuid: Option<SUserType>,
    pub setgroups: Option<SGroups>,
    pub caps: Option<CapSet>,
    pub task: Option<String>,
    pub role: String,
}

pub fn find_best_exec_settings<'de: 'a, 'a, P>(
    cli: &'a Cli,
    cred: &'a Cred,
    path: &'a P,
) -> Result<BestExecSettings, Box<dyn std::error::Error>>
where
    P: AsRef<Path>,
{
    register_plugins();
    let settings_file = rar_common::get_settings(path)?;
    let config_finder_deserializer = ConfigFinderDeserializer { cli, cred };
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
                config_finder_deserializer
                    .deserialize(&mut cbor4ii::serde::Deserializer::new(&mut io_reader))?,
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
                config_finder_deserializer
                    .deserialize(&mut serde_json::Deserializer::new(io_reader))?,
            )?)
        }
        _ => Err("Storage method not supported".into()),
    }
}

impl BestExecSettings {
    fn retrieve_settings<'a>(
        cli: &'a Cli,
        data: DConfigFinder<'a>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut result = Self::default();
        let mut matching = false;
        for role in data.roles() {
            matching |= result.role_settings(cli, role)?;
        }
        Api::notify(ApiEvent::BestGlobalSettingsFound(&cli, &data, &mut result, &mut matching))?;
        if !matching {
            return Err("No matching role found".into());
        }
        Ok(result)
    }

    pub fn role_settings<'a>(
        &mut self,
        cli: &'a Cli,
        data: DLinkedRole<'a>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        if !self.actors_settings(&data)? {
            return Ok(false);
        }
        let mut res = false;
        for task in data.tasks() {
            res |= self.task_settings(cli, task)?;
        }
        if res {
            self.role = data.role().role.to_string();
        }
        Api::notify(ApiEvent::BestRoleSettingsFound(&cli, &data, self, &mut res))?;
        Ok(res)
    }

    pub fn actors_settings<'a>(
        &mut self,
        data: &'a DLinkedRole<'a>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut res = !data.role().user_min.is_no_match();
        Api::notify(ApiEvent::ActorMatching(
            &data, self, &mut res,
        ))?;
        Ok(res)
    }

    pub fn task_settings<'a>(
        &mut self,
        cli: &'a Cli,
        data: DLinkedTask<'a>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut res = false;
        let opt_stack = BorrowedOptStack::from_task(&data);
        let env_path = opt_stack.calc_path(|behavior| {
            env::var("PATH")
                .unwrap_or_default()
                .split(':')
                .map(|s| s.into())
                .filter(|path: &PathBuf| behavior.is_keep_unsafe() || path.is_absolute())
                .collect::<Vec<_>>()
        });
        if let Some(commands) = &data.commands() {
            for command in commands.del() {
                if self.command_settings(&env_path, cli, command)? {
                    return Ok(false);
                }
            }
            for command in commands.add() {
                res |= self.command_settings(&env_path, cli, command)?;
            }
        }
        if res {
            self.task = Some(data.task.id.to_string());
            let cmd_min = self.score.cmd_min.clone();
            self.score = data.score(&opt_stack)
        }
        Api::notify(ApiEvent::BestTaskSettingsFound(&cli, &data, self, &mut res))?;
        Ok(res)
    }

    pub fn command_settings<'a>(
        &mut self,
        env_path: &[PathBuf],
        cli: &'a Cli,
        data: DLinkedCommand<'a>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        
        debug!("env_path: {:?}", env_path);
        match data.command {
            de::DCommand::Simple(role_cmd) => {
                let mut final_path = PathBuf::new();
                let cmd_min = cmd::evaluate_command_match(
                    env_path,
                    &cli.cmd_path,
                    &cli.cmd_args,
                    role_cmd,
                    &mut final_path,
                );
                self.update_command_score(data, final_path, cmd_min);
            }
            de::DCommand::Complex(value) => {
                let mut cmd_min = CmdMin::empty();
                let mut final_path = PathBuf::new();
                Api::notify(ApiEvent::ProcessComplexCommand(
                    value,
                    env_path,
                    &cli.cmd_path,
                    &cli.cmd_args,
                    &mut cmd_min,
                    &mut final_path,
                ))?;
                self.update_command_score(data, final_path, cmd_min);
            }
        }
        Ok(true)
    }

    fn update_command_score<'a>(
        &mut self,
        data: DLinkedCommand<'a>,
        final_path: PathBuf,
        res: CmdMin,
    ) {
        if  self.score.cmd_min.better(&res) {
            debug!("New command found: {:?}", data.command);
            self.score.cmd_min = res;
            self.final_path = final_path;
        }
    }
}

#[cfg(test)]
mod tests {}
