/// This file implements a finder algorithm within deserialization of the settings
/// It is much more efficient to do it this way, way less memory allocation and manipulation
/// Only the settings that are needed are kept in memory
use std::{collections::HashMap, io::BufReader, path::{Path, PathBuf}};

use api::{Api, ApiEvent, EventKey};
use capctl::CapSet;
use glob::Pattern;
use log::{debug, info, warn};
use nix::unistd::Group;
use rar_common::{database::{actor::{SActor, SGroupType, SGroups, SUserType}, finder::{ActorMatchMin, CapsMin, CmdMin, Cred, MatchError, Score, SetgidMin, SetuidMin}, options::{Level, Opt}, structs::{IdTask, SCapabilities, SetBehavior}}, util::{capabilities_are_exploitable, final_path, open_with_privileges}, StorageMethod};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use serde_json::Value;

use crate::Cli;

mod api;
mod hierarchy;
mod ssd;
mod hashchecker;

#[derive(Debug, Default, Clone)]
pub struct BestExecSettings {
    pub score: Score,
    pub opt: Opt,
    pub setuid: Option<SUserType>,
    pub setgroups: Option<SGroups>,
    pub caps: Option<CapSet>,
    pub task: IdTask,
    pub role: String,
}

struct GlobalSettingsVisitor<'a> {
    cli: &'a Cli,
    cred: &'a Cred,
}

struct RoleListSettingsVisitor<'a> {
    cli: &'a Cli,
    cred: &'a Cred,
    settings: &'a mut BestExecSettings,
}

struct RoleSettingsVisitor<'a> {
    cli: &'a Cli,
    cred: &'a Cred,
    settings: &'a mut BestExecSettings,
}

struct ActorsSettingsVisitor<'a> {
    cred: &'a Cred,
}

struct TaskListSettingsVisitor<'a> {
    cli: &'a Cli,
}

struct TaskSettingsVisitor<'a> {
    cli: &'a Cli,
    settings: &'a mut BestExecSettings,
}

struct CredSettingsVisitor<'a> {
    cli: &'a Cli,
    settings: &'a mut BestExecSettings,
}

struct SUserChooserVisitor<'a> {
    cli: &'a Cli,
    user: &'a mut Option<SUserType>
}

struct SGroupsChooserVisitor<'a> {
    cli: &'a Cli,
    groups: &'a mut Option<SGroups>,
}

struct CommandListSettingsVisitor<'a> {
    cli: &'a Cli,
    cmd_min: &'a mut CmdMin,
}

struct CommandSettingsVisitor<'a> {
    cli: &'a Cli,
    cmd_min: &'a mut CmdMin,
}

fn register_plugins() {
    ssd::register();
    hashchecker::register();
    hierarchy::register();
}

pub fn find_best_exec_settings<'a, P>(
    cli: &'a Cli,
    cred: &'a Cred,
    path: &'a P
) -> Result<BestExecSettings, Box<dyn std::error::Error>> 
where 
    P: AsRef<Path>,{
    register_plugins();
    let settings_file = rar_common::get_settings(path)?;
    match settings_file.storage.method {
        StorageMethod::CBOR => {
            let file_path = settings_file.storage.settings.unwrap_or_default().path.ok_or("Settings file variable not found")?;
            let file = open_with_privileges(&file_path)?;
            let reader = BufReader::new(file); // Use BufReader for efficient streaming
            let mut io_reader = cbor4ii::core::utils::IoReader::new(reader); // Use IoReader for streaming
            Ok(BestExecSettings::deserialize_with_params(
                &mut cbor4ii::serde::Deserializer::new(&mut io_reader),
                &cli,
                &cred,
            )?)
        },
        StorageMethod::JSON => {
            let file_path = settings_file.storage.settings.unwrap_or_default().path.ok_or("Settings file variable not found")?;
            let file = open_with_privileges(&file_path)?;
            let reader = BufReader::new(file);
            let io_reader = serde_json::de::IoRead::new(reader);
            Ok(BestExecSettings::deserialize_with_params(
                &mut serde_json::Deserializer::new(io_reader),
                &cli,
                &cred,
            )?)
        }
        _ => {
            Err("Storage method not supported".into())
        }
    }
}

impl<'a, 'de> BestExecSettings {
    pub fn deserialize_with_params<D>(deserializer: D,
        cli: &'a Cli,
        cred: &'a Cred,) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let visitor = GlobalSettingsVisitor {
            cli,
            cred,
        };
        debug!("Deserializing with params");
        deserializer.deserialize_map(visitor)
    }
}

impl<'a, 'de> Visitor<'de> for GlobalSettingsVisitor<'a> {
    type Value = BestExecSettings;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("RootAsRole configuration")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>, {
        let mut settings = BestExecSettings::default();
        let mut opt = Opt::level_default();
        debug!("GlobalSettingsVisitor: map");
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "options" => {
                    debug!("GlobalSettingsVisitor: options");
                    let mut temp_opt = map.next_value::<Opt>()?;
                    temp_opt.level = Level::Global;
                    opt.union(temp_opt);
                    opt.level = Level::Global;
                    settings.score.security_min = opt.calc_security_min();
                },
                "roles" => {
                    debug!("GlobalSettingsVisitor: roles");
                    // deserialize roles
                    map.next_value_seed(self.role_list_visitor(&mut settings))?;
                    if !settings.score.fully_matching() {
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        return Ok(settings);
                    }
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        settings.opt.union(opt);
        Api::notify(ApiEvent::BestGlobalSettingsFound(&mut settings)).map_err(
            |e| serde::de::Error::custom(format!("Error in plugins {}: {}",EventKey::BestGlobalSettings, e))
        )?;
        debug!("GlobalSettingsVisitor: end {:?}", settings);
        Ok(settings)
    }
}

impl<'a> GlobalSettingsVisitor<'a> {
    fn role_list_visitor(&self, settings: &'a mut BestExecSettings) -> RoleListSettingsVisitor<'a> {
        RoleListSettingsVisitor {
            cli: self.cli,
            cred: self.cred,
            settings,
        }
    }
}


impl<'a, 'de> DeserializeSeed<'de> for RoleListSettingsVisitor<'a> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(self)
    }
}

impl<'a, 'de> Visitor<'de> for RoleListSettingsVisitor<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("RootAsRole configuration")
    }

    fn visit_seq<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>, {
        debug!("RoleListSettingsVisitor: seq");
        let mut temp = BestExecSettings::default();
        while let Some(matches) = map.next_element_seed(self.role_visitor(&mut temp))? {
            if matches && temp.score.better_fully(&self.settings.score) {
                debug!("RoleListSettingsVisitor: Better role found {:?}", temp);
                *self.settings = temp;
            }
            temp = BestExecSettings::default();
        }
        
        Api::notify(
            ApiEvent::BestRoleSettingsFound(&mut *self.settings),
        ).map_err(
            |e| serde::de::Error::custom(format!("Error in plugins {}: {}",EventKey::BestTaskSettings, e))
        )?;
        debug!("RoleListSettingsVisitor: end {:?}", self.settings);
        Ok(true)
    }
}

impl<'a> RoleListSettingsVisitor<'a> {
    fn role_visitor(&self, temp: &'a mut BestExecSettings) -> RoleSettingsVisitor<'a> {
        RoleSettingsVisitor {
            cli: self.cli,
            cred: self.cred,
            settings: temp,
        }
    }
}

impl<'a, 'de> DeserializeSeed<'de> for RoleSettingsVisitor<'a> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_map(self)
    }
}

impl<'a, 'de> Visitor<'de> for RoleSettingsVisitor<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("role map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>, {
        debug!("RoleSettingsVisitor: map");
        let mut opt = Opt::default();
        let mut result = true;
        let mut settings = BestExecSettings::default();
        let mut role = String::new();
        let mut user_min = ActorMatchMin::NoMatch;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "name" => role = map.next_value()?,
                "actors" => {
                    let min = map.next_value_seed(ActorsSettingsVisitor {
                        cred: self.cred,
                    })?;
                    if min.better(&user_min) {
                        debug!("RoleSettingsVisitor: actor found {:?}", min);
                        user_min = min;
                    } else {
                        warn!("RoleSettingsVisitor: No actor matches");
                        // We must read tasks, it is useful for role hierarchy
                        result = false;
                    }
                },
                "tasks" => {
                    let task_visitor = TaskListSettingsVisitor {
                        cli: self.cli,
                    };
                    if let Some(ret_settings) = map.next_value_seed(task_visitor)? {
                        if ret_settings.score.better_command(&settings.score) {
                            info!("RoleSettingsVisitor: matching task found {:?}", ret_settings);
                            settings = ret_settings;
                        }
                        
                    } else {
                        warn!("RoleSettingsVisitor: No task matches");
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        return Ok(false);
                    }
                },
                "options" => {
                    let mut temp_opt = map.next_value::<Opt>()?;
                    temp_opt.level = Level::Role;
                    opt.union(temp_opt);
                    opt.level = Level::Role;
                }
                key => {
                    let value = map.next_value::<serde_json::Value>()?;
                    Api::notify(
                        ApiEvent::NewRoleKey(key, &value),
                    ).map_err(
                        |e| serde::de::Error::custom(format!("Error in plugins {}: {}",EventKey::NewRoleKey, e))
                    )?;
                }
            }
        }
        settings.role = role;
        settings.score.user_min = user_min;
        settings.opt.union(opt);
        settings.score.security_min = settings.opt.calc_security_min();
        *self.settings = settings;
        Api::notify(
            ApiEvent::BestTaskSettingsFound(self.settings),
        ).map_err(
            |e| serde::de::Error::custom(format!("Error in plugins {}: {}",EventKey::BestTaskSettings, e)))?;
        warn!("RoleSettingsVisitor: end {:?}", self.settings);
        Ok(result)
    }
}

impl<'de> DeserializeSeed<'de> for ActorsSettingsVisitor<'_> {
    type Value = ActorMatchMin;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_seq(self)
    }
}


impl<'de> Visitor<'de> for ActorsSettingsVisitor<'_> {
    type Value = ActorMatchMin;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a set of users")
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>, {
        let mut user_matches = ActorMatchMin::NoMatch;
        while let Some(actor) = seq.next_element::<SActor>()? {
            debug!("ActorsSettingsVisitor: actor {:?}", actor);
            let temp = self.user_matches(self.cred, &actor);
            if temp != ActorMatchMin::NoMatch && temp < user_matches {
                info!("ActorsSettingsVisitor: Better actor found {:?}", temp);
                user_matches = temp;
            }
        }
        Ok(user_matches)
    }
}

impl ActorsSettingsVisitor<'_> {
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
    fn user_matches(&self, user: &Cred, actor: &SActor) -> ActorMatchMin {
        match actor {
            SActor::User { id, .. } => {
                if let Some(id) = id {
                    if *id == user.user {
                        return ActorMatchMin::UserMatch;
                    }
                }
            }
            SActor::Group { groups, .. } => {
                if let Some(groups) = groups.as_ref() {
                    if Self::match_groups(&user.groups, &[groups.clone()]) {
                        return ActorMatchMin::GroupMatch(groups.len());
                    }
                }
            }
            SActor::Unknown(element) => {
                unimplemented!("Unknown actor type: {:?}", element);
            }
        }
        ActorMatchMin::NoMatch
    }
}

impl<'de> DeserializeSeed<'de> for TaskListSettingsVisitor<'_> {
    type Value = Option<BestExecSettings>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_seq(self)
    }
}
impl<'a, 'de> Visitor<'de> for TaskListSettingsVisitor<'_> {
    type Value = Option<BestExecSettings>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("task list")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>, {
        debug!("TaskListSettingsVisitor: seq");
        let mut result: Option<BestExecSettings> = None;
        let mut temp = BestExecSettings::default();
        let mut task_visitor = TaskSettingsVisitor {
            cli: self.cli,
            settings: &mut temp,
        };
        while let Some(matches) = seq.next_element_seed(task_visitor)? {
            if matches && result.as_ref().is_none_or(|x| temp.score.better_command(&x.score)) {
                debug!("TaskListSettingsVisitor: Better task found {:?}", temp);
                result = Some(temp.clone());
            }
            task_visitor = TaskSettingsVisitor {
                cli: self.cli,
                settings: &mut temp,
            };
        }
        debug!("TaskListSettingsVisitor: end {:?}", result);
        Ok(result)
    }
}
impl<'a, 'de> DeserializeSeed<'de> for TaskSettingsVisitor<'a> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_map(self)
    }
}
impl<'a, 'de> Visitor<'de> for TaskSettingsVisitor<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("task map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>, {
        debug!("TaskSettingsVisitor: map");
        let mut result = BestExecSettings::default();
        let mut opt = Opt::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "name" => self.settings.task = map.next_value()?,
                "cred" => {
                    let cred_visitor = CredSettingsVisitor {
                        cli: self.cli,
                        settings: &mut result,
                    };
                    if !map.next_value_seed(cred_visitor)? {
                        warn!("TaskSettingsVisitor: No cred matches");
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        return Ok(false);
                    }
                },
                "commands" => {
                    let command_visitor = CommandListSettingsVisitor {
                        cli: self.cli,
                        cmd_min: &mut result.score.cmd_min,
                    };
                    if !map.next_value_seed(command_visitor)? {
                        warn!("TaskSettingsVisitor: No command matches");
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        return Ok(false);
                    }

                },
                "options" => {
                    let mut temp_opt = map.next_value::<Opt>()?;
                    temp_opt.level = Level::Task;
                    opt.union(temp_opt);
                    result.score.security_min = opt.calc_security_min();
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        opt.union(result.opt);
        result.opt = opt;
        result.score.security_min = result.opt.calc_security_min();
        *self.settings = result;
        debug!("TaskSettingsVisitor: end {:?}", self.settings);
        Ok(true)
    }
}

impl<'a, 'de> DeserializeSeed<'de> for CredSettingsVisitor<'a> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_map(self)
    }
}

impl<'a, 'de> Visitor<'de> for CredSettingsVisitor<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("cred map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>, {
        debug!("CredSettingsVisitor: map");
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "setuid" => {
                    let mut user = None;
                    let setuid_visitor = SUserChooserVisitor {
                        cli: self.cli,
                        user: &mut user,
                    };
                    if map.next_value_seed(setuid_visitor)? {
                        self.settings.score.setuser_min.uid = user.and_then(|x| {
                            self.settings.setuid = Some(x.clone());
                            Some(Into::<SetuidMin>::into(x))
                        });
                    } else {
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        return Ok(false);
                    }
                }
                "setgid" => {
                    let mut groups = None;
                    let setgroups_visitor = SGroupsChooserVisitor {
                        cli: self.cli,
                        groups: &mut groups,
                    };
                    if map.next_value_seed(setgroups_visitor)? {
                        self.settings.score.setuser_min.gid = groups.and_then(|x| {
                            self.settings.setgroups = Some(x.clone());
                            Some(Into::<SetgidMin>::into(x))
                        });
                    } else {
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        return Ok(false);
                    }
                },
                "capabilities" | "caps" => {
                    let caps: SCapabilities = map.next_value()?;
                    let capset = caps.to_capset();
                    self.settings.score.caps_min = Self::get_caps_min(&capset);
                    self.settings.caps = Some(capset);
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(true)
    }
}

impl CredSettingsVisitor<'_> {
    fn get_caps_min(caps: &CapSet) -> CapsMin {
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
}

impl<'a, 'de> DeserializeSeed<'de> for SGroupsChooserVisitor<'a> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_any(self)
    }
}

impl<'a, 'de> Visitor<'de> for SGroupsChooserVisitor<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a struct of allowed impersonating, user id, or user name")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>, {
        let mut default = SetBehavior::default();
        let filter = self.cli.opt_filter.as_ref().and_then(|x| x.group.as_ref());
        let mut add: Vec<SGroups> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "default" => {
                    default = map.next_value()?;
                },
                "fallback" => {
                    let value: SGroups = map.next_value()?;
                    if let Some(u) = filter {
                        if u == &value {
                            return Ok(true);
                        }
                    } else {
                        self.groups.replace(value);
                    }
                }
                "add" => {
                    if filter.is_some() {
                        add = map.next_value()?;
                    }
                }
                "del" => {
                    if let Some(u) = filter {
                        if map.next_value::<Vec<SGroups>>()?.contains(u) {
                            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                            return Ok(false);
                        }
                    }
                }
                _ => {}
            }
        }
        if default.is_all() || filter.is_some_and(|u| add.iter().any(|x| x == u)) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        if v > u32::MAX as u64 {
            return Err(serde::de::Error::custom(format!("setuid {} is too big", v)));
        }
        if self.cli.opt_filter.as_ref().and_then(|x| x.group.as_ref()).is_some() {
            return Ok(false);
        } else {
            self.groups.replace(SGroups::Single((v as u32).into()));
            return Ok(true);
        }
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        if self.cli.opt_filter.as_ref().and_then(|x| x.group.as_ref()).is_some() {
            return Ok(false);
        } else {
            self.groups.replace(SGroups::Single(v.into()));
            return Ok(true);
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>, {
        debug!("SGroupsChooserVisitor: seq");
        let mut groups = Vec::new();
        while let Some(group) = seq.next_element::<SGroupType>()? {
            groups.push(group);
        }
        if self.cli.opt_filter.as_ref().and_then(|x| x.group.as_ref()).is_some() {
            // this setgid do not allow setting filter
            Ok(false)
        } else {
            self.groups.replace(SGroups::Multiple(groups));
            Ok(true)
        }
        
    }
}

impl<'a, 'de> DeserializeSeed<'de> for SUserChooserVisitor<'a> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de> {
            deserializer.deserialize_any(self)
    }
}

impl<'a, 'de> Visitor<'de> for SUserChooserVisitor<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a struct of allowed impersonating, user id, or user name")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>, {
        debug!("SUserChooserVisitor: map");
        let mut default = SetBehavior::default();
        let filter = self.cli.opt_filter.as_ref().and_then(|x| x.user.as_ref());
        let mut add: Vec<SUserType> = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "default" => {
                    default = map.next_value()?;
                },
                "fallback" => {
                    let value: SUserType = map.next_value()?;
                    if let Some(u) = filter {
                        if u == &value {
                            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                            return Ok(true);
                        }
                    } else {
                        self.user.replace(value);
                    }
                }
                "add" => {
                    if filter.is_some() {
                        add = map.next_value()?;
                    }
                }
                "del" => {
                    if let Some(u) = filter {
                        if map.next_value::<Vec<SUserType>>()?.contains(u) {
                            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                            return Ok(false);
                        }
                    }
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if default.is_all() || filter.is_some_and(|u| add.iter().any(|x| x == u)) {
            Ok(true)
        } else {
            Ok(false)
        }
        
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        if self.cli.opt_filter.as_ref().and_then(|x| x.user.as_ref()).is_some() {
            return Ok(false);
        } else {
            self.user.replace(v.into());
            return Ok(true);
        }
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        if v > u32::MAX as u64 {
            return Err(serde::de::Error::custom(format!("setuid {} is too big", v)));
        }
        if self.cli.opt_filter.as_ref().and_then(|x| x.user.as_ref()).is_some() {
            return Ok(false);
        } else {
            self.user.replace((v as u32).into());
            return Ok(true);
        }
    }
}

impl<'a, 'de> DeserializeSeed<'de> for CommandListSettingsVisitor<'a> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_any(self)
    }
}
impl<'a, 'de> Visitor<'de> for CommandListSettingsVisitor<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("command seq")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>, {
        debug!("CommandListSettingsVisitor: seq");
        let mut result = CmdMin::empty();
        while let Some(command) = seq.next_element_seed(self.command_visitor(&mut result))? {
            debug!("CommandListSettingsVisitor: command {:?} {:?}", command, result);
            if command && result.better(self.cmd_min) {
                info!("CommandListSettingsVisitor: Found a better command : {:?}", result);
                *self.cmd_min = result;
            }
        }
        Ok(true)
    }

    /*
    {
        "default": "none",
        "add": [
            ""
        ],
        "del": [
            ""
        ]
    }
     */
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>, {
        debug!("CommandListSettingsVisitor: map");
        let mut behavior = SetBehavior::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "default" => {
                    behavior = map.next_value()?;
                }
                "add" => {
                    let mut temp_res: CmdMin = CmdMin::empty();
                    let command_visitor = CommandListSettingsVisitor {
                        cli: self.cli,
                        cmd_min: &mut temp_res,
                    };
                    let res = map.next_value_seed(command_visitor)?;
                    if res && temp_res.better(self.cmd_min) {
                        debug!("CommandListSettingsVisitor: Found a better command : {:?}", temp_res);
                        *self.cmd_min = temp_res;
                    }
                    debug!("CommandListSettingsVisitor: end add {:?}", self.cmd_min);
                }
                "del" => {
                    let mut temp_cmd_min = CmdMin::empty();
                    let command_visitor = CommandListSettingsVisitor {
                        cli: self.cli,
                        cmd_min: &mut temp_cmd_min,
                    };
                    map.next_value_seed(command_visitor)?;
                    if !temp_cmd_min.is_empty() {
                        *self.cmd_min = CmdMin::empty();
                        warn!("CommandListSettingsVisitor: A denied command found : {:?}", temp_cmd_min);
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        return Ok(false);
                    }
                    debug!("CommandListSettingsVisitor: end del {:?}", self.cmd_min);
                }
                _ => {
                    let _ = map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if behavior.is_all() {
            debug!("default CommandListBehavior is All");
            *self.cmd_min |= CmdMin::FullWildcardPath;
        }
        debug!("CommandListSettingsVisitor: {:?}", self.cmd_min);
        if !self.cmd_min.is_empty() {
            return Ok(true)
        }
        warn!("CommandListSettingsVisitor: return false");
        return Ok(false);

    }
}

impl<'a> CommandListSettingsVisitor<'a> {
    fn command_visitor(&self, cmd_min: &'a mut CmdMin) -> CommandSettingsVisitor<'a> {
        CommandSettingsVisitor {
            cli: self.cli,
            cmd_min,
        }
    }
}

impl<'a, 'de> DeserializeSeed<'de> for CommandSettingsVisitor<'a> {
    type Value = bool;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        deserializer.deserialize_any(self)
    }
}

impl<'a, 'de> Visitor<'de> for CommandSettingsVisitor<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("cmd string or cmd map")
    }

    fn visit_str<E>(mut self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error, {
        self.evaluate_command_match(
            &self.cli.cmd_path,
            &self.cli.cmd_args,
            v,
        );
        Ok(true)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>, {
        debug!("CommandSettingsVisitor: map");
        let mut result = CmdMin::empty();
        let mut map_value: HashMap<String, Value> = HashMap::new();
        while let Some((key,value)) = map.next_entry::<String, Value>()? {
            map_value.insert(key, value);
        }
        Api::notify(ApiEvent::NewComplexCommand(&map_value, &self.cli.cmd_path, self.cli.cmd_args.as_slice(), &mut result)).map_err(
            |e| serde::de::Error::custom(format!("Error in command map: {}", e))
        )?;
        Ok(!result.is_empty())
    }
}

impl CommandSettingsVisitor<'_> {
    
    fn match_path(&mut self, new_path: &PathBuf, role_path: &str) -> CmdMin {
        if role_path == "**" {
            return CmdMin::FullWildcardPath;
        }
        let mut match_status = CmdMin::empty();
        if !role_path.ends_with(new_path.to_str().unwrap()) {
            // the files could not be the same
            return CmdMin::empty();
        }
        let role_path = final_path(role_path);
        debug!("Matching path {:?} with {:?}", new_path, role_path);
        if *new_path == role_path {
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
    fn match_args(&mut self, input_args: &[String], role_args: &[String]) -> Result<CmdMin, Box<dyn std::error::Error>> {
        if role_args[0] == ".*" {
            return Ok(CmdMin::FullRegexArgs);
        }
        let commandline = input_args.join(" ");
        let role_args = role_args.join(" ");
        debug!("Matching args {:?} with {:?}", commandline, role_args);
        let res = if commandline != role_args {
            debug!("test regex");
            Self::evaluate_regex_cmd(role_args, commandline).inspect_err(|e| {
                debug!("{:?},No match for args {:?}", e, input_args);
            })
        } else {
            Ok(CmdMin::Match)
        };
        res
    }
    
    #[cfg(feature = "pcre2")]
    fn evaluate_regex_cmd(role_args: String, commandline: String) -> Result<CmdMin, Box<dyn std::error::Error>> {
        let regex = RegexBuilder::new().build(&role_args)?;
        if regex.is_match(commandline.as_bytes())? {
            Ok(CmdMin::RegexArgs)
        } else {
            Err(Box::new(MatchError::NoMatch(
                "Regex for command does not match".to_string(),
            )))
        }
    }
    
    #[cfg(not(feature = "pcre2"))]
    fn evaluate_regex_cmd(_role_args: String, _commandline: String) -> Result<CmdMin, Box<dyn std::error::Error>> {

        Err(Box::new(MatchError::NoMatch("No match found".to_string())))
    }
    
    /// Check if input command line is matching with role command line and return the score
    fn match_command_line(&mut self, cmd_path: &PathBuf, cmd_args: &[String], role_command: &[String]) -> CmdMin {
        let mut result = self.match_path(&cmd_path, &role_command[0]);
        if result.is_empty() || role_command.len() == 1 {
            return result;
        }
        match self.match_args(cmd_args, &role_command[1..]) {
            Ok(args_result) => result |= args_result,
            Err(err) => {
                if err.downcast_ref::<MatchError>().is_none() {
                    warn!("Error: {}", err);
                }
                return CmdMin::empty();
            }
        }
        result
    }

    pub fn evaluate_command_match(&mut self, cmd_path: &PathBuf, cmd_args: &[String], command: &str) {
        match shell_words::split(command).map_err(|e| Into::<Box<dyn std::error::Error>>::into(e)) {
            Ok(command) => {
                let new_score = self.match_command_line(cmd_path, cmd_args, &command);
                debug!("Score for command {:?} is {:?}", command, new_score);
                if !new_score.is_empty() && (self.cmd_min.is_empty() || (new_score < *self.cmd_min)) {
                    debug!("New min score for command {:?} is {:?}", command, new_score);
                    *self.cmd_min = new_score;
                }
            }
            Err(err) => {
                warn!("Error: {}", err);
            }
        }
    }
}