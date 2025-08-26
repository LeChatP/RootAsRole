/// Lossy deserializer for an optimized user access search
use std::{
    borrow::Cow, collections::HashMap, fmt::Display, ops::Deref, path::PathBuf, str::FromStr,
};

use bon::Builder;
use capctl::CapSet;
use derivative::Derivative;
use log::{debug, info};
use nix::unistd::Group;
use rar_common::{
    database::{
        actor::{DActor, DGroupType, DGroups, DUserType},
        options::Level,
        score::{
            ActorMatchMin, CapsMin, CmdMin, Score, SecurityMin, SetgidMin, SetuidMin, TaskScore,
        },
        structs::{SCapabilities, SetBehavior},
    },
    util::capabilities_are_exploitable,
    Cred,
};
use serde::{
    de::{DeserializeSeed, IgnoredAny, Visitor},
    Deserialize,
};
use serde_json::Value;
use strum::EnumIs;

use crate::{
    finder::{
        api::{Api, ApiEvent},
        cmd,
        options::DPathOptions,
    },
    Cli,
};

use super::options::Opt;

#[cfg_attr(test, derive(Builder))]
#[derive(PartialEq, Eq, Debug, Default)]
pub struct DConfigFinder<'a> {
    pub options: Option<Opt<'a>>,
    pub roles: Vec<DRoleFinder<'a>>,
}

#[cfg_attr(test, derive(Builder))]
#[derive(Debug, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct DRoleFinder<'a> {
    #[cfg_attr(test, builder(default))]
    pub user_min: ActorMatchMin,
    #[cfg_attr(test, builder(into))]
    pub role: Cow<'a, str>,
    #[cfg_attr(test, builder(default))]
    pub tasks: Vec<DTaskFinder<'a>>,
    pub options: Option<Opt<'a>>,
    #[cfg_attr(test, builder(default))]
    pub _extra_values: HashMap<Cow<'a, str>, Value>,
}

#[derive(Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum IdTask<'a> {
    Name(#[serde(borrow)] Cow<'a, str>),
    Number(usize),
}

impl Display for IdTask<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdTask::Name(name) => write!(f, "{}", name),
            IdTask::Number(num) => write!(f, "{}", num),
        }
    }
}

#[derive(Debug, Derivative, Builder)]
#[derivative(PartialEq, Eq)]
pub struct DTaskFinder<'a> {
    pub id: IdTask<'a>,
    #[builder(default)]
    pub score: TaskScore,
    pub setuid: Option<DUserType<'a>>,
    pub setgroups: Option<DGroups<'a>>,
    pub caps: Option<CapSet>,
    pub commands: Option<DCommandList<'a>>,
    pub options: Option<Opt<'a>>,
    pub final_path: Option<PathBuf>,
    #[builder(default)]
    pub _extra_values: HashMap<Cow<'a, str>, Value>,
}

#[derive(Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum DCommand<'a> {
    Simple(#[serde(borrow)] Cow<'a, str>),
    Complex(Value),
}

#[cfg(test)]
impl<'a> DCommand<'a> {
    pub fn simple(cmd: &'a str) -> Self {
        DCommand::Simple(Cow::Borrowed(cmd))
    }
    pub fn complex(cmd: Value) -> Self {
        DCommand::Complex(cmd)
    }
}

pub struct ConfigFinderDeserializer<'a> {
    pub cli: &'a Cli,
    pub cred: &'a Cred,
    pub env_path: &'a [&'a str],
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for ConfigFinderDeserializer<'a> {
    type Value = DConfigFinder<'a>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field<'a> {
            Options,
            Roles,
            #[serde(untagged, borrow)]
            #[allow(dead_code)]
            Unknown(Cow<'a, str>),
        }

        struct ConfigFinderVisitor<'a> {
            cli: &'a Cli,
            cred: &'a Cred,
            env_path: &'a [&'a str],
            human_readable: bool,
        }

        impl<'de: 'a, 'a> Visitor<'de> for ConfigFinderVisitor<'a> {
            type Value = DConfigFinder<'a>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("policy")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut options = None;
                let mut roles = Vec::new();
                let mut spath = DPathOptions::default_path();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Options => {
                            debug!("ConfigFinderVisitor: options");
                            let mut opt: Opt = map.next_value()?;
                            opt.level = Level::Global;
                            if self.human_readable {
                                if let Some(path) = opt.path.as_ref() {
                                    spath.union(path.clone());
                                }
                            }
                            options = Some(opt);
                        }
                        Field::Roles => {
                            debug!("ConfigFinderVisitor: roles");
                            roles = map.next_value_seed(RoleListFinderDeserializer {
                                cli: self.cli,
                                cred: self.cred,
                                spath: &mut spath,
                                env_path: self.env_path,
                            })?;
                        }
                        Field::Unknown(_) => {
                            debug!("ConfigFinderVisitor: unknown");
                            let _ = map.next_value::<IgnoredAny>();
                        }
                    }
                }
                Ok(DConfigFinder { options, roles })
            }
        }
        const FIELDS: &[&str] = &["options", "roles", "version"];
        let human_readable = deserializer.is_human_readable();
        let res = deserializer.deserialize_struct(
            "Config",
            FIELDS,
            ConfigFinderVisitor {
                cli: self.cli,
                cred: self.cred,
                human_readable,
                env_path: self.env_path,
            },
        );
        res
    }
}

struct RoleListFinderDeserializer<'a, 'b> {
    cli: &'a Cli,
    cred: &'a Cred,
    spath: &'b mut DPathOptions<'a>,
    env_path: &'a [&'a str],
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for RoleListFinderDeserializer<'a, '_> {
    type Value = Vec<DRoleFinder<'a>>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RoleListFinderVisitor<'a, 'b> {
            cli: &'a Cli,
            cred: &'a Cred,
            spath: &'b mut DPathOptions<'a>,
            env_path: &'a [&'a str],
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for RoleListFinderVisitor<'a, '_> {
            type Value = Vec<DRoleFinder<'a>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("RoleList sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                debug!("RoleListFinderVisitor: visit_seq");
                let mut roles = Vec::new();
                while let Some(role) = seq.next_element_seed(RoleFinderDeserializer {
                    cli: self.cli,
                    cred: self.cred,
                    spath: self.spath,
                    env_path: self.env_path,
                })? {
                    if let Some(role) = role {
                        debug!("adding role {:?}", role);
                        roles.push(role);
                    }
                }
                Ok(roles)
            }
        }
        deserializer.deserialize_seq(RoleListFinderVisitor {
            cli: self.cli,
            cred: self.cred,
            spath: self.spath,
            env_path: self.env_path,
        })
    }
}

struct RoleFinderDeserializer<'a, 'b> {
    cli: &'a Cli,
    cred: &'a Cred,
    env_path: &'a [&'a str],
    spath: &'b mut DPathOptions<'a>,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for RoleFinderDeserializer<'a, '_> {
    type Value = Option<DRoleFinder<'a>>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field<'a> {
            #[serde(alias = "n")]
            Name,
            #[serde(alias = "a", alias = "users")]
            Actors,
            #[serde(alias = "t")]
            Tasks,
            #[serde(alias = "o")]
            Options,
            #[serde(untagged, borrow)]
            Unknown(Cow<'a, str>),
        }

        struct RoleFinderVisitor<'a, 'b> {
            cli: &'a Cli,
            cred: &'a Cred,
            env_path: &'a [&'a str],
            spath: &'b mut DPathOptions<'a>,
            _human_readable: bool,
        }

        impl<'de: 'a, 'a> Visitor<'de> for RoleFinderVisitor<'a, '_> {
            type Value = Option<DRoleFinder<'a>>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a role")
            }
            fn visit_map<V>(mut self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                debug!("RoleFinderVisitor: visit_map");
                let mut role = None;
                let mut tasks: Vec<DTaskFinder<'a>> = Vec::new();
                let mut options = None;
                let mut extra_values = HashMap::new();
                let mut user_min = ActorMatchMin::default();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Options => {
                            debug!("RoleFinderVisitor: options");
                            let mut opt: Opt = map.next_value()?;
                            opt.level = Level::Role;
                            if let Some(path) = opt.path.as_ref() {
                                self.spath.union(path.clone().into());
                            }
                            options = Some(opt);
                        }
                        Field::Name => {
                            debug!("RoleFinderVisitor: name");
                            let role_name = map.next_value()?;
                            if self
                                .cli
                                .opt_filter
                                .as_ref()
                                .and_then(|x| x.role.as_ref())
                                .is_some_and(|r| r != &role_name)
                            {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                            role = Some(role_name);
                        }
                        Field::Actors => {
                            debug!("RoleFinderVisitor: actors");
                            user_min =
                                map.next_value_seed(ActorsFinderDeserializer { cred: self.cred })?;
                        }
                        Field::Tasks => {
                            debug!("RoleFinderVisitor: tasks");
                            tasks = map.next_value_seed(TaskListFinderDeserializer {
                                cli: self.cli,
                                spath: &mut self.spath,
                                env_path: self.env_path,
                            })?;
                        }
                        Field::Unknown(key) => {
                            debug!("RoleFinderVisitor: unknown {}", key);
                            let unknown: Value = map.next_value()?;
                            extra_values.insert(key, unknown);
                        }
                    }
                }
                Ok(Some(DRoleFinder {
                    user_min,
                    role: role.unwrap_or_default(),
                    tasks,
                    options,
                    _extra_values: extra_values,
                }))
            }
        }
        const FIELDS: &[&str] = &["name", "tasks", "options"];
        let _human_readable = deserializer.is_human_readable();
        deserializer.deserialize_struct(
            "Role",
            FIELDS,
            RoleFinderVisitor {
                cli: self.cli,
                cred: self.cred,
                spath: self.spath,
                env_path: self.env_path,
                _human_readable,
            },
        )
    }
}

struct ActorsFinderDeserializer<'a> {
    cred: &'a Cred,
}

impl<'de> DeserializeSeed<'de> for ActorsFinderDeserializer<'_> {
    type Value = ActorMatchMin;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ActorsFinderVisitor<'a> {
            cred: &'a Cred,
        }

        impl<'de> Visitor<'de> for ActorsFinderVisitor<'_> {
            type Value = ActorMatchMin;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a set of users")
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut user_matches = ActorMatchMin::NoMatch;
                while let Some(actor) = seq.next_element::<DActor>()? {
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

        impl ActorsFinderVisitor<'_> {
            fn match_groups(groups: &[Group], role_groups: &[&DGroups<'_>]) -> bool {
                for role_group in role_groups {
                    if match role_group {
                        DGroups::Single(group) => groups.iter().any(|g| group == g),
                        DGroups::Multiple(multiple_actors) => multiple_actors
                            .iter()
                            .all(|actor| groups.iter().any(|g| actor == g)),
                    } {
                        return true;
                    }
                }
                false
            }
            fn user_matches(&self, user: &Cred, actor: &DActor<'_>) -> ActorMatchMin {
                match actor {
                    DActor::User { id, .. } => {
                        if *id == user.user {
                            return ActorMatchMin::UserMatch;
                        }
                    }
                    DActor::Group { groups, .. } => {
                        if Self::match_groups(&user.groups, &[groups]) {
                            return ActorMatchMin::GroupMatch(groups.len());
                        }
                    }
                    DActor::Unknown(element) => {
                        unimplemented!("Unknown actor type: {:?}", element);
                    }
                }
                ActorMatchMin::NoMatch
            }
        }

        deserializer.deserialize_seq(ActorsFinderVisitor { cred: self.cred })
    }
}

struct TaskListFinderDeserializer<'a, 'b> {
    cli: &'a Cli,
    env_path: &'a [&'a str],
    spath: &'b mut DPathOptions<'a>,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for TaskListFinderDeserializer<'a, '_> {
    type Value = Vec<DTaskFinder<'a>>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TaskListFinderVisitor<'a, 'b> {
            cli: &'a Cli,
            spath: &'b mut DPathOptions<'a>,
            env_path: &'a [&'a str],
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for TaskListFinderVisitor<'a, '_> {
            type Value = Vec<DTaskFinder<'a>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("TaskList sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut tasks = Vec::new();
                let mut i = 0;
                while let Some(element) = seq.next_element_seed(TaskFinderDeserializer {
                    cli: self.cli,
                    spath: self.spath,
                    env_path: self.env_path,
                    i,
                })? {
                    if let Some(task) = element {
                        debug!("adding task {:?}", task);
                        tasks.push(task);
                        i += 1;
                    }
                }
                Ok(tasks)
            }
        }
        deserializer.deserialize_seq(TaskListFinderVisitor {
            cli: self.cli,
            spath: self.spath,
            env_path: self.env_path,
        })
    }
}

struct TaskFinderDeserializer<'a, 'b> {
    cli: &'a Cli,
    i: usize,
    env_path: &'a [&'a str],
    spath: &'b mut DPathOptions<'a>,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for TaskFinderDeserializer<'a, '_> {
    type Value = Option<DTaskFinder<'a>>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field<'a> {
            #[serde(alias = "n")]
            Name,
            #[serde(alias = "i", alias = "credentials")]
            Cred,
            #[serde(alias = "c", alias = "cmds")]
            Commands,
            #[serde(alias = "o")]
            Options,
            #[serde(untagged, borrow)]
            Unknown(Cow<'a, str>),
        }

        struct TaskFinderVisitor<'a, 'b> {
            cli: &'a Cli,
            i: usize,
            env_path: &'a [&'a str],
            spath: &'b mut DPathOptions<'a>,
            human_readable: bool,
        }

        impl<'de: 'a, 'a> serde::de::Visitor<'de> for TaskFinderVisitor<'a, '_> {
            type Value = Option<DTaskFinder<'a>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("STask structure")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                // Use local temporaries for each field
                let mut id = IdTask::Number(self.i);
                let mut score = TaskScore::default();
                let mut setuid = None;
                let mut setgroups = None;
                let mut caps = None;
                let mut commands = None;
                let mut options = None;
                let mut final_path = None;
                let mut extra_values = HashMap::new();

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Options => {
                            debug!("TaskFinderVisitor: options");
                            let mut opt: Opt = map.next_value()?;
                            opt.level = Level::Task;
                            if let Some(path) = opt.path.as_ref() {
                                self.spath.union(path.clone().into());
                            }
                            // skip the task if env_override is required and not allowed
                            if self.cli.opt_filter.as_ref().is_some_and(|o| {
                                // we have a filter
                                o.env_behavior.as_ref().is_some_and(|_| {
                                    // the filter overrides env behavior
                                    opt.env.as_ref().is_some_and(|e| {
                                        // the task specifies env options
                                        e.override_behavior.is_some_and(|b| !b) // the task specifies override behavior and deny it
                                    })
                                })
                                // in any other case, we cannot know if this task is valid or not (as we don't know the inherited env override value)
                            }) {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                            options = Some(opt);
                        }
                        Field::Name => {
                            debug!("TaskFinderVisitor: name");
                            let task_name = map.next_value()?;
                            if self
                                .cli
                                .opt_filter
                                .as_ref()
                                .and_then(|x| x.task.as_ref())
                                .is_some_and(|t| IdTask::Name(t.into()) != task_name)
                            {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                            id = task_name;
                        }
                        Field::Cred => {
                            debug!("TaskFinderVisitor: cred");
                            let (su, sg, ca, sc, ok) = map
                                .next_value_seed(CredFinderDeserializerReturn { cli: self.cli })?;
                            setuid = su;
                            setgroups = sg;
                            caps = ca;
                            score.setuser_min = sc.setuser_min;
                            score.caps_min = sc.caps_min;
                            if !ok {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                        }
                        Field::Commands => {
                            debug!("TaskFinderVisitor: commands");
                            // if is_human_readable -> next_value
                            // else -> next_value_seed -> no memory allocation, just the result, thus highly optimizing
                            if self.human_readable {
                                commands = Some(map.next_value()?);
                            } else {
                                map.next_value_seed(DCommandListDeserializer {
                                    env_path: &self.spath.calc_path(self.env_path),
                                    cmd_path: &self.cli.cmd_path,
                                    cmd_args: &self.cli.cmd_args,
                                    final_path: &mut final_path,
                                    cmd_min: &mut score.cmd_min,
                                    blocker: false,
                                })?;
                            }
                        }
                        Field::Unknown(key) => {
                            debug!("TaskFinderVisitor: unknown");
                            let unknown: Value = map.next_value()?;
                            extra_values.insert(key, unknown);
                        }
                    }
                }
                debug!("TaskFinderVisitor: final_path {:?}", final_path);
                Ok(Some(DTaskFinder {
                    id,
                    score,
                    setuid,
                    setgroups,
                    caps,
                    commands,
                    options,
                    final_path,
                    _extra_values: extra_values,
                }))
            }
        }

        const FIELDS: &[&str] = &["name", "cred", "commands", "options"];
        let human_readable = deserializer.is_human_readable();
        deserializer.deserialize_struct(
            "STask",
            FIELDS,
            TaskFinderVisitor {
                i: self.i,
                cli: self.cli,
                env_path: self.env_path,
                spath: self.spath,
                human_readable,
            },
        )
    }
}

struct CredFinderDeserializerReturn<'a> {
    cli: &'a Cli,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for CredFinderDeserializerReturn<'a> {
    type Value = (
        Option<DUserType<'a>>,
        Option<DGroups<'a>>,
        Option<CapSet>,
        TaskScore,
        bool,
    );
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field<'a> {
            #[serde(alias = "u")]
            Setuid,
            #[serde(alias = "g", alias = "setgroups")]
            Setgid,
            #[serde(alias = "c", alias = "capabilities")]
            Caps,
            #[serde(untagged, borrow)]
            Other(Cow<'a, str>),
        }

        struct CredFinderVisitor<'a> {
            cli: &'a Cli,
        }

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

        impl<'de: 'a, 'a> serde::de::Visitor<'de> for CredFinderVisitor<'a> {
            type Value = (
                Option<DUserType<'a>>,
                Option<DGroups<'a>>,
                Option<CapSet>,
                TaskScore,
                bool,
            );

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Cred structure")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut setuid = None;
                let mut setgroups = None;
                let mut caps = None;
                let mut score = TaskScore::default();
                let mut ok = true;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Setuid => {
                            debug!("CredFinderVisitor: setuid");
                            let (user, setuser_min, user_ok) =
                                map.next_value_seed(SetUserDeserializerReturn { cli: self.cli })?;
                            setuid = user;
                            score.setuser_min.uid = setuser_min;
                            if !user_ok {
                                ok = false;
                            }
                        }
                        Field::Setgid => {
                            debug!("CredFinderVisitor: setgid");
                            let (groups, setuser_min, groups_ok) =
                                map.next_value_seed(SetGroupsDeserializerReturn { cli: self.cli })?;
                            setgroups = groups;
                            score.setuser_min.gid = setuser_min;
                            if !groups_ok {
                                ok = false;
                            }
                        }
                        Field::Caps => {
                            debug!("CredFinderVisitor: capabilities");
                            let scaps: SCapabilities = map.next_value()?;
                            let capset = scaps.to_capset();
                            score.caps_min = get_caps_min(&capset);
                            caps = Some(capset);
                        }
                        Field::Other(n) => {
                            return Err(serde::de::Error::custom(format!(
                                "Unknown Cred field {}",
                                n
                            )));
                        }
                    }
                }
                debug!("CredFinderVisitor: end");
                Ok((setuid, setgroups, caps, score, ok))
            }
        }
        const FIELDS: &[&str] = &["setuid", "setgroups", "capabilities", "0", "1", "2"];
        let (setuid, setgroups, caps, score, ok) =
            deserializer.deserialize_struct("Cred", FIELDS, CredFinderVisitor { cli: self.cli })?;
        Ok((setuid, setgroups, caps, score, ok))
    }
}

// New deserializer for SetGroups that returns values instead of using &mut
struct SetGroupsDeserializerReturn<'a> {
    cli: &'a Cli,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for SetGroupsDeserializerReturn<'a> {
    type Value = (Option<DGroups<'a>>, Option<SetgidMin>, bool);
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            #[serde(alias = "d")]
            Default,
            #[serde(alias = "f")]
            Fallback,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "s", alias = "sub")]
            Del,
        }
        struct SGroupsChooserVisitor<'a> {
            cli: &'a Cli,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for SGroupsChooserVisitor<'a> {
            type Value = (Option<DGroups<'a>>, Option<SetgidMin>, bool);

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("SGroups structure")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SGroupsChooserVisitor: visit_borrowed_str");
                let group: DGroupType<'_> = if let Ok(gid) = v.parse::<u32>() {
                    gid.into()
                } else {
                    v.into()
                };
                let score = Some(SetgidMin::from(&group));
                let ok = true;
                if let Some(y) = &self
                    .cli
                    .opt_filter
                    .as_ref()
                    .map(|x| x.group.as_ref())
                    .flatten()
                {
                    if y.len() == 1
                        && y[0]
                            != group
                                .fetch_id()
                                .ok_or(serde::de::Error::custom("Group does not exist"))?
                    {
                        return Ok((None, None, false));
                    }
                }
                Ok((Some(DGroups::Single(group)), score, ok))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SGroupsChooserVisitor: visit_str");
                self.visit_string(v.to_string())
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SGroupsChooserVisitor: visit_string");
                let group: DGroupType<'_> = if let Ok(gid) = v.parse::<u32>() {
                    gid.into()
                } else {
                    Cow::<str>::from(v).into()
                };
                let score = Some(SetgidMin::from(&group));
                let ok = true;
                if let Some(y) = &self
                    .cli
                    .opt_filter
                    .as_ref()
                    .map(|x| x.group.as_ref())
                    .flatten()
                {
                    if y.len() == 1
                        && y[0]
                            != group
                                .fetch_id()
                                .ok_or(serde::de::Error::custom("Group does not exist"))?
                    {
                        return Ok((None, None, false));
                    }
                }
                Ok((Some(DGroups::Single(group)), score, ok))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SGroupsChooserVisitor: visit_u64");
                if v > u32::MAX as u64 {
                    return Err(serde::de::Error::custom("Group id too large"));
                }
                let group: DGroupType<'_> = (v as u32).into();
                let score = Some(SetgidMin::from(&group));
                let ok = true;
                if let Some(y) = &self
                    .cli
                    .opt_filter
                    .as_ref()
                    .map(|x| x.group.as_ref())
                    .flatten()
                {
                    if y.len() == 1
                        && y[0]
                            != group
                                .fetch_id()
                                .ok_or(serde::de::Error::custom("Group does not exist"))?
                    {
                        return Ok((None, None, false));
                    }
                }
                Ok((Some(DGroups::Single(group)), score, ok))
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                debug!("SGroupsChooserVisitor: visit_seq");
                let mut groups = None;
                let mut score = None;
                let mut ok = false;
                let filter = self.cli.opt_filter.as_ref().and_then(|x| x.group.as_ref());
                while let Some(group) = seq.next_element::<DGroups>()? {
                    if let Some(u) = filter {
                        let parsed_ids: Vec<u32> =
                            (&group).try_into().map_err(serde::de::Error::custom)?;
                        if *u == parsed_ids {
                            ok = true;
                            groups = Some(group.to_owned());
                            score.replace((&group).into());
                            while seq.next_element::<IgnoredAny>()?.is_some() {}
                            break;
                        }
                    } else {
                        groups = Some(group.to_owned());
                        ok = true;
                        score.replace((&group).into());
                    }
                }
                Ok((groups, score, ok))
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut groups = None;
                let mut score = None;
                let mut ok = false;
                let filter = self.cli.opt_filter.as_ref().and_then(|x| x.group.as_ref());
                'fields: while let Some(key) = map.next_key()? {
                    match key {
                        Field::Default => {
                            debug!("SGroupsChooserVisitor: default");
                            let default = map.next_value::<SetBehavior>()?;
                            if default.is_all() {
                                ok = true;
                            }
                        }
                        Field::Fallback => {
                            debug!("SGroupsChooserVisitor: fallback");
                            let value = map.next_value::<DGroups>()?;
                            if let Some(u) = filter {
                                let parsed_ids: Vec<u32> =
                                    (&value).try_into().map_err(serde::de::Error::custom)?;
                                if *u == parsed_ids {
                                    ok = true;
                                    groups = Some(value.to_owned());
                                    score.replace((&value).into());
                                }
                            } else {
                                groups = Some(value.to_owned());
                                ok = true;
                                score.replace((&value).into());
                            }
                        }
                        Field::Add => {
                            debug!("SGroupsChooserVisitor: add");
                            if filter.is_some() {
                                let add = map.next_value::<Cow<'_, [DGroups]>>()?;
                                for group in add.iter() {
                                    let v: Vec<u32> =
                                        group.try_into().map_err(serde::de::Error::custom)?;
                                    if v == *filter.unwrap() {
                                        ok = true;
                                        groups = Some(group.to_owned());
                                        score.replace(group.into());
                                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some()
                                        {
                                        }
                                        break;
                                    }
                                }
                            } else {
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                        Field::Del => {
                            debug!("SGroupsChooserVisitor: del");
                            if let Some(u) = filter {
                                for group in map.next_value::<Cow<'_, [DGroups]>>()?.iter() {
                                    if let Some(v) = TryInto::<Vec<u32>>::try_into(group).ok() {
                                        if v == *u {
                                            while map
                                                .next_entry::<IgnoredAny, IgnoredAny>()?
                                                .is_some()
                                            {
                                            }
                                            ok = false;
                                            groups = None;
                                            score = None;
                                            break 'fields;
                                        }
                                    } else {
                                        return Err(serde::de::Error::custom("Invalid group"));
                                    }
                                }
                            } else {
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                    }
                }
                Ok((groups, score, ok))
            }
        }
        deserializer.deserialize_any(SGroupsChooserVisitor { cli: self.cli })
    }
}

// New deserializer for SetUser that returns values instead of using &mut
struct SetUserDeserializerReturn<'a> {
    cli: &'a Cli,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for SetUserDeserializerReturn<'a> {
    type Value = (Option<DUserType<'a>>, Option<SetuidMin>, bool);
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            #[serde(alias = "d")]
            Default,
            #[serde(alias = "f")]
            Fallback,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "s", alias = "sub")]
            Del,
        }
        struct SetUserVisitor<'a> {
            cli: &'a Cli,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for SetUserVisitor<'a> {
            type Value = (Option<DUserType<'a>>, Option<SetuidMin>, bool);
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("SUser structure")
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SetUserVisitor: visit_borrowed_str");
                let user = if let Ok(uid) = v.parse::<u32>() {
                    DUserType::from(uid)
                } else {
                    DUserType::from(v)
                };
                let score = Some(SetuidMin::from(&user));
                let ok = true;
                if let Some(y) = &self.cli.opt_filter.as_ref().map(|x| x.user).flatten() {
                    if *y
                        != user
                            .fetch_id()
                            .ok_or(serde::de::Error::custom("User does not exist"))?
                    {
                        return Ok((None, None, false));
                    }
                }
                Ok((Some(user), score, ok))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SetUserVisitor: visit_str");
                self.visit_string(v.to_string())
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SetUserVisitor: visit_string");
                let user = if let Ok(uid) = v.parse::<u32>() {
                    DUserType::from(uid)
                } else {
                    DUserType::from(v)
                };
                let score = Some(SetuidMin::from(&user));
                let ok = true;
                if let Some(y) = &self.cli.opt_filter.as_ref().map(|x| x.user).flatten() {
                    if *y
                        != user
                            .fetch_id()
                            .ok_or(serde::de::Error::custom("User does not exist"))?
                    {
                        return Ok((None, None, false));
                    }
                }
                Ok((Some(user), score, ok))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                debug!("SetUserVisitor: visit_i64");
                if v > u32::MAX as u64 {
                    return Err(serde::de::Error::custom("User id too large"));
                }
                let user = DUserType::from(v as u32);
                let score = Some(SetuidMin::from(&user));
                let ok = true;
                if let Some(y) = &self.cli.opt_filter.as_ref().map(|x| x.user).flatten() {
                    if *y
                        != user
                            .fetch_id()
                            .ok_or(serde::de::Error::custom("User does not exist"))?
                    {
                        return Ok((None, None, false));
                    }
                }
                Ok((Some(user), score, ok))
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut user = None;
                let mut score = None;
                let mut ok = false;
                let filter = self.cli.opt_filter.as_ref().and_then(|x| x.user.as_ref());
                'fields: while let Some(key) = map.next_key()? {
                    match key {
                        Field::Default => {
                            debug!("SUserChooserVisitor: default");
                            let default = map.next_value::<SetBehavior>()?;
                            if default.is_all() {
                                ok = true;
                            }
                        }
                        Field::Fallback => {
                            debug!("SUserChooserVisitor: fallback");
                            let value = map.next_value::<DUserType>()?;
                            if let Some(u) = filter {
                                let userid = value
                                    .fetch_id()
                                    .ok_or(serde::de::Error::custom("User does not exist"))?;
                                if u == &userid {
                                    score.replace((&value).into());
                                    user = Some(value.into());
                                    ok = true;
                                }
                            } else {
                                ok = true;
                                score.replace((&value).into());
                                user = Some(value);
                            }
                        }
                        Field::Add => {
                            debug!("SUserChooserVisitor: add");
                            if filter.is_some() {
                                let users = map.next_value::<Cow<'_, [DUserType]>>()?;
                                for user_item in users.iter() {
                                    let user_id = user_item
                                        .fetch_id()
                                        .ok_or(serde::de::Error::custom("User does not exist"))?;
                                    if user_id == *filter.unwrap() {
                                        ok = true;
                                        user = Some(user_item.to_owned());
                                        score.replace(user_item.into());
                                        break;
                                    }
                                }
                            } else {
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                        Field::Del => {
                            debug!("SUserChooserVisitor: del");
                            if let Some(u) = filter {
                                let users = map.next_value::<Cow<'_, [DUserType]>>()?;
                                for user_item in users.iter() {
                                    let user_id = user_item
                                        .fetch_id()
                                        .ok_or(serde::de::Error::custom("User does not exist"))?;
                                    if user_id == *u {
                                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some()
                                        {
                                        }
                                        score = None;
                                        user = None;
                                        ok = false;
                                        break 'fields;
                                    }
                                }
                            } else {
                                map.next_value::<IgnoredAny>()?;
                            }
                        }
                    }
                }
                Ok((user, score, ok))
            }
        }
        deserializer.deserialize_any(SetUserVisitor { cli: self.cli })
    }
}

/// This struct keeps the list of commands because options may be written after
#[cfg_attr(test, derive(Builder))]
#[derive(PartialEq, Eq, Debug)]
pub struct DCommandList<'a> {
    #[cfg_attr(test, builder(start_fn, into))]
    pub default_behavior: Option<SetBehavior>,
    #[cfg_attr(test, builder(default, into))]
    pub add: Cow<'a, [DCommand<'a>]>,
    #[cfg_attr(test, builder(default, into))]
    pub del: Cow<'a, [DCommand<'a>]>,
}

impl<'de: 'a, 'a> Deserialize<'de> for DCommandList<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            Default,
            Add,
            Del,
        }
        #[derive(Default)]
        struct DCommandListVisitor<'a> {
            _phantom: std::marker::PhantomData<&'a ()>,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for DCommandListVisitor<'a> {
            type Value = DCommandList<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("CommandList structure")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut default_behavior = None;
                let mut add: Cow<'_, [DCommand<'_>]> = Cow::Borrowed(&[]);
                let mut del: Cow<'_, [DCommand<'_>]> = Cow::Borrowed(&[]);
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Default => {
                            debug!("DCommandListVisitor: default");
                            default_behavior = Some(map.next_value()?);
                        }
                        Field::Add => {
                            debug!("DCommandListVisitor: add");
                            add = map.next_value()?;
                        }
                        Field::Del => {
                            debug!("DCommandListVisitor: del");
                            del = map.next_value()?;
                        }
                    }
                }
                Ok(DCommandList {
                    default_behavior,
                    add,
                    del,
                })
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut add = Vec::new();
                while let Some(command) = seq.next_element()? {
                    add.push(command);
                }
                return Ok(DCommandList {
                    default_behavior: None,
                    add: Cow::Owned(add),
                    del: Cow::Borrowed(&[]),
                });
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let set = SetBehavior::from_str(v).map_err(serde::de::Error::custom)?;
                Ok(DCommandList {
                    default_behavior: Some(set),
                    add: Cow::Borrowed(&[]),
                    del: Cow::Borrowed(&[]),
                })
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }
        }
        deserializer.deserialize_any(DCommandListVisitor::default())
    }
}

/// This struct evaluates commands directly from deserialization
pub struct DCommandListDeserializer<'a> {
    env_path: &'a [&'a str],
    cmd_path: &'a PathBuf,
    cmd_args: &'a [String],
    pub final_path: &'a mut Option<PathBuf>,
    pub cmd_min: &'a mut CmdMin,
    pub blocker: bool,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for DCommandListDeserializer<'a> {
    type Value = bool;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'a> DCommandListDeserializer<'a> {
    fn generate_dcommand_deserializer(&mut self) -> DCommandDeserializer<'_> {
        DCommandDeserializer {
            env_path: self.env_path,
            cmd_path: self.cmd_path,
            cmd_args: self.cmd_args,
            final_path: self.final_path,
            cmd_min: self.cmd_min,
        }
    }
}

impl<'de: 'a, 'a> serde::de::Visitor<'de> for DCommandListDeserializer<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("CommandList Deserializer structure")
    }

    fn visit_seq<A>(mut self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut result = false;
        while let Some(bool) = seq.next_element_seed(self.generate_dcommand_deserializer())? {
            if bool && self.blocker {
                return Ok(true);
            }
            result |= bool;
        }
        Ok(result)
    }

    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::MapAccess<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            #[serde(alias = "d")]
            Default,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "s", alias = "sub")]
            Del,
        }
        let mut result = false;
        let mut default = SetBehavior::None;
        while let Some(key) = map.next_key()? {
            match key {
                Field::Default => {
                    debug!("DCommandListVisitor: default");
                    default = map.next_value()?;
                }
                Field::Del => {
                    let deserializer = DCommandListDeserializer {
                        env_path: self.env_path,
                        cmd_path: self.cmd_path,
                        cmd_args: self.cmd_args,
                        final_path: self.final_path,
                        cmd_min: self.cmd_min,
                        blocker: true,
                    };
                    let res = map.next_value_seed(deserializer)?;
                    if res {
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        return Ok(false);
                    }
                }
                Field::Add => {
                    if default.is_all() {
                        let _ = map.next_value::<IgnoredAny>();
                    } else {
                        let deserializer = DCommandListDeserializer {
                            env_path: self.env_path,
                            cmd_path: self.cmd_path,
                            cmd_args: self.cmd_args,
                            final_path: self.final_path,
                            cmd_min: self.cmd_min,
                            blocker: false,
                        };
                        result |= map.next_value_seed(deserializer)?;
                    }
                }
            }
        }
        Ok(result)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v)
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let set = SetBehavior::from_str(v).map_err(serde::de::Error::custom)?;
        Ok(set.is_all())
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
}

pub(super) struct DCommandDeserializer<'a> {
    pub(super) env_path: &'a [&'a str],
    pub(super) cmd_path: &'a PathBuf,
    pub(super) cmd_args: &'a [String],
    pub(super) final_path: &'a mut Option<PathBuf>,
    pub(super) cmd_min: &'a mut CmdMin,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for DCommandDeserializer<'a> {
    type Value = bool;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DCommandVisitor<'a> {
            env_path: &'a [&'a str],
            cmd_path: &'a PathBuf,
            cmd_args: &'a [String],
            final_path: &'a mut Option<PathBuf>,
            cmd_min: &'a mut CmdMin,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for DCommandVisitor<'a> {
            type Value = bool;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Command structure")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut final_path = None;
                let mut result = false;
                debug!("DCommandVisitor: command {}", v);
                let cmd_min = cmd::evaluate_command_match(
                    self.env_path,
                    self.cmd_path,
                    self.cmd_args,
                    v,
                    self.cmd_min,
                    &mut final_path,
                );
                debug!("DCommandVisitor: command result {:?}", cmd_min);
                if cmd_min.better(&self.cmd_min) {
                    debug!("DCommandVisitor: better command found");
                    result = true;
                    *self.final_path = final_path;
                    *self.cmd_min = cmd_min;
                }
                Ok(result)
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut map_value = Vec::new();
                while let Some((key, value)) = map.next_entry::<&str, Value>()? {
                    map_value.push((key, value));
                }
                Api::notify(ApiEvent::ProcessComplexCommand(
                    &Value::Object(
                        map_value
                            .into_iter()
                            .map(|(k, v)| (k.to_string(), v))
                            .collect(),
                    ),
                    self.env_path,
                    self.cmd_path,
                    self.cmd_args,
                    self.cmd_min,
                    self.final_path,
                ))
                .map(|_| true)
                .map_err(|_| serde::de::Error::custom("Failed to notify process complex command"))
            }
        }
        deserializer.deserialize_any(DCommandVisitor {
            env_path: self.env_path,
            cmd_path: self.cmd_path,
            cmd_args: self.cmd_args,
            final_path: self.final_path,
            cmd_min: self.cmd_min,
        })
    }
}

impl<'a> DConfigFinder<'a> {
    pub fn roles<'s>(&'s self) -> impl Iterator<Item = DLinkedRole<'s, 'a>> {
        self.roles.iter().map(|role| DLinkedRole::new(self, role))
    }

    pub fn role<'s>(&'s self, role_name: &str) -> Option<DLinkedRole<'s, 'a>> {
        self.roles
            .iter()
            .find(|r| r.role == role_name)
            .map(|role| DLinkedRole::new(self, role))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DLinkedRole<'c, 'a> {
    parent: &'c DConfigFinder<'a>,
    role: &'c DRoleFinder<'a>,
}

impl<'c, 'a> DLinkedRole<'c, 'a> {
    fn new(parent: &'c DConfigFinder<'a>, role: &'c DRoleFinder<'a>) -> Self {
        Self { parent, role }
    }

    pub fn tasks<'t>(&'t self) -> impl Iterator<Item = DLinkedTask<'t, 'c, 'a>> {
        self.role
            .tasks
            .iter()
            .map(|task| DLinkedTask::new(self, task))
    }

    pub fn role(&self) -> &DRoleFinder<'a> {
        self.role
    }

    pub fn config(&self) -> &DConfigFinder<'a> {
        self.parent
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DLinkedTask<'t, 'c, 'a> {
    parent: &'t DLinkedRole<'c, 'a>,
    pub task: &'t DTaskFinder<'a>,
}

impl<'t, 'c, 'a> DLinkedTask<'t, 'c, 'a> {
    fn new(parent: &'t DLinkedRole<'c, 'a>, task: &'t DTaskFinder<'a>) -> Self {
        Self { parent, task }
    }

    pub fn commands<'l>(&'l self) -> Option<DLinkedCommandList<'l, 't, 'c, 'a>> {
        self.task
            .commands
            .as_ref()
            .map(|list| DLinkedCommandList::new(self, list))
    }

    pub fn role(&self) -> &DLinkedRole<'c, 'a> {
        self.parent
    }

    pub fn task(&self) -> &DTaskFinder<'a> {
        self.task
    }

    pub fn score(&self, cmd_min: CmdMin, security_min: SecurityMin) -> Score {
        Score::builder()
            .user_min(self.role().role.user_min)
            .caps_min(self.score.caps_min)
            .cmd_min(cmd_min)
            .security_min(security_min)
            .setuser_min(self.score.setuser_min)
            .build()
    }
}

impl<'t, 'c, 'a> Deref for DLinkedTask<'t, 'c, 'a> {
    type Target = DTaskFinder<'a>;
    fn deref(&self) -> &Self::Target {
        self.task
    }
}

pub struct DLinkedCommandList<'l, 't, 'c, 'a> {
    #[allow(dead_code)] // TODO: remove this
    parent: &'l DLinkedTask<'t, 'c, 'a>,
    command_list: &'l DCommandList<'a>,
}

impl<'l, 't, 'c, 'a> DLinkedCommandList<'l, 't, 'c, 'a> {
    fn new(parent: &'l DLinkedTask<'t, 'c, 'a>, list: &'l DCommandList<'a>) -> Self {
        Self {
            parent,
            command_list: list,
        }
    }

    pub fn add<'d>(&'d self) -> impl Iterator<Item = DLinkedCommand<'d, 'l, 't, 'c, 'a>> {
        self.command_list
            .add
            .iter()
            .map(|cmd| DLinkedCommand::new(self, cmd))
    }

    pub fn del<'d>(&'d self) -> impl Iterator<Item = DLinkedCommand<'d, 'l, 't, 'c, 'a>> {
        self.command_list
            .del
            .iter()
            .map(|cmd| DLinkedCommand::new(self, cmd))
    }
}

impl<'l, 't, 'c, 'a> Deref for DLinkedCommandList<'l, 't, 'c, 'a> {
    type Target = DCommandList<'a>;
    fn deref(&self) -> &Self::Target {
        self.command_list
    }
}

pub struct DLinkedCommand<'d, 'l, 't, 'c, 'a> {
    #[allow(dead_code)] // TODO: remove this
    parent: &'d DLinkedCommandList<'l, 't, 'c, 'a>,
    pub command: &'d DCommand<'a>,
}

impl<'d, 'l, 't, 'c, 'a> DLinkedCommand<'d, 'l, 't, 'c, 'a> {
    fn new(parent: &'d DLinkedCommandList<'l, 't, 'c, 'a>, command: &'d DCommand<'a>) -> Self {
        Self { parent, command }
    }

    #[allow(dead_code)] // TODO: remove this
    pub fn task(&self) -> &DLinkedTask<'t, 'c, 'a> {
        self.parent.parent
    }
}

impl<'d, 'l, 't, 'c, 'a> Deref for DLinkedCommand<'d, 'l, 't, 'c, 'a> {
    type Target = DCommand<'a>;
    fn deref(&self) -> &Self::Target {
        self.command
    }
}

#[cfg(test)]
mod tests {

    use std::fs;

    use super::*;
    use capctl::Cap;
    use cbor4ii::core::utils::SliceReader;
    use nix::unistd::{getgid, getuid};
    use rar_common::database::{
        actor::{DGroupType, SGroupType, SGroups},
        score::{SetUserMin, SetgidMin, SetuidMin},
        FilterMatcher,
    };
    use test_log::test;

    fn get_non_root_uid(nth: usize) -> Option<u32> {
        // list all users
        let passwd = fs::read_to_string("/etc/passwd").unwrap();
        let passwd: Vec<&str> = passwd.split('\n').collect();
        return passwd
            .iter()
            .map(|line| {
                let line: Vec<&str> = line.split(':').collect();
                line[2].parse::<u32>().unwrap()
            })
            .filter(|uid| *uid != 0)
            .nth(nth);
    }

    fn get_non_root_gid(nth: usize) -> Option<u32> {
        // list all users
        let passwd = fs::read_to_string("/etc/group").unwrap();
        let passwd: Vec<&str> = passwd.split('\n').collect();
        return passwd
            .iter()
            .map(|line| {
                let line: Vec<&str> = line.split(':').collect();
                line[2].parse::<u32>().unwrap()
            })
            .filter(|uid| *uid != 0)
            .nth(nth);
    }

    fn convert_json_to_cbor(json: &str) -> Vec<u8> {
        let value: Value = serde_json::from_str(json).unwrap();
        let cbor = cbor4ii::serde::to_vec(Vec::new(), &value).unwrap();
        cbor
    }

    #[test]
    fn test_idtask_display() {
        let name = IdTask::Name(Cow::Borrowed("test"));
        let number = IdTask::Number(42);
        assert_eq!(format!("{}", name), "test");
        assert_eq!(format!("{}", number), "42");
    }

    #[test]
    fn test_dcommandlist_deserialize_seq() {
        let json = r#"["ls", "cat"]"#;
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.add.len(), 2);
        assert!(matches!(list.add[0], DCommand::Simple(_)));
    }

    #[test]
    fn test_dcommandlist_deserialize_map() {
        let json = r#"{"default": "all", "add": ["ls"], "del": ["rm"]}"#;
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.default_behavior.unwrap(), SetBehavior::All);
        assert_eq!(list.add.len(), 1);
        assert_eq!(list.del.len(), 1);
    }

    #[test]
    fn test_dcommandlist_deserialize_all_or_none() {
        let json = "\"all\"";
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.default_behavior, Some(SetBehavior::All));
        assert_eq!(list.add.len(), 0);
        assert_eq!(list.del.len(), 0);
        let json = "\"none\"";
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.default_behavior, Some(SetBehavior::None));
        assert_eq!(list.add.len(), 0);
        assert_eq!(list.del.len(), 0);
    }

    #[test]
    fn test_dcommandlist_deserialize_empty() {
        let json = "{}";
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.default_behavior, None);
        assert_eq!(list.add.len(), 0);
        assert_eq!(list.del.len(), 0);
    }

    #[test]
    fn test_dcommandlist_deserialize_invalid() {
        let json = r#"{"default": "invalid", "add": ["ls"], "del": ["rm"]}"#;
        let result: Result<DCommandList, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_dcommandlist_seed() {
        let json = r#"{"default": "none", "add": ["/usr/bin/ls"], "del": ["/usr/bin/rm"]}"#;
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandListDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from("/usr/bin/ls"),
            cmd_args: &vec![],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
            blocker: false,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(final_path, Some(PathBuf::from("/usr/bin/ls")));
        assert!(result);
    }

    #[test]
    fn test_dcommand_seed() {
        let json = r#""/usr/bin/ls""#;
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from("/usr/bin/ls"),
            cmd_args: &vec![],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(final_path, Some(PathBuf::from("/usr/bin/ls")));
        assert!(result);
    }

    #[test]
    fn test_setuserdeserializerreturn() {
        let json =
            r#"{"default": "none", "fallback": "user1", "add": ["user2"], "del": ["user3"]}"#;
        let cli = Cli::builder().build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from("user1");
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
    }

    #[test]
    fn test_setuserdeserializerreturn_filter() {
        let uid1 = get_non_root_uid(0).unwrap();
        let uid2 = get_non_root_uid(1).unwrap();
        let json = format!(
            r#"{{"default": "none", "fallback": "root", "add": [{}], "del": [{}]}}"#,
            uid1, uid2
        );
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user(uid1).unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from(uid1);
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user("root").unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from("root");
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user(uid2).unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(user, None);
        let json = "\"root\"";
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user("root").unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from("root");
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user(uid1).unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(user, None);
        let json = "0";
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user(uid1).unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(user, None);
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().user("root").unwrap().build())
            .build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        let user1 = DUserType::from(0);
        assert_eq!(score, Some(SetuidMin::from(&user1)));
        assert_eq!(user, Some(user1));
    }

    #[test]
    fn test_no_fallback() {
        let json = r#"{"default": "all"}"#;
        let cli = Cli::builder().build();
        let deserializer = SetUserDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (user, score, ok) = result.unwrap();
        assert!(ok);
        assert_eq!(score, None);
        assert_eq!(user, None);
    }

    #[test]
    fn test_setgroupsdeserializerreturn() {
        let json = r#"{"default": "none", "fallback": [1, 2], "add": [[3, 4]], "del": [[5, 6]]}"#;
        let cli = Cli::builder().build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::from(vec![1.into(), 2.into()]);
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
    }

    #[test]
    fn test_setgroupsdeserializerreturn_filter() {
        let gid1 = get_non_root_gid(0).unwrap();
        let gid2 = get_non_root_gid(1).unwrap();
        let json = format!(
            r#"{{"default": "none", "fallback": ["root"], "add": [[{}]], "del": [[{}]]}}"#,
            gid1, gid2
        );
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group("root").unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::Single("root".into());
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid1).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::Single(gid1.into());
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid2).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
        let json = "\"root\"";
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group("root").unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::Single("root".into());
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid1).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
        let json = "0";
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid1).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group("root").unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::Single(0.into());
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let json = "[[\"root\", 1]]";
        let cli = Cli::builder()
            .opt_filter(
                FilterMatcher::builder()
                    .group(vec!["root".into(), Into::<SGroupType>::into(1)])
                    .unwrap()
                    .build(),
            )
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::from(vec!["root".into(), 1.into()]);
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        let groups1 = DGroups::from(vec!["root".into(), 1.into()]);
        assert_eq!(score, Some((&groups1).into()));
        assert_eq!(groups, Some(groups1));
        let cli = Cli::builder()
            .opt_filter(FilterMatcher::builder().group(gid1).unwrap().build())
            .build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(!ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
    }

    #[test]
    fn test_no_fallback_groups() {
        let json = r#"{"default": "all"}"#;
        let cli = Cli::builder().build();
        let deserializer = SetGroupsDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let (groups, score, ok) = result.unwrap();
        assert!(ok);
        assert_eq!(score, None);
        assert_eq!(groups, None);
    }

    #[test]
    fn test_cred_deserializer() {
        let json = r#"{"setuid":"root", "setgid":"root", "caps": ["CAP_SYS_ADMIN"]}"#;
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let (user, groups, caps, score, ok) = result.unwrap();
        assert!(ok);
        assert_eq!(user, Some("root".into()));
        assert_eq!(groups, Some(DGroups::from(vec!["root".into()])));
        assert_eq!(caps, Some(CapSet::from_iter(vec![Cap::SYS_ADMIN])));
        assert_eq!(score.setuser_min.uid, Some(SetuidMin::from(&"root".into())));
        assert_eq!(
            score.setuser_min.gid,
            Some(SetgidMin::from(&Into::<DGroupType<'_>>::into("root")))
        );
        assert_eq!(score.caps_min, CapsMin::CapsAdmin(1));

        let uid = get_non_root_uid(0).unwrap();
        let gid = get_non_root_gid(0).unwrap();
        let json = format!(r#"{{"setuid":{}, "setgid":[[{}]]}}"#, uid, gid);
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let (user, groups, caps, score, ok) = result.unwrap();
        assert!(ok);
        assert_eq!(user, Some(uid.into()));
        assert_eq!(groups, Some(DGroups::from(vec![gid.into()])));
        assert_eq!(caps, None);
        assert_eq!(score.setuser_min.uid, Some(SetuidMin::from(&uid.into())));
        assert_eq!(
            score.setuser_min.gid,
            Some(SetgidMin::from(&Into::<DGroupType<'_>>::into(uid)))
        );
        assert_eq!(score.caps_min, CapsMin::Undefined);

        let uid = get_non_root_uid(0).unwrap();
        let gid = get_non_root_gid(0).unwrap();
        let json = format!(r#"{{"setuid":"{}", "setgid":["{}"]}}"#, uid, gid);
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let (user, groups, caps, score, ok) = result.unwrap();
        assert!(ok);
        assert_eq!(user, Some(uid.into()));
        assert_eq!(groups, Some(DGroups::from(vec![gid.into()])));
        assert_eq!(caps, None);
        assert_eq!(score.setuser_min.uid, Some(SetuidMin::from(&uid.into())));
        assert_eq!(
            score.setuser_min.gid,
            Some(SetgidMin::from(&Into::<DGroupType<'_>>::into(uid)))
        );
        assert_eq!(score.caps_min, CapsMin::Undefined);
    }

    #[test]
    fn test_cred_deserializer_invalid() {
        let json = r#"{"setuid":-1, "setgid":"invalid", "caps": ["CAP_SYS_ADMIN"]}"#;
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let json = r#"{"setuid":"invalid", "setgid":-1, "caps": ["CAP_SYS_ADMIN"]}"#;
        let cli = Cli::builder().build();
        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
    }

    #[test]
    fn test_task_deserializer() {
        let json = r#"{"name": "test", "cred": {"setuid":"0", "setgid":["0", 0], "caps": []}, "commands": ["ls"]}}"#;
        let cli = Cli::builder().build();
        let deserializer = TaskFinderDeserializer {
            cli: &cli,
            i: 0,
            env_path: &[],
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let task = result.unwrap().unwrap();
        assert_eq!(task.id, IdTask::Name("test".into()));
        assert_eq!(task.score.setuser_min.uid, Some(SetuidMin::from(&0.into())));
        assert_eq!(task.score.setuser_min.gid, Some(SetgidMin::from(&vec![0])));
        assert_eq!(task.score.caps_min, CapsMin::NoCaps);
        let commands = task.commands.unwrap();
        assert_eq!(commands.add.len(), 1);
        assert_eq!(commands.add[0], DCommand::Simple("ls".into()));
    }

    #[test]
    fn test_task_list_deserializer() {
        let json = r#"[{"name": "test", "cred": {"setuid":"0", "setgid":["0", 0], "caps": []}, "commands": ["ls"]}]"#;
        let cli = Cli::builder().build();
        let deserializer = TaskListFinderDeserializer {
            cli: &cli,
            env_path: &[],
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let task = &result.unwrap()[0];
        assert_eq!(task.id, IdTask::Name("test".into()));
        assert_eq!(task.score.setuser_min.uid, Some(SetuidMin::from(&0.into())));
        assert_eq!(task.score.setuser_min.gid, Some(SetgidMin::from(&vec![0])));
        assert_eq!(task.score.caps_min, CapsMin::NoCaps);
        let commands = task.commands.as_ref().unwrap();
        assert_eq!(commands.add.len(), 1);
        assert_eq!(commands.add[0], DCommand::Simple("ls".into()));
    }

    #[test]
    fn test_actors_finder_deserializer() {
        let json = format!(r#"[{{"type": "user", "id": {}}}]"#, getuid().as_raw());
        let deserializer = ActorsFinderDeserializer {
            cred: &Cred::builder().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let user_min = result.unwrap();
        assert_eq!(user_min, ActorMatchMin::UserMatch);
    }

    #[test]
    fn test_role_finder_deserializer() {
        let json = format!(
            r#"{{"name":"r_test","actors":[{{"type": "user", "id": {}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0", 0], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}"#,
            getuid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = RoleFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let role = result.unwrap().unwrap();
        assert_eq!(role.role, "r_test");
        assert_eq!(role.tasks.len(), 1);
        assert_eq!(role.tasks[0].id, IdTask::Name("test".into()));
    }

    #[test]
    fn test_role_list_finder_deserializer() {
        let json = format!(
            r#"[{{"name":"r_test","actors":[{{"type": "user", "id": {}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0", 0], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}]"#,
            getuid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = RoleListFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let role = &result.unwrap()[0];
        assert_eq!(role.role, "r_test");
        assert_eq!(role.tasks.len(), 1);
        assert_eq!(role.tasks[0].id, IdTask::Name("test".into()));
        let json = format!(
            r#"[{{"name":"r_test","actors":[{{"type": "group", "id": {}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0", 0], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}]"#,
            getgid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = RoleListFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let role = &result.unwrap()[0];
        assert_eq!(role.role, "r_test");
        assert_eq!(role.tasks.len(), 1);
        assert_eq!(role.tasks[0].id, IdTask::Name("test".into()));
        let json = format!(
            r#"[{{"name":"r_test","actors":[{{"type": "user", "id": "874510"}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0", 0], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}]"#
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = RoleListFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].user_min, ActorMatchMin::NoMatch);
    }

    #[test]
    fn test_config_finder_deserializer() {
        let json = format!(
            r#"{{"roles":[{{"name":"r_test","actors":[{{"type": "user", "id": {}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0", 0], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}]}}"#,
            getuid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let config = result.unwrap();
        assert_eq!(config.roles.len(), 1);
        assert_eq!(config.roles[0].role, "r_test");
    }

    #[test]
    fn test_config_finder_implementation() {
        let json = format!(
            r#"{{"roles":[{{"name":"r_test","actors":[{{"type":"user","id":{}}}],"tasks":[{{"name":"test","cred":{{"setuid":"0","setgid":["0",0],"caps":[]}},"commands":["/usr/bin/ls"]}},{{"name":"test2","cred":{{"setuid":"0","setgid":["0",0],"caps":[]}},"commands":["/usr/bin/ls","/usr/bin/cat"]}}]}},{{"name":"r_test2","actors":[{{"type":"group","names":[{}, {}]}}],"tasks":[{{"name":"test3","cred":{{"setuid":"0","setgid":["0",0],"caps":[]}},"commands":["/usr/bin/cat","/usr/bin/ls"]}}]}}]}}"#,
            getuid().as_raw(),
            getgid().as_raw(),
            getgid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let config = result.unwrap();
        let mut roles = config.roles();
        let role_a = roles.next().unwrap();
        assert_eq!(role_a.role().role, "r_test");
        let mut tasks = role_a.tasks();
        let task_a = tasks.next().unwrap();
        assert_eq!(task_a.task().id, IdTask::Name("test".into()));
        let commands = task_a.commands().unwrap();
        assert_eq!(commands.add().count(), 1);
        assert_eq!(
            *commands.add().next().unwrap().command,
            DCommand::Simple("/usr/bin/ls".into())
        );
        let task_b = tasks.next().unwrap();
        assert_eq!(task_b.task().id, IdTask::Name("test2".into()));
        let commands = task_b.commands().unwrap();
        assert_eq!(commands.add().count(), 2);
        assert_eq!(
            *commands.add().next().unwrap().command,
            DCommand::Simple("/usr/bin/ls".into())
        );
        assert_eq!(
            *commands.add().nth(1).unwrap().command,
            DCommand::Simple("/usr/bin/cat".into())
        );
        assert!(tasks.next().is_none());
        let role_b = roles.next().unwrap();
        assert_eq!(role_b.role().role, "r_test2");
        let mut tasks = role_b.tasks();
        let task_a = tasks.next().unwrap();
        assert_eq!(task_a.task().id, IdTask::Name("test3".into()));
        let commands = task_a.commands().unwrap();
        assert_eq!(commands.add().count(), 2);
        assert_eq!(
            *commands.add().next().unwrap().command,
            DCommand::Simple("/usr/bin/cat".into())
        );
        assert_eq!(
            *commands.add().nth(1).unwrap().command,
            DCommand::Simple("/usr/bin/ls".into())
        );
        assert_eq!(commands.del().count(), 0);
        assert!(tasks.next().is_none());
        assert!(roles.next().is_none());
        assert!(config.options.is_none());
        assert!(config.roles[0].options.is_none());
        assert!(config.roles[0].tasks[0].options.is_none());
        assert!(config.roles[0].tasks[1].options.is_none());
        assert!(config.roles[1].options.is_none());
        assert!(config.roles[1].tasks[0].options.is_none());
        assert!(config.role("r_test").is_some());
        assert!(config.role("r_test2").is_some());
        assert!(config.role("r_test3").is_none());
        assert_eq!(*config.role("r_test").unwrap().config(), config);
        assert_eq!(*config.role("r_test2").unwrap().config(), config);
        assert_eq!(
            *config
                .role("r_test")
                .unwrap()
                .tasks()
                .next()
                .unwrap()
                .role(),
            config.role("r_test").unwrap()
        );
        assert_eq!(
            *config
                .role("r_test2")
                .unwrap()
                .tasks()
                .next()
                .unwrap()
                .role(),
            config.role("r_test2").unwrap()
        );
        assert_eq!(
            config
                .role("r_test")
                .unwrap()
                .tasks()
                .next()
                .unwrap()
                .score(CmdMin::MATCH, SecurityMin::empty()),
            Score::builder()
                .user_min(ActorMatchMin::UserMatch)
                .setuser_min(SetUserMin {
                    uid: Some(SetuidMin::from(0)),
                    gid: Some(SetgidMin::from(SGroups::from(vec![0])))
                })
                .caps_min(CapsMin::NoCaps)
                .security_min(SecurityMin::empty())
                .cmd_min(CmdMin::MATCH)
                .build()
        );
    }

    #[test]
    fn test_config_with_options() {
        let json = format!(
            r#"{{
    "options": {{
        "timeout": {{
            "type": "ppid",
            "duration": "00:05:00"
        }},
        "path": {{
            "default": "delete",
            "add": [
                "/usr/bin"
            ]
        }},
        "env": {{
            "default": "delete",
            "override_behavior": false,
            "keep": [
                "keep1"
            ],
            "check": [
                "check1"
            ],
            "delete": [
                "del1"
            ],
            "set": {{
                "set1": "value1",
                "set2": "value2"
            }}
        }},
        "root": "user",
        "bounding": "strict"
    }},
    "roles": [
        {{
            "options": {{
                "timeout": {{
                    "type": "ppid",
                    "duration": "00:06:00"
                }},
                "path": {{
                    "default": "delete",
                    "add": [
                        "/usr/bin"
                    ]
                }},
                "env": {{
                    "default": "delete",
                    "override_behavior": false,
                    "keep": [
                        "keep2"
                    ],
                    "check": [
                        "check2"
                    ],
                    "delete": [
                        "del2"
                    ],
                    "set": {{
                        "set1": "value2",
                        "set3": "value3"
                    }}
                }},
                "root": "user",
                "bounding": "strict"
            }},
            "name": "role1",
            "actors": [
                {{
                    "type": "user",
                    "id": {}
                }}
            ],
            "tasks": [
                {{
                    "options": {{
                        "timeout": {{
                            "type": "ppid",
                            "duration": "00:07:00"
                        }},
                        "path": {{
                            "default": "delete",
                            "add": [
                                "/usr/bin"
                            ]
                        }},
                        "env": {{
                            "default": "delete",
                            "override_behavior": false,
                            "keep": [
                                "keep3"
                            ],
                            "check": [
                                "check3"
                            ],
                            "delete": [
                                "del3"
                            ],
                            "set": {{
                                "set1": "value3",
                                "set4": "value4"
                            }}
                        }},
                        "root": "user",
                        "bounding": "strict"
                    }},
                    "name": "task1",
                    "cred": {{
                        "setuid": 0,
                        "setgid": 0,
                        "caps": [
                            "CAP_SYS_ADMIN",
                            "CAP_SYS_RESOURCE"
                        ]
                    }}
                }}
            ]
        }}
    ]
}}"#,
            getuid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let config = result.unwrap();
        assert_eq!(config.roles.len(), 1);
        assert_eq!(config.roles[0].role, "role1");
        assert_eq!(config.roles[0].tasks.len(), 1);
        assert_eq!(config.roles[0].tasks[0].id, IdTask::Name("task1".into()));
        assert!(config.options.is_some());
        assert!(config.roles[0].options.is_some());
        assert!(config.roles[0].tasks[0].options.is_some());
    }

    #[test]
    fn test_config_optimized_with_options() {
        let json = format!(
            r#"{{
    "options": {{
        "timeout": {{
            "type": "ppid",
            "duration": "00:05:00"
        }},
        "path": {{
            "default": "delete",
            "add": [
                "/usr/bin"
            ]
        }},
        "env": {{
            "default": "delete",
            "override_behavior": false,
            "keep": [
                "keep1"
            ],
            "check": [
                "check1"
            ],
            "delete": [
                "del1"
            ],
            "set": {{
                "set1": "value1",
                "set2": "value2"
            }}
        }},
        "root": "user",
        "bounding": "strict"
    }},
    "roles": [
        {{
            "options": {{
                "timeout": {{
                    "type": "ppid",
                    "duration": "00:06:00"
                }},
                "path": {{
                    "default": "delete",
                    "add": [
                        "/usr/bin"
                    ]
                }},
                "env": {{
                    "default": "delete",
                    "override_behavior": false,
                    "keep": [
                        "keep2"
                    ],
                    "check": [
                        "check2"
                    ],
                    "delete": [
                        "del2"
                    ],
                    "set": {{
                        "set1": "value2",
                        "set3": "value3"
                    }}
                }},
                "root": "user",
                "bounding": "strict"
            }},
            "name": "role1",
            "actors": [
                {{
                    "type": "group",
                    "id": {}
                }}
            ],
            "tasks": [
                {{
                    "options": {{
                        "timeout": {{
                            "type": "ppid",
                            "duration": "00:07:00"
                        }},
                        "path": {{
                            "default": "delete",
                            "add": [
                                "/usr/bin"
                            ]
                        }},
                        "env": {{
                            "default": "delete",
                            "override_behavior": false,
                            "keep": [
                                "keep3"
                            ],
                            "check": [
                                "check3"
                            ],
                            "delete": [
                                "del3"
                            ],
                            "set": {{
                                "set1": "value3",
                                "set4": "value4"
                            }}
                        }},
                        "root": "user",
                        "bounding": "strict"
                    }},
                    "name": "task1",
                    "cred": {{
                        "setuid": 0,
                        "setgid": 0,
                        "caps": [
                            "CAP_SYS_ADMIN",
                            "CAP_SYS_RESOURCE"
                        ]
                    }},
                    "commands": ["/usr/bin/ls"]
                }}
            ]
        }}
    ]
}}"#,
            getgid().as_raw()
        );
        //convert json to cbor4ii
        let cbor = convert_json_to_cbor(&json);
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
        };
        let result: Result<DConfigFinder<'_>, _> = deserializer.deserialize(
            &mut cbor4ii::serde::Deserializer::new(SliceReader::new(cbor.as_slice())),
        );
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let config = result.unwrap();
        assert_eq!(config.roles.len(), 1);
        assert_eq!(config.roles[0].role, "role1");
        assert_eq!(config.roles[0].tasks.len(), 1);
        assert_eq!(config.roles[0].tasks[0].id, IdTask::Name("task1".into()));
        assert!(config.options.is_some());
        assert!(config.roles[0].options.is_some());
        assert!(config.roles[0].tasks[0].options.is_some());
        assert_eq!(config.roles[0].user_min, ActorMatchMin::GroupMatch(1));
        assert_eq!(config.roles[0].tasks[0].score.cmd_min, CmdMin::MATCH);
        assert_eq!(
            config.roles[0].tasks[0].score.setuser_min.uid,
            Some(SetuidMin::from(&0.into()))
        );
        assert_eq!(
            config.roles[0].tasks[0].score.setuser_min.gid,
            Some(SetgidMin::from(&vec![0]))
        );
        assert_eq!(
            config.roles[0].tasks[0].score.caps_min,
            CapsMin::CapsAdmin(2)
        );
        assert!(config.roles[0].tasks[0].commands.is_none());
        assert_eq!(
            config.roles[0].tasks[0].final_path,
            Some(PathBuf::from("/usr/bin/ls"))
        );
    }

    #[test]
    fn test_optimized_config() {
        let uid = getuid().as_raw();
        let json = format!(
            r#"{{"roles":[{{"name":"r_test","actors":[{{"type": "user", "id": {}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0"], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}]}}"#,
            uid
        );
        //convert json to cbor4ii
        let cbor = convert_json_to_cbor(&json);
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
        };
        let result: Result<DConfigFinder<'_>, _> = deserializer.deserialize(
            &mut cbor4ii::serde::Deserializer::new(SliceReader::new(cbor.as_slice())),
        );
        assert!(result.is_ok(), "Failed to deserialize: {:?}", result);
        let config = result.unwrap();
        assert_eq!(config.roles[0].user_min, ActorMatchMin::UserMatch);
        assert_eq!(config.roles[0].tasks[0].score.cmd_min, CmdMin::MATCH);
        assert_eq!(
            config.roles[0].tasks[0].score.setuser_min.uid,
            Some(SetuidMin::from(&0.into()))
        );
        assert_eq!(
            config.roles[0].tasks[0].score.setuser_min.gid,
            Some(SetgidMin::from(&vec![0]))
        );
        assert_eq!(config.roles[0].tasks[0].score.caps_min, CapsMin::NoCaps);
        assert!(config.roles[0].tasks[0].commands.is_none());
        assert_eq!(
            config.roles[0].tasks[0].final_path,
            Some(PathBuf::from("/usr/bin/ls"))
        );
    }

    #[test]
    fn test_expecting_error() {
        let seq = "[1, 2, 3]";
        let map = "{\"1\": 2, \"3\": 4}";
        let int = "1";
        let float = "1.0";
        let cli = Cli::builder().build();
        let config_finder = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().build(),
        };
        let result = config_finder.deserialize(&mut serde_json::Deserializer::from_str(seq));
        assert!(result.is_err(), "Expected error, got: {:?}", result);

        let role_list = RoleListFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = role_list.deserialize(&mut serde_json::Deserializer::from_str(map));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let task_list = TaskListFinderDeserializer {
            cli: &cli,
            env_path: &[],
            spath: &mut DPathOptions::default(),
        };
        let result = task_list.deserialize(&mut serde_json::Deserializer::from_str(map));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let task = TaskFinderDeserializer {
            cli: &cli,
            i: 0,
            env_path: &[],
            spath: &mut DPathOptions::default(),
        };
        let result = task.deserialize(&mut serde_json::Deserializer::from_str(seq));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        assert!(serde_json::from_str::<DCommandList>(int).is_err());
        let mut var_name = None;
        let mut cmd_min = CmdMin::MATCH;
        let dcommand = DCommandDeserializer {
            env_path: &[],
            cmd_path: &cli.cmd_path,
            cmd_args: &cli.cmd_args,
            final_path: &mut var_name,
            cmd_min: &mut cmd_min,
        };
        let result = dcommand.deserialize(&mut serde_json::Deserializer::from_str(seq));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let cred = CredFinderDeserializerReturn { cli: &cli };
        let result = cred.deserialize(&mut serde_json::Deserializer::from_str(seq));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let setuser = SetUserDeserializerReturn { cli: &cli };
        let result = setuser.deserialize(&mut serde_json::Deserializer::from_str(float));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let setgroups = SetGroupsDeserializerReturn { cli: &cli };
        let result = setgroups.deserialize(&mut serde_json::Deserializer::from_str(float));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let actors = ActorsFinderDeserializer {
            cred: &Cred::builder().build(),
        };
        let result = actors.deserialize(&mut serde_json::Deserializer::from_str(int));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
        let role = RoleFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = role.deserialize(&mut serde_json::Deserializer::from_str(int));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
    }

    // this test is to check if the deserializer can handle unknown types... It might evolve in the future
    #[test]
    fn test_unknown_type() {
        let json = r#"{"unknown": "unknown"}"#;
        let cli = Cli::builder().build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Expected error, got: {:?}", result);

        let deserializer = RoleFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Expected error, got: {:?}", result);

        let deserializer = TaskFinderDeserializer {
            cli: &cli,
            i: 0,
            env_path: &[],
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok(), "Expected error, got: {:?}", result);

        let deserializer = CredFinderDeserializerReturn { cli: &cli };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_err(), "Expected error, got: {:?}", result);
    }
}
