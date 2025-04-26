use std::{borrow::Cow, collections::HashMap, fmt::Display, ops::Deref};

use bon::Builder;
use capctl::CapSet;
use derivative::Derivative;
use log::{debug, info};
use nix::unistd::Group;
use rar_common::{database::{actor::{DActor, DGroups, DUserType}, options::Level, score::{ActorMatchMin, CapsMin, CmdMin, Score, SecurityMin, SetUserMin, TaskScore}, structs::{SCapabilities, SetBehavior}}, util::capabilities_are_exploitable, Cred};
use serde::{de::{DeserializeSeed, IgnoredAny, Visitor}, Deserialize};
use serde_json_borrow::Value;
use strum::EnumIs;

use crate::Cli;

use super::options::Opt;



#[derive(PartialEq, Eq, Debug, Default)]
pub struct DConfigFinder<'a> {
    pub options: Option<Opt<'a>>,
    pub roles: Vec<DRoleFinder<'a>>,
}


#[derive(Debug, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct DRoleFinder<'a> {
    pub user_min: ActorMatchMin,
    pub role: Cow<'a,str>,
    pub tasks: Vec<DTaskFinder<'a>>,
    pub options: Option<Opt<'a>>,
    pub _extra_values: HashMap<String, Value<'a>>,
}

#[derive(Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum IdTask<'a> {
    Name(
        #[serde(borrow)]
        Cow<'a, str>
    ),
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
    #[builder(default)]
    pub _extra_values: HashMap<Cow<'a,str>, Value<'a>>,
}


#[derive(Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum DCommand<'a> {
    Simple(
        #[serde(borrow)]
        Cow<'a,str>),
    Complex(Value<'a>),
}



pub struct ConfigFinderDeserializer<'a> {
    pub cli: &'a Cli,
    pub cred: &'a Cred,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for ConfigFinderDeserializer<'a> {
    type Value = DConfigFinder<'a>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field<'a> {
            Options,
            Roles,
            #[serde(untagged, borrow)]
            #[allow(dead_code)]
            Unknown(Cow<'a,str>),
        }

        struct ConfigFinderVisitor<'a> {
            cli: &'a Cli,
            cred: &'a Cred,
        }

        impl<'de: 'a, 'a> Visitor<'de> for ConfigFinderVisitor<'a> {
            type Value = DConfigFinder<'a>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("policy")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
                where
                    V: serde::de::MapAccess<'de>, {
                let mut options = None;
                let mut roles = Vec::new();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Options => {
                            debug!("ConfigFinderVisitor: options");
                            let mut opt : Opt = map.next_value()?;
                            opt.level = Level::Global;
                            options = Some(opt);
                        }
                        Field::Roles => {
                            debug!("ConfigFinderVisitor: roles");
                            roles = map.next_value_seed(RoleListFinderDeserializer {
                                cli: self.cli,
                                cred: self.cred,
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
        deserializer.deserialize_struct("Config", FIELDS, ConfigFinderVisitor { cli: self.cli, cred: self.cred })
    }
}

struct RoleListFinderDeserializer<'a> {
    cli: &'a Cli,
    cred: &'a Cred,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for RoleListFinderDeserializer<'a> {
    type Value = Vec<DRoleFinder<'a>>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        struct RoleListFinderVisitor<'a> {
            cli: &'a Cli,
            cred: &'a Cred,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for RoleListFinderVisitor<'a> {
            type Value = Vec<DRoleFinder<'a>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("RoleList sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>, {
                let mut roles = Vec::new();
                while let Some(role) = seq.next_element_seed(RoleFinderDeserializer {
                    cli: self.cli,
                    cred: self.cred,
                })? {
                    roles.push(role);
                }
                Ok(roles)
            }
        }
        deserializer.deserialize_seq(RoleListFinderVisitor { cli: self.cli, cred: self.cred })
    }
}

struct RoleFinderDeserializer<'a> {
    cli: &'a Cli,
    cred: &'a Cred,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for RoleFinderDeserializer<'a> {
    type Value = DRoleFinder<'a>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            Name,
            Actors,
            Tasks,
            Options,
            #[serde(untagged)]
            Unknown(String),
        }

        struct RoleFinderVisitor<'a> {
            cli: &'a Cli,
            cred: &'a Cred,
        }

        impl<'de: 'a, 'a> Visitor<'de> for RoleFinderVisitor<'a> {
            type Value = DRoleFinder<'a>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a role")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
                where
                    V: serde::de::MapAccess<'de>, {
                let mut role = None;
                let mut tasks: Vec<DTaskFinder<'a>> = Vec::new();
                let mut options = None;
                let mut extra_values = HashMap::new();
                let mut user_min = ActorMatchMin::default();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Name => {
                            debug!("RoleFinderVisitor: name");
                            role = Some(map.next_value()?);
                        }
                        Field::Actors => {
                            debug!("RoleFinderVisitor: actors");
                            user_min = map.next_value_seed(ActorsFinderDeserializer {
                                cred: self.cred,
                            })?;
                        }
                        Field::Tasks => {
                            debug!("RoleFinderVisitor: tasks");
                            tasks = map.next_value_seed(TaskListFinderDeserializer {
                                cli: self.cli,
                            })?;
                        }
                        Field::Options => {
                            debug!("RoleFinderVisitor: options");
                            let mut opt : Opt = map.next_value()?;
                            opt.level = Level::Role;
                            options = Some(opt);
                        }
                        Field::Unknown(key) => {
                            debug!("RoleFinderVisitor: unknown");
                            let unknown: Value = map.next_value()?;
                            extra_values.insert(key, unknown);
                        }
                    }
                }
                Ok(DRoleFinder {
                    user_min,
                    role: role.unwrap_or_default(),
                    tasks,
                    options,
                    _extra_values: extra_values,
                })
            }
        }
        const FIELDS: &[&str] = &["name", "tasks", "options"];
        deserializer.deserialize_struct("Role", FIELDS,RoleFinderVisitor { cli: self.cli, cred: self.cred })
    }
}

struct ActorsFinderDeserializer<'a> {
    cred: &'a Cred,
}

impl<'de> DeserializeSeed<'de> for ActorsFinderDeserializer<'_> {
    type Value = ActorMatchMin;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de> {
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
                    A: serde::de::SeqAccess<'de>, {
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
            fn match_groups(groups: &[Group], role_groups: &[DGroups<'_>]) -> bool {
                for role_group in role_groups {
                    if match role_group {
                        DGroups::Single(group) => {
                            debug!(
                                "Checking group {}, with {:?}, it must be {}",
                                group,
                                groups,
                                groups.iter().any(|g| group == g)
                            );
                            groups.iter().any(|g| group == g)
                        }
                        DGroups::Multiple(multiple_actors) => multiple_actors.iter().all(|actor| {
                            debug!("Checking group {}, with {:?}", actor, groups);
                            groups.iter().any(|g| actor == g)
                        }),
                    } {
                        return true;
                    }
                }
                false
            }
            fn user_matches(&self, user: &Cred, actor: &DActor<'_>) -> ActorMatchMin {
                match actor {
                    DActor::User { id, .. } => {
                        if let Some(id) = id {
                            if *id == user.user {
                                return ActorMatchMin::UserMatch;
                            }
                        }
                    }
                    DActor::Group { groups, .. } => {
                        if let Some(groups) = groups.as_ref() {
                            if Self::match_groups(&user.groups, &[groups.clone()]) {
                                return ActorMatchMin::GroupMatch(groups.len());
                            }
                        }
                    }
                    DActor::Unknown(element) => {
                        unimplemented!("Unknown actor type: {:?}", element);
                    }
                }
                ActorMatchMin::NoMatch
            }
        }

        deserializer.deserialize_seq(ActorsFinderVisitor {
            cred: self.cred,
        })
    }
}

struct TaskListFinderDeserializer<'a> {
    cli: &'a Cli,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for TaskListFinderDeserializer<'a> {
    type Value = Vec<DTaskFinder<'a>>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de> {
        struct TaskListFinderVisitor<'a> {
            cli: &'a Cli,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for TaskListFinderVisitor<'a> {
            type Value = Vec<DTaskFinder<'a>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("TaskList sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>, {
                let mut tasks = Vec::new();
                let mut i = 0;
                while let Some(element) = seq.next_element_seed(TaskFinderDeserializer {
                    cli: self.cli,
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
        })
    }
}

struct TaskFinderDeserializer<'a> {
    cli: &'a Cli,
    i: usize,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for TaskFinderDeserializer<'a>
{
    type Value = Option<DTaskFinder<'a>>;
    
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field<'a> {
            Name,
            Cred,
            #[serde(alias = "cmds")]
            Commands,
            Options,
            #[serde(untagged)]
            Unknown(Cow<'a,str>),
        }

        struct TaskFinderVisitor<'a> {
            cli: &'a Cli,
            i: usize,
        }

        impl<'de: 'a, 'a> serde::de::Visitor<'de> for TaskFinderVisitor<'a> {
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
                let mut extra_values = HashMap::new();

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Name => {
                            debug!("TaskFinderVisitor: name");
                            id = map.next_value()?;
                        }
                        Field::Cred => {
                            debug!("TaskFinderVisitor: cred");
                            let (su, sg, ca, sc, ok) = map.next_value_seed(CredFinderDeserializerReturn { cli: self.cli })?;
                            setuid = su;
                            setgroups = sg;
                            caps = ca;
                            score = sc;
                            if !ok {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                        }
                        Field::Commands => {
                            debug!("TaskFinderVisitor: commands");
                            commands = Some(map.next_value()?);
                        }
                        Field::Options => {
                            debug!("TaskFinderVisitor: options");
                            let mut opt : Opt = map.next_value()?;
                            opt.level = Level::Task;
                            options = Some(opt);
                        }
                        Field::Unknown(key) => {
                            debug!("TaskFinderVisitor: unknown");
                            let unknown: Value = map.next_value()?;
                            extra_values.insert(key, unknown);
                        }
                    }
                }

                Ok(Some(DTaskFinder {
                    id,
                    score,
                    setuid,
                    setgroups,
                    caps,
                    commands,
                    options,
                    _extra_values: extra_values,
                }))
            }
        }

        const FIELDS: &[&str] = &["name", "cred", "commands", "options"];
        deserializer.deserialize_struct("STask", FIELDS, TaskFinderVisitor { i: self.i, cli: self.cli })
    }
}


struct CredFinderDeserializerReturn<'a> {
    cli: &'a Cli,
}

impl <'de: 'a, 'a> DeserializeSeed<'de> for CredFinderDeserializerReturn<'a> {
    type Value = (Option<DUserType<'a>>, Option<DGroups<'a>>, Option<CapSet>, TaskScore, bool);
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            Setuid,
            #[serde(alias = "setgroups")]
            Setgid,
            #[serde(alias = "capabilities")]
            Caps,
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
            type Value = (Option<DUserType<'a>>, Option<DGroups<'a>>, Option<CapSet>, TaskScore, bool);

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
                            let (user, setuser_min, user_ok) = map.next_value_seed(SetUserDeserializerReturn { cli: self.cli })?;
                            setuid = user;
                            score.setuser_min = setuser_min;
                            if !user_ok { ok = false; }
                        }
                        Field::Setgid => {
                            debug!("CredFinderVisitor: setgid");
                            let (groups, setuser_min, groups_ok) = map.next_value_seed(SetGroupsDeserializerReturn { cli: self.cli })?;
                            setgroups = groups;
                            score.setuser_min = setuser_min;
                            if !groups_ok { ok = false; }
                        }
                        Field::Caps => {
                            debug!("CredFinderVisitor: capabilities");
                            let scaps: SCapabilities = map.next_value()?;
                            let capset = scaps.to_capset();
                            score.caps_min = get_caps_min(&capset);
                            caps = Some(capset);
                        }
                    }
                }
                Ok((setuid, setgroups, caps, score, ok))
            }
        }

        const FIELDS: &[&str] = &["setuid", "setgroups", "capabilities"];
        let (setuid, setgroups, caps, score, ok) = deserializer.deserialize_struct("Cred", FIELDS, CredFinderVisitor {
            cli: self.cli,
        })?;
        Ok((setuid, setgroups, caps, score, ok))
    }
}

// New deserializer for SetGroups that returns values instead of using &mut
struct SetGroupsDeserializerReturn<'a> {
    cli: &'a Cli,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for SetGroupsDeserializerReturn<'a> {
    type Value = (Option<DGroups<'a>>, SetUserMin, bool);
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            Default,
            Fallback,
            Add,
            Del,
        }
        struct SGroupsChooserVisitor<'a> {
            cli: &'a Cli,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for SGroupsChooserVisitor<'a> {
            type Value = (Option<DGroups<'a>>, SetUserMin, bool);

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("SGroups structure")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
                where
                    V: serde::de::MapAccess<'de>, {
                let mut groups = None;
                let mut score = SetUserMin::default();
                let mut ok = true;
                let mut default = SetBehavior::default();
                let filter = self.cli.opt_filter.as_ref().and_then(|x| x.group.as_ref());
                let mut add: Vec<Vec<u32>> = Vec::new();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Default => {
                            debug!("SGroupsChooserVisitor: default");
                            default = map.next_value()?;
                        },
                        Field::Fallback => {
                            debug!("SGroupsChooserVisitor: fallback");
                            let value= map.next_value::<DGroups>()?;
                            if let Some(u) = filter {
                                let value: Vec<u32> = value.try_into().map_err(serde::de::Error::custom)?;
                                if *u == value {
                                    ok = true;
                                }
                            } else {
                                groups = Some(value);
                            }
                        }
                        Field::Add => {
                            debug!("SGroupsChooserVisitor: add");
                            add = map.next_value()?;
                        }
                        Field::Del => {
                            debug!("SGroupsChooserVisitor: del");
                            if let Some(u) = filter {
                                for group in map.next_value::<Vec<DGroups>>()? {
                                    if let Some(v) = TryInto::<Vec<u32>>::try_into(group).ok() {
                                        if v == *u {
                                            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                            ok = false;
                                        }
                                    } else {
                                        return Err(serde::de::Error::custom("Invalid group"));
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(ref g) = groups {
                    score.gid.replace(g.into());
                }
                if default.is_all() || filter.is_some_and(|u| add.iter().any(|x| x == u)) {
                    ok = true;
                }
                Ok((groups, score, ok))
            }
        }
        deserializer.deserialize_any(SGroupsChooserVisitor {
            cli: self.cli,
        })
    }
}

// New deserializer for SetUser that returns values instead of using &mut
struct SetUserDeserializerReturn<'a> {
    cli: &'a Cli,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for SetUserDeserializerReturn<'a> {
    type Value = (Option<DUserType<'a>>, SetUserMin, bool);
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Default,
            Fallback,
            Add,
            Del,
        }
        struct SetUserVisitor<'a> {
            cli: &'a Cli,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for SetUserVisitor<'a> {
            type Value = (Option<DUserType<'a>>, SetUserMin, bool);
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("SUser structure")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
                where
                    V: serde::de::MapAccess<'de>, {
                let mut user = None;
                let mut score = SetUserMin::default();
                let mut ok = true;
                let mut default = SetBehavior::default();
                let filter = self.cli.opt_filter.as_ref().and_then(|x| x.user.as_ref());
                let mut add: Vec<DUserType<'a>> = Vec::new();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Default => {
                            debug!("SUserChooserVisitor: default");
                            default = map.next_value()?;
                        },
                        Field::Fallback => {
                            debug!("SUserChooserVisitor: fallback");
                            let value = map.next_value::<DUserType>()?;
                            if let Some(u) = filter {
                                let value  = value.fetch_id().ok_or(serde::de::Error::custom("User does not exist"))?;
                                if u == &value {
                                    ok = true;
                                }
                            } else {
                                user = Some(value);
                            }
                        }
                        Field::Add => {
                            debug!("SUserChooserVisitor: add");
                            if filter.is_some() {
                                add = map.next_value()?;
                            }
                        }
                        Field::Del => {
                            debug!("SUserChooserVisitor: del");
                            if let Some(u) = filter {
                                let users = map.next_value::<Vec<DUserType>>()?;
                                for user_item in users {
                                    let user_id = user_item.fetch_id().ok_or(serde::de::Error::custom("User does not exist"))?;
                                    if user_id == *u {
                                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                        ok = false;
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(ref u) = user {
                    score.uid.replace(u.into());
                }
                if default.is_all() || filter.is_some_and(|u| add.iter().any(|x| x == u)) {
                    ok = true;
                }
                Ok((user, score, ok))
            }
        }
        deserializer.deserialize_any(SetUserVisitor {
            cli: self.cli,
        })
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct DCommandList<'a> {
    pub default_behavior: Option<SetBehavior>,
    pub add: Vec<DCommand<'a>>,
    pub del: Vec<DCommand<'a>>,
}

impl<'de: 'a, 'a> Deserialize<'de> for DCommandList<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>, {
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
        impl<'a, 'de> serde::de::Visitor<'de> for DCommandListVisitor<'a> {
            type Value = DCommandList<'de>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("CommandList structure")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
                where
                    V: serde::de::MapAccess<'de>, {
                let mut default_behavior = None;
                let mut add = Vec::new();
                let mut del = Vec::new();
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
                Ok(DCommandList { default_behavior, add, del })
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: serde::de::SeqAccess<'de>, {
                let default_behavior = None;
                let mut add = Vec::new();
                while let Some(command) = seq.next_element()? {
                    add.push(command);
                }
                return Ok(DCommandList {
                    default_behavior,
                    add,
                    del: Vec::new(),
                });
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
                where
                    E: serde::de::Error, {
                return Ok(DCommandList {
                    default_behavior: Some(if v {
                        SetBehavior::All
                    } else {
                        SetBehavior::None
                    }),
                    add: Vec::new(),
                    del: Vec::new(),
                });
            }
        }
        deserializer.deserialize_any(DCommandListVisitor::default())
    }
}


impl<'a> DConfigFinder<'a> {
    pub fn roles<'s>(&'s self) -> Vec<DLinkedRole<'s, 'a>> {
        self.roles
            .iter()
            .map(|role| DLinkedRole::new(self, role))
            .collect()
    }

    pub fn role<'s>(&'s self, role_name: &str) -> Option<DLinkedRole<'s, 'a>> {
        self.roles
            .iter()
            .find(|r| r.role == role_name)
            .map(|role| DLinkedRole::new(self, role))
    }
}

#[derive(Clone, Copy)]
pub struct DLinkedRole<'c, 'a> {
    parent: &'c DConfigFinder<'a>,
    role: &'c DRoleFinder<'a>,
}

impl<'c, 'a> DLinkedRole<'c, 'a> {
    fn new(parent: &'c DConfigFinder<'a>, role: &'c DRoleFinder<'a>) -> Self {
        Self { parent, role }
    }

    pub fn tasks<'t>(&'t self) -> Vec<DLinkedTask<'t, 'c, 'a>> {
        self.role
            .tasks
            .iter()
            .map(|task| DLinkedTask::new(self, task))
            .collect()
    }

    pub fn role(&self) -> &DRoleFinder<'a> {
        self.role
    }

    pub fn config(&self) -> &DConfigFinder<'a> {
        self.parent
    }
}

#[derive(Clone, Copy)]
pub struct DLinkedTask<'t, 'c, 'a> {
    parent: &'t DLinkedRole<'c, 'a>,
    pub task: &'t DTaskFinder<'a>,
}

impl<'t, 'c, 'a> DLinkedTask<'t, 'c, 'a> {
    fn new(parent: &'t DLinkedRole<'c, 'a>, task: &'t DTaskFinder<'a>) -> Self {
        Self { parent, task }
    }

    pub fn commands<'l>(&'l self) -> Option<DLinkedCommandList<'l, 't, 'c, 'a>> {
        self.task.commands.as_ref().map(|list| DLinkedCommandList::new(self, list))
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
        Self { parent, command_list: list }
    }

    pub fn add<'d>(&'d self) -> Vec<DLinkedCommand<'d, 'l, 't, 'c, 'a>> {
        self.command_list
            .add
            .iter()
            .map(|cmd| DLinkedCommand::new(self, cmd))
            .collect()
    }

    pub fn del<'d>(&'d self) -> Vec<DLinkedCommand<'d, 'l, 't, 'c, 'a>> {
        self.command_list
            .del
            .iter()
            .map(|cmd| DLinkedCommand::new(self, cmd))
            .collect()
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