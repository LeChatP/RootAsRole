use bon::{bon, builder, Builder};
use capctl::{Cap, CapSet};
use derivative::Derivative;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Value};
use strum::{Display, EnumIs};

use std::{
    cell::RefCell,
    error::Error,
    fmt,
    ops::{Index, Not},
    rc::{Rc, Weak},
};

use super::{
    actor::{SActor, SGroups, SUserType},
    is_default,
    options::{Level, Opt, OptBuilder},
    wrapper::{OptWrapper, STaskWrapper},
};

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
pub struct SConfig {
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "sconfig_opt")]
    pub options: OptWrapper,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<Rc<RefCell<SRole>>>,
    #[serde(default)]
    #[serde(flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
}

fn sconfig_opt<'de, D>(deserializer: D) -> Result<Option<Rc<RefCell<Opt>>>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut opt = Opt::deserialize(deserializer)?;
    opt.level = Level::Global;
    Ok(Some(Rc::new(RefCell::new(opt))))
}

#[derive(Serialize, Deserialize, Debug, Derivative)]
#[serde(rename_all = "kebab-case")]
#[derivative(PartialEq, Eq)]
pub struct SRole {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<SActor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tasks: Vec<STaskWrapper>,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "srole_opt")]
    pub options: OptWrapper,
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
    #[serde(skip)]
    #[derivative(PartialEq = "ignore")]
    pub _config: Option<Weak<RefCell<SConfig>>>,
}

fn srole_opt<'de, D>(deserializer: D) -> Result<Option<Rc<RefCell<Opt>>>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut opt = Opt::deserialize(deserializer)?;
    opt.level = Level::Role;
    Ok(Some(Rc::new(RefCell::new(opt))))
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs)]
#[serde(untagged)]
pub enum IdTask {
    Name(String),
    Number(usize),
}

impl std::fmt::Display for IdTask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IdTask::Name(name) => write!(f, "{}", name),
            IdTask::Number(id) => write!(f, "{}", id),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct STask {
    #[serde(default, skip_serializing_if = "IdTask::is_number")]
    pub name: IdTask,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub cred: SCredentials,
    #[serde(default, skip_serializing_if = "is_default")]
    pub commands: SCommands,
    #[serde(skip_serializing_if = "Option::is_none", deserialize_with = "stask_opt")]
    pub options: OptWrapper,
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
    #[serde(skip)]
    #[derivative(PartialEq = "ignore")]
    pub _role: Option<Weak<RefCell<SRole>>>,
}

fn stask_opt<'de, D>(deserializer: D) -> Result<Option<Rc<RefCell<Opt>>>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut opt = Opt::deserialize(deserializer)?;
    opt.level = Level::Task;
    Ok(Some(Rc::new(RefCell::new(opt))))
}

#[derive(Serialize, Deserialize, Debug, Builder, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct SCredentials {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub setuid: Option<SUserChooser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub setgid: Option<SGroups>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<SCapabilities>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub additional_auth: Option<String>, // TODO: to extract as plugin
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    #[builder(default)]
    pub _extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum SUserChooser {
    Actor(SUserType),
    ChooserStruct(SSetuidSet),
}

impl From<SUserType> for SUserChooser {
    fn from(actor: SUserType) -> Self {
        SUserChooser::Actor(actor)
    }
}

impl From<SSetuidSet> for SUserChooser {
    fn from(set: SSetuidSet) -> Self {
        SUserChooser::ChooserStruct(set)
    }
}

impl From<&str> for SUserChooser {
    fn from(name: &str) -> Self {
        SUserChooser::Actor(name.into())
    }
}

impl From<u32> for SUserChooser {
    fn from(id: u32) -> Self {
        SUserChooser::Actor(id.into())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Builder, PartialEq, Eq)]

pub struct SSetuidSet {
    #[builder(start_fn, into)]
    pub fallback: SUserType,
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default: SetBehavior,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[builder(default, with = FromIterator::from_iter)]
    pub add: Vec<SUserType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[builder(default, with = FromIterator::from_iter)]
    pub sub: Vec<SUserType>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Display, Debug, EnumIs, Clone)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SetBehavior {
    All,
    #[default]
    None,
}

#[derive(PartialEq, Eq, Debug, Builder)]
pub struct SCapabilities {
    #[builder(start_fn)]
    pub default_behavior: SetBehavior,
    #[builder(field)]
    pub add: CapSet,
    #[builder(field)]
    pub sub: CapSet,
    #[builder(default, with = <_>::from_iter)]
    pub _extra_fields: Map<String, Value>,
}

impl<S: s_capabilities_builder::State> SCapabilitiesBuilder<S> {
    pub fn add_cap(mut self, cap: Cap) -> Self {
        self.add.add(cap);
        self
    }
    pub fn add_all(mut self, set: CapSet) -> Self {
        self.add = set;
        self
    }
    pub fn sub_cap(mut self, cap: Cap) -> Self {
        self.sub.add(cap);
        self
    }
    pub fn sub_all(mut self, set: CapSet) -> Self {
        self.sub = set;
        self
    }
}

impl Serialize for SCapabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.default_behavior.is_none() && self.sub.is_empty() && self._extra_fields.is_empty() {
            super::serialize_capset(&self.add, serializer)
        } else {
            let mut map = serializer.serialize_map(Some(3))?;
            if self.default_behavior.is_none() {
                map.serialize_entry("default", &self.default_behavior)?;
            }
            if !self.add.is_empty() {
                let v: Vec<String> = self.add.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("add", &v)?;
            }
            if !self.sub.is_empty() {
                let v: Vec<String> = self.sub.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("del", &v)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
    }
}
impl<'de> Deserialize<'de> for SCapabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SCapabilitiesVisitor;

        impl<'de> Visitor<'de> for SCapabilitiesVisitor {
            type Value = SCapabilities;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of strings or a map with SCapabilities fields")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut add = CapSet::default();
                while let Some(cap) = seq.next_element::<String>()? {
                    add.add(cap.parse().map_err(de::Error::custom)?);
                }

                Ok(SCapabilities {
                    default_behavior: SetBehavior::None,
                    add,
                    sub: CapSet::default(),
                    _extra_fields: Map::new(),
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut default_behavior = SetBehavior::None;
                let mut add = CapSet::default();
                let mut sub = CapSet::default();
                let mut _extra_fields = Map::new();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "default" => {
                            default_behavior = map
                                .next_value()
                                .expect("default entry must be either 'all' or 'none'");
                        }
                        "add" => {
                            let values: Vec<String> =
                                map.next_value().expect("add entry must be a list");
                            for value in values {
                                add.add(value.parse().map_err(|_| {
                                    de::Error::custom(format!("Invalid capability: {}", value))
                                })?);
                            }
                        }
                        "sub" | "del" => {
                            let values: Vec<String> =
                                map.next_value().expect("sub entry must be a list");
                            for value in values {
                                sub.add(value.parse().map_err(|_| {
                                    de::Error::custom(format!("Invalid capability: {}", value))
                                })?);
                            }
                        }
                        other => {
                            _extra_fields.insert(other.to_string(), map.next_value()?);
                        }
                    }
                }

                Ok(SCapabilities {
                    default_behavior,
                    add,
                    sub,
                    _extra_fields,
                })
            }
        }

        deserializer.deserialize_any(SCapabilitiesVisitor)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum SCommand {
    Simple(String),
    Complex(Value),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SCommands {
    #[serde(rename = "default")]
    pub default_behavior: Option<SetBehavior>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<SCommand>,
    #[serde(default, alias = "del", skip_serializing_if = "Vec::is_empty")]
    pub sub: Vec<SCommand>,
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
}

// ------------------------
// Default implementations
// ------------------------

impl Default for SConfig {
    fn default() -> Self {
        SConfig {
            options: Some(Rc::new(RefCell::new(Opt::default()))),
            roles: Vec::new(),
            _extra_fields: Map::default(),
        }
    }
}

impl Default for SRole {
    fn default() -> Self {
        SRole {
            name: "".to_string(),
            actors: Vec::new(),
            tasks: Vec::new(),
            options: None,
            _extra_fields: Map::default(),
            _config: None,
        }
    }
}

impl Default for STask {
    fn default() -> Self {
        STask {
            name: IdTask::Number(0),
            purpose: None,
            cred: SCredentials::default(),
            commands: SCommands::default(),
            options: None,
            _extra_fields: Map::default(),
            _role: None,
        }
    }
}

impl Default for SCredentials {
    fn default() -> Self {
        SCredentials {
            setuid: None,
            setgid: None,
            capabilities: Some(SCapabilities::default()),
            additional_auth: None,
            _extra_fields: Map::default(),
        }
    }
}

impl Default for SCommands {
    fn default() -> Self {
        SCommands {
            default_behavior: Some(SetBehavior::default()),
            add: Vec::new(),
            sub: Vec::new(),
            _extra_fields: Map::default(),
        }
    }
}

impl Default for SCapabilities {
    fn default() -> Self {
        SCapabilities {
            default_behavior: SetBehavior::default(),
            add: CapSet::empty(),
            sub: CapSet::empty(),
            _extra_fields: Map::default(),
        }
    }
}

impl Default for SSetuidSet {
    fn default() -> Self {
        SSetuidSet::builder(0, SetBehavior::None).build()
    }
}

impl Default for IdTask {
    fn default() -> Self {
        IdTask::Number(0)
    }
}

// ------------------------
// From implementations
// ------------------------

impl From<usize> for IdTask {
    fn from(id: usize) -> Self {
        IdTask::Number(id)
    }
}

impl From<String> for IdTask {
    fn from(name: String) -> Self {
        IdTask::Name(name)
    }
}

impl From<&str> for IdTask {
    fn from(name: &str) -> Self {
        IdTask::Name(name.to_string())
    }
}

impl From<&str> for SCommand {
    fn from(name: &str) -> Self {
        SCommand::Simple(name.to_string())
    }
}

impl From<CapSet> for SCapabilities {
    fn from(capset: CapSet) -> Self {
        SCapabilities {
            add: capset,
            ..Default::default()
        }
    }
}

// ------------------------
// Deserialize
// ------------------------

// This try to deserialize a number as an ID and a string as a name

// ========================
// Implementations for Struct navigation
// ========================
#[bon]
impl SConfig {
    #[builder]
    pub fn new(
        #[builder(field)] roles: Vec<Rc<RefCell<SRole>>>,
        #[builder(with = |f : fn(OptBuilder) -> Rc<RefCell<Opt>> | f(Opt::builder(Level::Global)))]
        options: Option<Rc<RefCell<Opt>>>,
        _extra_fields: Option<Map<String, Value>>,
    ) -> Rc<RefCell<Self>> {
        let c = Rc::new(RefCell::new(SConfig {
            roles: roles.clone(),
            options: options.clone(),
            _extra_fields: _extra_fields.unwrap_or_default().clone(),
        }));
        for role in &roles {
            role.borrow_mut()._config = Some(Rc::downgrade(&c));
        }
        c
    }
}

pub trait RoleGetter {
    fn role(&self, name: &str) -> Option<Rc<RefCell<SRole>>>;
    fn task<T: Into<IdTask>>(
        &self,
        role: &str,
        name: T,
    ) -> Result<Rc<RefCell<STask>>, Box<dyn Error>>;
}

pub trait TaskGetter {
    fn task(&self, name: &IdTask) -> Option<Rc<RefCell<STask>>>;
}

impl RoleGetter for Rc<RefCell<SConfig>> {
    fn role(&self, name: &str) -> Option<Rc<RefCell<SRole>>> {
        self.as_ref()
            .borrow()
            .roles
            .iter()
            .find(|role| role.borrow().name == name)
            .cloned()
    }
    fn task<T: Into<IdTask>>(
        &self,
        role: &str,
        name: T,
    ) -> Result<Rc<RefCell<STask>>, Box<dyn Error>> {
        let name = name.into();
        self.role(role)
            .and_then(|role| role.as_ref().borrow().task(&name).cloned())
            .ok_or_else(|| format!("Task {} not found in role {}", name, role).into())
    }
}

impl TaskGetter for Rc<RefCell<SRole>> {
    fn task(&self, name: &IdTask) -> Option<Rc<RefCell<STask>>> {
        self.as_ref()
            .borrow()
            .tasks
            .iter()
            .find(|task| task.borrow().name == *name)
            .cloned()
    }
}

impl<S: s_config_builder::State> SConfigBuilder<S> {
    pub fn role(mut self, role: Rc<RefCell<SRole>>) -> Self {
        self.roles.push(role);
        self
    }
    pub fn roles(mut self, roles: impl IntoIterator<Item = Rc<RefCell<SRole>>>) -> Self {
        self.roles.extend(roles);
        self
    }
}

impl<S: s_role_builder::State> SRoleBuilder<S> {
    pub fn task(mut self, task: Rc<RefCell<STask>>) -> Self {
        self.tasks.push(task);
        self
    }
    pub fn actor(mut self, actor: SActor) -> Self {
        self.actors.push(actor);
        self
    }
}

#[bon]
impl SRole {
    #[builder]
    pub fn new(
        #[builder(start_fn, into)] name: String,
        #[builder(field)] tasks: Vec<Rc<RefCell<STask>>>,
        #[builder(field)] actors: Vec<SActor>,
        #[builder(with = |f : fn(OptBuilder) -> Rc<RefCell<Opt>> | f(Opt::builder(Level::Role)))]
        options: Option<Rc<RefCell<Opt>>>,
        #[builder(default)] _extra_fields: Map<String, Value>,
    ) -> Rc<RefCell<Self>> {
        let s = Rc::new(RefCell::new(SRole {
            name,
            actors,
            tasks,
            options,
            _extra_fields,
            _config: None,
        }));
        for task in s.as_ref().borrow_mut().tasks.iter() {
            task.borrow_mut()._role = Some(Rc::downgrade(&s));
        }
        s
    }
    pub fn config(&self) -> Option<Rc<RefCell<SConfig>>> {
        self._config.as_ref()?.upgrade()
    }
    pub fn task(&self, name: &IdTask) -> Option<&Rc<RefCell<STask>>> {
        self.tasks
            .iter()
            .find(|task| task.as_ref().borrow().name == *name)
    }
}

#[bon]
impl STask {
    #[builder]
    pub fn new(
        #[builder(start_fn, into)] name: IdTask,
        purpose: Option<String>,
        #[builder(default)] cred: SCredentials,
        #[builder(default)] commands: SCommands,
        #[builder(with = |f : fn(OptBuilder) -> Rc<RefCell<Opt>> | f(Opt::builder(Level::Task)))]
        options: Option<Rc<RefCell<Opt>>>,
        #[builder(default)] _extra_fields: Map<String, Value>,
        _role: Option<Weak<RefCell<SRole>>>,
    ) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(STask {
            name,
            purpose,
            cred,
            commands,
            options,
            _extra_fields,
            _role,
        }))
    }
    pub fn role(&self) -> Option<Rc<RefCell<SRole>>> {
        self._role.as_ref()?.upgrade()
    }
}

impl Index<usize> for SConfig {
    type Output = Rc<RefCell<SRole>>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.roles[index]
    }
}

impl Index<usize> for SRole {
    type Output = Rc<RefCell<STask>>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.tasks[index]
    }
}

#[bon]
impl SCommands {
    #[builder]
    pub fn new(
        #[builder(start_fn)] default_behavior: SetBehavior,
        #[builder(default, with = FromIterator::from_iter)] add: Vec<SCommand>,
        #[builder(default, with = FromIterator::from_iter)] sub: Vec<SCommand>,
        #[builder(default, with = <_>::from_iter)] _extra_fields: Map<String, Value>,
    ) -> Self {
        SCommands {
            default_behavior: Some(default_behavior),
            add,
            sub,
            _extra_fields,
        }
    }
}

impl SCapabilities {
    pub fn to_capset(&self) -> CapSet {
        let mut capset = match self.default_behavior {
            SetBehavior::All => capctl::bounding::probe() & CapSet::not(CapSet::empty()),
            SetBehavior::None => CapSet::empty(),
        };
        capset = capset.union(self.add);
        capset.drop_all(self.sub);
        capset
    }
}

impl PartialEq<str> for SUserChooser {
    fn eq(&self, other: &str) -> bool {
        match self {
            SUserChooser::Actor(actor) => actor == &SUserType::from(other),
            SUserChooser::ChooserStruct(chooser) => chooser.fallback == *other,
        }
    }
}

#[cfg(test)]
mod tests {

    use capctl::Cap;
    use chrono::Duration;

    use crate::{
        as_borrow,
        database::{
            actor::SGroupType,
            options::{EnvBehavior, PathBehavior, SAuthentication, TimestampType},
        },
    };

    use super::*;

    #[test]
    fn test_deserialize() {
        println!("START");
        let config = r#"
        {
            "version": "1.0.0",
            "options": {
                "path": {
                    "default": "delete",
                    "add": ["path_add"],
                    "sub": ["path_sub"]
                },
                "env": {
                    "default": "delete",
                    "keep": ["keep_env"],
                    "check": ["check_env"]
                },
                "root": "privileged",
                "bounding": "ignore",
                "authentication": "skip",
                "wildcard-denied": "wildcards",
                "timeout": {
                    "type": "ppid",
                    "duration": "00:05:00"
                }
            },
            "roles": [
                {
                    "name": "role1",
                    "actors": [
                        {
                            "type": "user",
                            "name": "user1"
                        },
                        {
                            "type":"group",
                            "groups": ["group1","1000"]
                        }
                    ],
                    "tasks": [
                        {
                            "name": "task1",
                            "purpose": "purpose1",
                            "cred": {
                                "setuid": {
                                    "fallback": "user1",
                                    "default": "all",
                                    "add": ["cap_chown"],
                                    "sub": ["cap_chown"]
                                },
                                "setgid": "setgid1",
                                "capabilities": {
                                    "default": "all",
                                    "add": ["cap_net_bind_service"],
                                    "sub": ["cap_sys_admin"]
                                }
                            },
                            "commands": {
                                "default": "all",
                                "add": ["cmd1"],
                                "sub": ["cmd2"]
                            }
                        }
                    ]
                }
            ]
        }
        "#;
        println!("STEP 1");
        let config: SConfig = serde_json::from_str(config).unwrap();
        let options = config.options.as_ref().unwrap().as_ref().borrow();
        let path = options.path.as_ref().unwrap();
        assert_eq!(path.default_behavior, PathBehavior::Delete);
        assert!(path.add.front().is_some_and(|s| s == "path_add"));
        let env = options.env.as_ref().unwrap();
        assert_eq!(env.default_behavior, EnvBehavior::Delete);
        assert!(env.keep.front().is_some_and(|s| s == "keep_env"));
        assert!(env.check.front().is_some_and(|s| s == "check_env"));
        assert!(options.root.as_ref().unwrap().is_privileged());
        assert!(options.bounding.as_ref().unwrap().is_ignore());
        assert_eq!(options.authentication, Some(SAuthentication::Skip));
        assert_eq!(options.wildcard_denied.as_ref().unwrap(), "wildcards");

        let timeout = options.timeout.as_ref().unwrap();
        assert_eq!(timeout.type_field, Some(TimestampType::PPID));
        assert_eq!(timeout.duration, Some(Duration::minutes(5)));
        assert_eq!(config.roles[0].as_ref().borrow().name, "role1");
        let actor0 = &config.roles[0].as_ref().borrow().actors[0];
        assert_eq!(
            actor0,
            &SActor::User {
                id: Some("user1".into()),
                _extra_fields: Map::default()
            }
        );
        let actor1 = &config.roles[0].as_ref().borrow().actors[1];
        match actor1 {
            SActor::Group { groups, .. } => match groups.as_ref().unwrap() {
                SGroups::Multiple(groups) => {
                    assert_eq!(&groups[0], "group1");
                    assert_eq!(groups[1], 1000);
                }
                _ => panic!("unexpected actor group type"),
            },
            _ => panic!("unexpected actor {:?}", actor1),
        }
        let role = config.roles[0].as_ref().borrow();
        assert_eq!(as_borrow!(role[0]).purpose.as_ref().unwrap(), "purpose1");
        let cred = &as_borrow!(&role[0]).cred;
        let setuidstruct = SSetuidSet {
            fallback: "user1".into(),
            default: SetBehavior::All,
            add: ["cap_chown".into()].into(),
            sub: ["cap_chown".into()].into(),
        };
        assert!(
            matches!(cred.setuid.as_ref().unwrap(), SUserChooser::ChooserStruct(set) if set == &setuidstruct)
        );
        assert_eq!(*cred.setgid.as_ref().unwrap(), ["setgid1".into()]);
        let capabilities = cred.capabilities.as_ref().unwrap();
        assert_eq!(capabilities.default_behavior, SetBehavior::All);
        assert!(capabilities.add.has(Cap::NET_BIND_SERVICE));
        assert!(capabilities.sub.has(Cap::SYS_ADMIN));
        let commands = &as_borrow!(&role[0]).commands;
        assert_eq!(
            *commands.default_behavior.as_ref().unwrap(),
            SetBehavior::All
        );
        assert_eq!(commands.add[0], SCommand::Simple("cmd1".into()));
        assert_eq!(commands.sub[0], SCommand::Simple("cmd2".into()));
    }
    #[test]
    fn test_unknown_fields() {
        let config = r#"
        {
            "version": "1.0.0",
            "options": {
                "path": {
                    "default": "delete",
                    "add": ["path_add"],
                    "sub": ["path_sub"],
                    "unknown": "unknown"
                },
                "env": {
                    "default": "delete",
                    "keep": ["keep_env"],
                    "check": ["check_env"],
                    "unknown": "unknown"
                },
                "allow-root": false,
                "allow-bounding": false,
                "wildcard-denied": "wildcards",
                "timeout": {
                    "type": "ppid",
                    "duration": "00:05:00",
                    "unknown": "unknown"
                },
                "unknown": "unknown"
            },
            "roles": [
                {
                    "name": "role1",
                    "actors": [
                        {
                            "type": "user",
                            "name": "user1",
                            "unknown": "unknown"
                        },
                        {
                            "type":"bla",
                            "unknown": "unknown"
                        }
                    ],
                    "tasks": [
                        {
                            "name": "task1",
                            "purpose": "purpose1",
                            "cred": {
                                "setuid": "setuid1",
                                "setgid": "setgid1",
                                "capabilities": {
                                    "default": "all",
                                    "add": ["cap_dac_override"],
                                    "sub": ["cap_dac_override"],
                                    "unknown": "unknown"
                                },
                                "unknown": "unknown"
                            },
                            "commands": {
                                "default": "all",
                                "add": ["cmd1"],
                                "sub": ["cmd2"],
                                "unknown": "unknown"
                            },
                            "unknown": "unknown"
                        }
                    ],
                    "unknown": "unknown"
                }
            ],
            "unknown": "unknown"
        }
        "#;
        let config: SConfig = serde_json::from_str(config).unwrap();
        assert_eq!(config._extra_fields.get("unknown").unwrap(), "unknown");

        let binding = config.options.unwrap();
        let options = binding.as_ref().borrow();
        let path = options.path.as_ref().unwrap();
        assert_eq!(path._extra_fields.get("unknown").unwrap(), "unknown");
        let env = &options.env.as_ref().unwrap();
        assert_eq!(env._extra_fields.get("unknown").unwrap(), "unknown");
        assert_eq!(options._extra_fields.get("unknown").unwrap(), "unknown");
        let timeout = options.timeout.as_ref().unwrap();
        assert_eq!(timeout._extra_fields.get("unknown").unwrap(), "unknown");
        assert_eq!(config._extra_fields.get("unknown").unwrap(), "unknown");
        let actor0 = &as_borrow!(config.roles[0]).actors[0];
        match actor0 {
            SActor::User { id, _extra_fields } => {
                assert_eq!(id.as_ref().unwrap(), "user1");
                assert_eq!(_extra_fields.get("unknown").unwrap(), "unknown");
            }
            _ => panic!("unexpected actor type"),
        }
        let actor1 = &as_borrow!(config.roles[0]).actors[1];
        match actor1 {
            SActor::Unknown(unknown) => {
                let obj = unknown.as_object().unwrap();
                assert_eq!(obj.get("type").unwrap().as_str().unwrap(), "bla");
                assert_eq!(obj.get("unknown").unwrap().as_str().unwrap(), "unknown");
            }
            _ => panic!("unexpected actor type"),
        }
        assert_eq!(
            config.roles[0].as_ref().borrow()[0]
                .as_ref()
                .borrow()
                ._extra_fields
                .get("unknown")
                .as_ref()
                .unwrap()
                .as_str()
                .unwrap(),
            "unknown"
        );
        let role = config.roles[0].as_ref().borrow();
        let cred = &role[0].as_ref().borrow().cred;
        assert_eq!(cred._extra_fields.get("unknown").unwrap(), "unknown");
        let capabilities = cred.capabilities.as_ref().unwrap();
        assert_eq!(
            capabilities._extra_fields.get("unknown").unwrap(),
            "unknown"
        );
        let commands = &as_borrow!(role[0]).commands;
        assert_eq!(commands._extra_fields.get("unknown").unwrap(), "unknown");
    }

    #[test]
    fn test_deserialize_alias() {
        let config = r#"
        {
            "version": "1.0.0",
            "options": {
                "path": {
                    "default": "delete",
                    "add": ["path_add"],
                    "del": ["path_sub"]
                },
                "env": {
                    "default": "delete",
                    "keep": ["keep_env"],
                    "check": ["check_env"]
                },
                "root": "privileged",
                "bounding": "ignore",
                "authentication": "skip",
                "wildcard-denied": "wildcards",
                "timeout": {
                    "type": "ppid",
                    "duration": "00:05:00"
                }
            },
            "roles": [
                {
                    "name": "role1",
                    "actors": [
                        {
                            "type": "user",
                            "name": "user1"
                        },
                        {
                            "type":"group",
                            "groups": ["group1","1000"]
                        }
                    ],
                    "tasks": [
                        {
                            "name": "task1",
                            "purpose": "purpose1",
                            "cred": {
                                "setuid": "setuid1",
                                "setgid": "setgid1",
                                "capabilities": ["cap_net_bind_service"]
                            },
                            "commands": {
                                "default": "all",
                                "add": ["cmd1"],
                                "del": ["cmd2"]
                            }
                        }
                    ]
                }
            ]
        }
        "#;
        let config: SConfig = serde_json::from_str(config).unwrap();
        let options = config.options.as_ref().unwrap().as_ref().borrow();
        let path = options.path.as_ref().unwrap();
        assert_eq!(path.default_behavior, PathBehavior::Delete);
        assert!(path.add.front().is_some_and(|s| s == "path_add"));
        let env = options.env.as_ref().unwrap();
        assert_eq!(env.default_behavior, EnvBehavior::Delete);
        assert!(env.keep.front().is_some_and(|s| s == "keep_env"));
        assert!(env.check.front().is_some_and(|s| s == "check_env"));
        assert!(options.root.as_ref().unwrap().is_privileged());
        assert!(options.bounding.as_ref().unwrap().is_ignore());
        assert_eq!(options.authentication, Some(SAuthentication::Skip));
        assert_eq!(options.wildcard_denied.as_ref().unwrap(), "wildcards");

        let timeout = options.timeout.as_ref().unwrap();
        assert_eq!(timeout.type_field, Some(TimestampType::PPID));
        assert_eq!(timeout.duration, Some(Duration::minutes(5)));
        assert_eq!(config.roles[0].as_ref().borrow().name, "role1");
        let actor0 = &config.roles[0].as_ref().borrow().actors[0];
        match actor0 {
            SActor::User { id, .. } => {
                assert_eq!(id.as_ref().unwrap(), "user1");
            }
            _ => panic!("unexpected actor type"),
        }
        let actor1 = &config.roles[0].as_ref().borrow().actors[1];
        match actor1 {
            SActor::Group { groups, .. } => match groups.as_ref().unwrap() {
                SGroups::Multiple(groups) => {
                    assert_eq!(groups[0], SGroupType::from("group1"));
                    assert_eq!(groups[1], SGroupType::from(1000));
                }
                _ => panic!("unexpected actor group type"),
            },
            _ => panic!("unexpected actor {:?}", actor1),
        }
        let role = config.roles[0].as_ref().borrow();
        assert_eq!(as_borrow!(role[0]).purpose.as_ref().unwrap(), "purpose1");
        let cred = &as_borrow!(&role[0]).cred;
        assert_eq!(
            cred.setuid.as_ref().unwrap(),
            &SUserChooser::from(SUserType::from("setuid1"))
        );
        assert_eq!(cred.setgid.as_ref().unwrap(), &SGroups::from(["setgid1"]));
        let capabilities = cred.capabilities.as_ref().unwrap();
        assert_eq!(capabilities.default_behavior, SetBehavior::None);
        assert!(capabilities.add.has(Cap::NET_BIND_SERVICE));
        assert!(capabilities.sub.is_empty());
        let commands = &as_borrow!(&role[0]).commands;
        assert_eq!(
            *commands.default_behavior.as_ref().unwrap(),
            SetBehavior::All
        );
        assert_eq!(commands.add[0], SCommand::Simple("cmd1".into()));
        assert_eq!(commands.sub[0], SCommand::Simple("cmd2".into()));
    }
}
