use bon::{bon, Builder};
use capctl::{Cap, CapSet};
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use strum::{Display, EnumIs, EnumString, FromRepr};

use std::{
    cell::RefCell,
    error::Error,
    fmt,
    ops::{Index, Not},
    rc::{Rc, Weak},
};

use crate::{
    rc_refcell,
    util::{HARDENED_ENUM_VALUE_0, HARDENED_ENUM_VALUE_1},
};

use super::{
    actor::{SActor, SGroupType, SGroups, SUserType},
    options::{Level, Opt, OptBuilder},
};

#[derive(Deserialize, PartialEq, Eq, Debug, Default)]
pub struct SConfig {
    #[serde(default, deserialize_with = "sconfig_opt", alias = "o")]
    pub options: Option<Rc<RefCell<Opt>>>,
    #[serde(default, alias = "r")]
    pub roles: Vec<Rc<RefCell<SRole>>>,
    #[serde(default, flatten)]
    pub _extra_fields: Map<String, Value>,
}

fn sconfig_opt<'de, D>(deserializer: D) -> Result<Option<Rc<RefCell<Opt>>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<Rc<RefCell<Opt>>> = Option::deserialize(deserializer)?;
    if let Some(opt) = opt {
        opt.as_ref().borrow_mut().level = Level::Global;
        Ok(Some(opt))
    } else {
        Ok(None)
    }
}

#[derive(Deserialize, Debug, Derivative, Default)]
#[serde(rename_all = "kebab-case")]
#[derivative(PartialEq, Eq)]
pub struct SRole {
    #[serde(alias = "n", default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(alias = "a", default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<SActor>,
    #[serde(alias = "t", default, skip_serializing_if = "Vec::is_empty")]
    pub tasks: Vec<Rc<RefCell<STask>>>,
    #[serde(
        alias = "o",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "srole_opt"
    )]
    pub options: Option<Rc<RefCell<Opt>>>,
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
    let opt: Option<Rc<RefCell<Opt>>> = Option::deserialize(deserializer)?;
    if let Some(opt) = opt {
        opt.as_ref().borrow_mut().level = Level::Role;
        Ok(Some(opt))
    } else {
        Ok(None)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum IdTask {
    Name(String),
    Number(usize),
}

impl Default for IdTask {
    fn default() -> Self {
        IdTask::Number(0)
    }
}

impl std::fmt::Display for IdTask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IdTask::Name(name) => write!(f, "{}", name),
            IdTask::Number(id) => write!(f, "{}", id),
        }
    }
}

pub(super) fn cmds_is_default(cmds: &SCommands) -> bool {
    cmds.default
        .as_ref()
        .is_none_or(|b| *b == Default::default())
        && cmds.add.is_empty()
        && cmds.sub.is_empty()
        && cmds._extra_fields.is_empty()
}

#[derive(Deserialize, Debug, Derivative, Default)]
#[derivative(PartialEq, Eq)]
pub struct STask {
    #[serde(alias = "n", default, skip_serializing_if = "IdTask::is_number")]
    pub name: IdTask,
    #[serde(alias = "p", skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(
        alias = "i",
        alias = "credentials",
        default,
        skip_serializing_if = "is_default"
    )]
    pub cred: SCredentials,
    #[serde(
        alias = "c",
        alias = "cmds",
        default,
        skip_serializing_if = "cmds_is_default"
    )]
    pub commands: SCommands,
    #[serde(
        alias = "o",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "stask_opt"
    )]
    pub options: Option<Rc<RefCell<Opt>>>,
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
    let opt: Option<Rc<RefCell<Opt>>> = Option::deserialize(deserializer)?;
    if let Some(opt) = opt {
        opt.as_ref().borrow_mut().level = Level::Task;
        Ok(Some(opt))
    } else {
        Ok(None)
    }
}

#[cfg_attr(test, derive(Clone))]
#[derive(Deserialize, Debug, Builder, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct SCredentials {
    #[serde(alias = "u", skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub setuid: Option<SUserEither>,
    #[serde(alias = "g", skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub setgid: Option<SGroupsEither>,
    #[serde(default, alias = "c", skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<SCapabilities>,
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    #[builder(default)]
    pub _extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum SUserEither {
    MandatoryUser(SUserType),
    UserSelector(SSetuidSet),
}

impl From<SUserType> for SUserEither {
    fn from(actor: SUserType) -> Self {
        SUserEither::MandatoryUser(actor)
    }
}

impl From<SSetuidSet> for SUserEither {
    fn from(set: SSetuidSet) -> Self {
        SUserEither::UserSelector(set)
    }
}

impl From<&str> for SUserEither {
    fn from(name: &str) -> Self {
        SUserEither::MandatoryUser(name.into())
    }
}

impl From<u32> for SUserEither {
    fn from(id: u32) -> Self {
        SUserEither::MandatoryUser(id.into())
    }
}

#[derive(Deserialize, Debug, Clone, Builder, PartialEq, Eq)]

pub struct SSetuidSet {
    #[serde(
        alias = "d",
        rename = "default",
        default,
        skip_serializing_if = "is_default"
    )]
    #[builder(default)]
    pub default: SetBehavior,
    #[builder(into)]
    #[serde(alias = "f", skip_serializing_if = "Option::is_none")]
    pub fallback: Option<SUserType>,
    #[serde(default, alias = "a", skip_serializing_if = "Vec::is_empty")]
    #[builder(default, with = FromIterator::from_iter)]
    pub add: Vec<SUserType>,
    #[serde(
        default,
        alias = "del",
        alias = "s",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[builder(default, with = FromIterator::from_iter)]
    pub sub: Vec<SUserType>,
}

#[derive(PartialEq, Eq, Display, Debug, EnumIs, Clone, Copy, FromRepr, EnumString)]
#[strum(serialize_all = "lowercase")]
#[derive(Default)]
#[repr(u32)]
pub enum SetBehavior {
    #[default]
    None = HARDENED_ENUM_VALUE_0,
    All = HARDENED_ENUM_VALUE_1,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum SGroupsEither {
    MandatoryGroup(SGroupType),
    MandatoryGroups(SGroups),
    GroupSelector(SSetgidSet),
}

impl From<SGroups> for SGroupsEither {
    fn from(group: SGroups) -> Self {
        SGroupsEither::MandatoryGroups(group)
    }
}

impl From<SSetgidSet> for SGroupsEither {
    fn from(set: SSetgidSet) -> Self {
        SGroupsEither::GroupSelector(set)
    }
}

impl From<&str> for SGroupsEither {
    fn from(name: &str) -> Self {
        SGroupsEither::MandatoryGroup(name.into())
    }
}

impl From<u32> for SGroupsEither {
    fn from(id: u32) -> Self {
        SGroupsEither::MandatoryGroup(id.into())
    }
}

#[derive(Debug, Clone, Builder, PartialEq, Eq)]
pub struct SSetgidSet {
    #[builder(start_fn)]
    pub default_behavior: SetBehavior,
    #[builder(start_fn, into)]
    pub fallback: SGroups,
    #[builder(default, with = FromIterator::from_iter)]
    pub add: Vec<SGroups>,
    #[builder(default, with = FromIterator::from_iter)]
    pub sub: Vec<SGroups>,
}

#[derive(PartialEq, Eq, Debug, Builder, Default)]
#[cfg_attr(test, derive(Clone))]
pub struct SCapabilities {
    #[builder(start_fn)]
    pub default_behavior: SetBehavior,
    #[builder(field)]
    pub add: CapSet,
    #[builder(field)]
    pub sub: CapSet,
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum SCommand {
    Simple(String),
    Complex(Value),
}

#[cfg_attr(test, derive(Clone))]
#[derive(PartialEq, Eq, Debug, Default)]
pub struct SCommands {
    pub default: Option<SetBehavior>,
    pub add: Vec<SCommand>,
    pub sub: Vec<SCommand>,
    pub _extra_fields: Map<String, Value>,
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
        #[builder(with = |f : impl Fn(OptBuilder) -> Opt | rc_refcell!(f(Opt::builder(Level::Global))))]
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
    pub fn actors(mut self, actors: impl IntoIterator<Item = SActor>) -> Self {
        self.actors.extend(actors);
        self
    }
    pub fn tasks(mut self, tasks: impl IntoIterator<Item = Rc<RefCell<STask>>>) -> Self {
        self.tasks.extend(tasks);
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
        #[builder(with = |f : impl Fn(OptBuilder) -> Opt | rc_refcell!(f(Opt::builder(Level::Role))))]
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
        #[builder(with = |f : impl Fn(OptBuilder) -> Opt | rc_refcell!(f(Opt::builder(Level::Task))))]
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
        #[builder(start_fn)] default: SetBehavior,
        #[builder(default, with = FromIterator::from_iter)] add: Vec<SCommand>,
        #[builder(default, with = FromIterator::from_iter)] sub: Vec<SCommand>,
        #[builder(default, with = <_>::from_iter)] _extra_fields: Map<String, Value>,
    ) -> Self {
        SCommands {
            default: Some(default),
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

/* Confusing
impl PartialEq<str> for SUserChooser {
    fn eq(&self, other: &str) -> bool {
        match self {
            SUserChooser::Actor(actor) => actor == &SUserType::from(other),
            SUserChooser::ChooserStruct(chooser) => chooser.fallback.as_ref().is_some_and(|f| *f == *other),
        }
    }
}*/

#[cfg(test)]
mod tests {

    use capctl::Cap;
    use chrono::Duration;
    use linked_hash_set::LinkedHashSet;

    use crate::{
        as_borrow,
        database::{
            actor::SGroupType,
            options::{
                EnvBehavior, PathBehavior, SAuthentication, SBounding, SEnvOptions, SPathOptions,
                SPrivileged, STimeout, TimestampType,
            },
        },
    };

    use super::*;

    #[test]
    fn test_deserialize() {
        let config = r#"
        {
            "options": {
                "path": {
                    "default": "delete",
                    "add": ["path_add"],
                    "sub": ["path_sub"]
                },
                "env": {
                    "default": "delete",
                    "override_behavior": true,
                    "keep": ["keep_env"],
                    "check": ["check_env"]
                },
                "root": "privileged",
                "bounding": "ignore",
                "authentication": "skip",
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
                                    "add": ["user2"],
                                    "sub": ["user3"]
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
        let config: SConfig = serde_json::from_str(config).unwrap();
        let options = config.options.as_ref().unwrap().as_ref().borrow();
        let path = options.path.as_ref().unwrap();
        assert_eq!(path.default_behavior, PathBehavior::Delete);
        let default = LinkedHashSet::new();
        assert!(path
            .add
            .as_ref()
            .unwrap_or(&default)
            .front()
            .is_some_and(|s| s == "path_add"));
        let env = options.env.as_ref().unwrap();
        assert_eq!(env.default_behavior, EnvBehavior::Delete);
        assert!(env.override_behavior.is_some_and(|b| b));
        assert!(env
            .keep
            .as_ref()
            .unwrap_or(&LinkedHashSet::new())
            .front()
            .is_some_and(|s| s == "keep_env"));
        assert!(env
            .check
            .as_ref()
            .unwrap_or(&LinkedHashSet::new())
            .front()
            .is_some_and(|s| s == "check_env"));
        assert!(options.root.as_ref().unwrap().is_privileged());
        assert!(options.bounding.as_ref().unwrap().is_ignore());
        assert_eq!(options.authentication, Some(SAuthentication::Skip));

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
        let setuidstruct = SSetuidSet::builder()
            .fallback("user1")
            .default(SetBehavior::All)
            .add(["user2".into()])
            .sub(["user3".into()])
            .build();
        assert!(
            matches!(cred.setuid.as_ref().unwrap(), SUserEither::UserSelector(set) if set == &setuidstruct)
        );
        assert_eq!(
            *cred.setgid.as_ref().unwrap(),
            SGroupsEither::MandatoryGroup(SGroupType::from("setgid1"))
        );

        let capabilities = cred.capabilities.as_ref().unwrap();
        assert_eq!(capabilities.default_behavior, SetBehavior::All);
        assert!(capabilities.add.has(Cap::NET_BIND_SERVICE));
        assert!(capabilities.sub.has(Cap::SYS_ADMIN));
        let commands = &as_borrow!(&role[0]).commands;
        assert_eq!(*commands.default.as_ref().unwrap(), SetBehavior::All);
        assert_eq!(commands.add[0], SCommand::Simple("cmd1".into()));
        assert_eq!(commands.sub[0], SCommand::Simple("cmd2".into()));
    }
    #[test]
    fn test_unknown_fields() {
        let config = r#"
        {
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
                                    "sub": ["cap_dac_override"]
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
        let commands = &as_borrow!(role[0]).commands;
        assert_eq!(commands._extra_fields.get("unknown").unwrap(), "unknown");
    }

    #[test]
    fn test_deserialize_alias() {
        let config = r#"
        {
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
        let default = LinkedHashSet::new();
        assert!(path
            .add
            .as_ref()
            .unwrap_or(&default)
            .front()
            .is_some_and(|s| s == "path_add"));
        let env = options.env.as_ref().unwrap();
        assert_eq!(env.default_behavior, EnvBehavior::Delete);
        assert!(env
            .keep
            .as_ref()
            .unwrap()
            .front()
            .is_some_and(|s| s == "keep_env"));
        assert!(env
            .check
            .as_ref()
            .unwrap()
            .front()
            .is_some_and(|s| s == "check_env"));
        assert!(options.root.as_ref().unwrap().is_privileged());
        assert!(options.bounding.as_ref().unwrap().is_ignore());
        assert_eq!(options.authentication, Some(SAuthentication::Skip));

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
            &SUserEither::from(SUserType::from("setuid1"))
        );
        assert_eq!(
            *cred.setgid.as_ref().unwrap(),
            SGroupsEither::MandatoryGroup(SGroupType::from("setgid1"))
        );

        let capabilities = cred.capabilities.as_ref().unwrap();
        assert_eq!(capabilities.default_behavior, SetBehavior::None);
        assert!(capabilities.add.has(Cap::NET_BIND_SERVICE));
        assert!(capabilities.sub.is_empty());
        let commands = &as_borrow!(&role[0]).commands;
        assert_eq!(*commands.default.as_ref().unwrap(), SetBehavior::All);
        assert_eq!(commands.add[0], SCommand::Simple("cmd1".into()));
        assert_eq!(commands.sub[0], SCommand::Simple("cmd2".into()));
    }

    #[test]
    fn test_serialize() {
        let config = SConfig::builder()
            .role(
                SRole::builder("role1")
                    .actor(SActor::user("user1").build())
                    .actor(
                        SActor::group([SGroupType::from("group1"), SGroupType::from(1000)]).build(),
                    )
                    .task(
                        STask::builder("task1")
                            .purpose("purpose1".into())
                            .cred(
                                SCredentials::builder()
                                    .setuid(SUserEither::UserSelector(
                                        SSetuidSet::builder()
                                            .fallback("user1")
                                            .default(SetBehavior::All)
                                            .add(["user2".into()])
                                            .sub(["user3".into()])
                                            .build(),
                                    ))
                                    .setgid(SGroupsEither::MandatoryGroup(SGroupType::from(
                                        "setgid1",
                                    )))
                                    .capabilities(
                                        SCapabilities::builder(SetBehavior::All)
                                            .add_cap(Cap::NET_BIND_SERVICE)
                                            .sub_cap(Cap::SYS_ADMIN)
                                            .build(),
                                    )
                                    .build(),
                            )
                            .commands(
                                SCommands::builder(SetBehavior::All)
                                    .add(["cmd1".into()])
                                    .sub(["cmd2".into()])
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .options(|opt| {
                opt.path(
                    SPathOptions::builder(PathBehavior::Delete)
                        .add(["path_add"])
                        .sub(["path_sub"])
                        .build(),
                )
                .env(
                    SEnvOptions::builder(EnvBehavior::Delete)
                        .override_behavior(true)
                        .keep(["keep_env"])
                        .unwrap()
                        .check(["check_env"])
                        .unwrap()
                        .build(),
                )
                .root(SPrivileged::Privileged)
                .bounding(SBounding::Ignore)
                .authentication(SAuthentication::Skip)
                .timeout(
                    STimeout::builder()
                        .type_field(TimestampType::PPID)
                        .duration(Duration::minutes(5))
                        .build(),
                )
                .build()
            })
            .build();
        serde_json::to_string_pretty(&config).unwrap();
    }

    #[test]
    fn test_serialize_operride_behavior_option() {
        let config = SConfig::builder()
            .options(|opt| {
                opt.env(
                    SEnvOptions::builder(EnvBehavior::Inherit)
                        .override_behavior(true)
                        .build(),
                )
                .build()
            })
            .build();
        let config = serde_json::to_string(&config).unwrap();
        assert_eq!(
            config,
            "{\"options\":{\"env\":{\"override_behavior\":true}}}"
        );
    }
}
