use capctl::CapSet;
use derivative::Derivative;
use nix::{
    errno::Errno,
    unistd::{Group, User},
};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Value};
use strum::{Display, EnumIs};

use std::{
    cell::RefCell,
    cmp::Ordering,
    error::Error,
    fmt,
    ops::{Index, Not},
    rc::{Rc, Weak},
};

use crate::common::database::is_default;

use super::{
    options::Opt,
    wrapper::{OptWrapper, STaskWrapper},
};

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
pub struct SConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: OptWrapper,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<Rc<RefCell<SRole>>>,
    #[serde(skip)]
    storage: (),
    #[serde(default)]
    #[serde(flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: OptWrapper,
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
    #[serde(skip)]
    #[derivative(PartialEq = "ignore")]
    pub _config: Option<Weak<RefCell<SConfig>>>,
}

#[derive(Serialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged, rename_all = "lowercase")]
pub enum SActorType {
    Id(u32),
    Name(String),
}

impl std::fmt::Display for SActorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SActorType::Id(id) => write!(f, "{}", id),
            SActorType::Name(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, EnumIs)]
#[serde(untagged)]
pub enum SGroups {
    Single(SActorType),
    Multiple(Vec<SActorType>),
}

impl SGroups {
    pub fn len(&self) -> usize {
        match self {
            SGroups::Single(_) => 1,
            SGroups::Multiple(groups) => groups.len(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SActor {
    #[serde(rename = "user")]
    User {
        #[serde(alias = "name", skip_serializing_if = "Option::is_none")]
        id: Option<SActorType>,
        #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
        _extra_fields: Map<String, Value>,
    },
    #[serde(rename = "group")]
    Group {
        #[serde(alias = "names", skip_serializing_if = "Option::is_none")]
        groups: Option<SGroups>,
        #[serde(default, flatten)]
        _extra_fields: Map<String, Value>,
    },
    #[serde(untagged)]
    Unknown(Value),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: OptWrapper,
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
    #[serde(skip)]
    #[derivative(PartialEq = "ignore")]
    pub _role: Option<Weak<RefCell<SRole>>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct SCredentials {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setuid: Option<SActorType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setgid: Option<SGroups>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<SCapabilities>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additional_auth: Option<String>, // TODO: to extract as plugin
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Display, Debug, EnumIs)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SetBehavior {
    All,
    #[default]
    None,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct SCapabilities {
    #[serde(rename = "default", default, skip_serializing_if = "is_default")]
    pub default_behavior: SetBehavior,
    #[serde(
        default,
        skip_serializing_if = "CapSet::is_empty",
        deserialize_with = "super::deserialize_capset",
        serialize_with = "super::serialize_capset"
    )]
    pub add: CapSet,
    #[serde(
        default,
        skip_serializing_if = "CapSet::is_empty",
        deserialize_with = "super::deserialize_capset",
        serialize_with = "super::serialize_capset"
    )]
    pub sub: CapSet,
    #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
    pub _extra_fields: Map<String, Value>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
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
            storage: (),
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

impl Default for IdTask {
    fn default() -> Self {
        IdTask::Number(0)
    }
}

// ------------------------
// From implementations
// ------------------------

impl From<u32> for SActorType {
    fn from(id: u32) -> Self {
        SActorType::Id(id)
    }
}

impl From<String> for SActorType {
    fn from(name: String) -> Self {
        SActorType::Name(name)
    }
}

impl From<&str> for SActorType {
    fn from(name: &str) -> Self {
        SActorType::Name(name.to_string())
    }
}

impl From<&str> for SCommand {
    fn from(name: &str) -> Self {
        SCommand::Simple(name.to_string())
    }
}

impl From<CapSet> for SCapabilities {
    fn from(capset: CapSet) -> Self {
        let mut c = SCapabilities::default();
        c.add = capset;
        c
    }
}

// ------------------------
// Deserialize
// ------------------------

// This try to deserialize a number as an ID and a string as a name
impl<'de> Deserialize<'de> for SActorType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IdVisitor;

        impl<'de> Visitor<'de> for IdVisitor {
            type Value = SActorType;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("user ID as a number or string")
            }

            fn visit_u32<E>(self, id: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SActorType::Id(id))
            }

            fn visit_str<E>(self, id: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let rid: Result<u32, _> = id.parse();
                match rid {
                    Ok(id) => Ok(SActorType::Id(id)),
                    Err(_) => Ok(SActorType::Name(id.to_string())),
                }
            }
        }

        deserializer.deserialize_any(IdVisitor)
    }
}

// ========================
// Implementations for Struct navigation
// ========================

impl SConfig {
    pub fn role(&self, name: &str) -> Option<&Rc<RefCell<SRole>>> {
        self.roles.iter().find(|role| role.borrow().name == name)
    }
    pub fn task(&self, role: &str, name: &IdTask) -> Result<Rc<RefCell<STask>>, Box<dyn Error>> {
        self.role(role)
            .and_then(|role| role.as_ref().borrow().task(name).cloned())
            .ok_or_else(|| format!("Task {} not found in role {}", name, role).into())
    }
}

impl SRole {
    pub fn new(name: String, config: Weak<RefCell<SConfig>>) -> Self {
        let mut ret = SRole::default();
        ret.name = name;
        ret._config = Some(config);
        ret
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

impl STask {
    pub fn new(name: IdTask, role: Weak<RefCell<SRole>>) -> Self {
        let mut ret = STask::default();
        ret.name = name;
        ret._role = Some(role);
        ret
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

// =================
// Display implementations
// =================

impl core::fmt::Display for SActor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SActor::User { id, _extra_fields } => {
                write!(f, "User: {}", id.as_ref().unwrap())
            }
            SActor::Group {
                groups,
                _extra_fields,
            } => {
                write!(f, "Group: {}", groups.as_ref().unwrap())
            }
            SActor::Unknown(unknown) => {
                write!(f, "Unknown: {}", unknown)
            }
        }
    }
}

impl core::fmt::Display for SGroups {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SGroups::Single(group) => {
                write!(f, "{}", group)
            }
            SGroups::Multiple(groups) => {
                write!(f, "{:?}", groups)
            }
        }
    }
}

// =================
// Other implementations
// =================

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

impl PartialEq<str> for SActorType {
    fn eq(&self, other: &str) -> bool {
        match self {
            SActorType::Name(name) => name == other,
            SActorType::Id(id) => other.parse().map(|oid: u32| oid == *id).unwrap_or(false),
        }
    }
}

impl PartialEq<User> for SActorType {
    fn eq(&self, other: &User) -> bool {
        match self {
            SActorType::Name(name) => name == &other.name,
            SActorType::Id(id) => other.uid.as_raw() == *id,
        }
    }
}

impl PartialEq<Group> for SActorType {
    fn eq(&self, other: &Group) -> bool {
        match self {
            SActorType::Name(name) => name == &other.name,
            SActorType::Id(id) => other.gid.as_raw() == *id,
        }
    }
}

impl PartialEq<str> for SGroups {
    fn eq(&self, other: &str) -> bool {
        match self {
            SGroups::Single(actor) => actor == other,
            SGroups::Multiple(actors) => actors.len() == 1 && &actors[0] == other,
        }
    }
}

impl PartialEq<Vec<SActorType>> for SGroups {
    fn eq(&self, other: &Vec<SActorType>) -> bool {
        match self {
            SGroups::Single(actor) => {
                if other.len() == 1 {
                    return actor == &other[0];
                }
            }
            SGroups::Multiple(actors) => {
                if actors.len() == other.len() {
                    return actors.iter().all(|actor| other.iter().any(|x| actor == x));
                }
            }
        }
        false
    }
}

impl FromIterator<String> for SGroups {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        let mut iter = iter.into_iter();
        let first = iter.next().unwrap();
        let mut groups = vec![SActorType::Name(first)];
        for group in iter {
            groups.push(SActorType::Name(group));
        }
        if groups.len() == 1 {
            SGroups::Single(groups[0].to_owned())
        } else {
            SGroups::Multiple(groups)
        }
    }
}

impl From<SGroups> for Vec<SActorType> {
    fn from(val: SGroups) -> Self {
        match val {
            SGroups::Single(group) => vec![group],
            SGroups::Multiple(groups) => groups,
        }
    }
}

impl SActorType {
    pub fn into_group(&self) -> Result<Option<Group>, Errno> {
        match self {
            SActorType::Name(name) => Group::from_name(name),
            SActorType::Id(id) => Group::from_gid(id.to_owned().into()),
        }
    }
    pub fn into_user(&self) -> Result<Option<User>, Errno> {
        match self {
            SActorType::Name(name) => User::from_name(name),
            SActorType::Id(id) => User::from_uid(id.to_owned().into()),
        }
    }
}

impl PartialOrd<SGroups> for SGroups {
    fn partial_cmp(&self, other: &SGroups) -> Option<std::cmp::Ordering> {
        let other = Into::<Vec<SActorType>>::into(other.clone());
        self.partial_cmp(&other)
    }
}

impl PartialOrd<Vec<SActorType>> for SGroups {
    fn partial_cmp(&self, other: &Vec<SActorType>) -> Option<std::cmp::Ordering> {
        match self {
            SGroups::Single(group) => {
                if other.len() == 1 {
                    if group == &other[0] {
                        return Some(Ordering::Equal);
                    }
                } else if other.iter().any(|x| group == x) {
                    return Some(Ordering::Less);
                }
            }
            SGroups::Multiple(groups) => {
                if groups.len() == other.len() {
                    if groups.iter().all(|x| other.iter().any(|y| x == y)) {
                        return Some(Ordering::Equal);
                    }
                } else if groups.len() < other.len() {
                    if groups.iter().all(|x| other.iter().any(|y| x == y)) {
                        return Some(Ordering::Less);
                    }
                } else if other.iter().all(|x| groups.iter().any(|y| y == x)) {
                    return Some(Ordering::Greater);
                }
            }
        }
        None
    }
}

impl From<SGroups> for Vec<Group> {
    fn from(val: SGroups) -> Self {
        match val {
            SGroups::Single(group) => vec![group.into_group().unwrap().unwrap()],
            SGroups::Multiple(groups) => groups
                .into_iter()
                .map(|x| x.into_group().unwrap().unwrap())
                .collect(),
        }
    }
}

impl SActor {
    pub fn from_user_string(user: &str) -> Self {
        SActor::User {
            id: Some(user.into()),
            _extra_fields: Map::default(),
        }
    }
    pub fn from_user_id(id: u32) -> Self {
        SActor::User {
            id: Some(id.into()),
            _extra_fields: Map::default(),
        }
    }
    pub fn from_group_string(group: &str) -> Self {
        SActor::Group {
            groups: Some(SGroups::Single(group.into())),
            _extra_fields: Map::default(),
        }
    }
    pub fn from_group_id(id: u32) -> Self {
        SActor::Group {
            groups: Some(SGroups::Single(id.into())),
            _extra_fields: Map::default(),
        }
    }
    pub fn from_group_vec_string(group: Vec<&str>) -> Self {
        Self::from_group_vec_actors(
            group
                .into_iter()
                .map(|str| str.into())
                .collect::<Vec<SActorType>>(),
        )
    }
    pub fn from_group_vec_id(groups: Vec<u32>) -> Self {
        Self::from_group_vec_actors(
            groups
                .into_iter()
                .map(|id| id.into())
                .collect::<Vec<SActorType>>(),
        )
    }
    pub fn from_group_vec_actors(groups: Vec<SActorType>) -> Self {
        SActor::Group {
            groups: Some(SGroups::Multiple(groups)),
            _extra_fields: Map::default(),
        }
    }
}

#[cfg(test)]
mod tests {

    use capctl::Cap;
    use chrono::Duration;

    use crate::{
        as_borrow,
        common::database::options::{EnvBehavior, PathBehavior, TimestampType},
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
                    assert_eq!(groups[0], SActorType::Name("group1".into()));
                    assert_eq!(groups[1], SActorType::Id(1000));
                }
                _ => panic!("unexpected actor group type"),
            },
            _ => panic!("unexpected actor {:?}", actor1),
        }
        let role = config.roles[0].as_ref().borrow();
        assert_eq!(as_borrow!(role[0]).purpose.as_ref().unwrap(), "purpose1");
        let cred = &as_borrow!(&role[0]).cred;
        assert_eq!(cred.setuid.as_ref().unwrap(), "setuid1");
        assert_eq!(cred.setgid.as_ref().unwrap(), "setgid1");
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
    fn test_sgroups_compare() {
        let single = SGroups::Single(SActorType::Name("single".into()));
        let multiple = SGroups::Multiple(vec![
            SActorType::Name("single".into()),
            SActorType::Id(1000),
        ]);
        assert!(single == single);
        assert!(single <= multiple);
        assert!(multiple >= single);
        assert!(multiple == multiple);
        let multiple2 = SGroups::Multiple(vec![
            SActorType::Name("single".into()),
            SActorType::Id(1001),
        ]);
        assert!(multiple != multiple2);
    }
}
