use bon::{bon, builder, Builder};
use capctl::{Cap, CapSet};
use derivative::Derivative;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Value};
use strum::{Display, EnumIs, EnumString, FromRepr};

use std::{
    cell::RefCell,
    error::Error,
    fmt,
    ops::{Index, Not},
    rc::{Rc, Weak},
};

use crate::rc_refcell;

use super::{
    actor::{SActor, SGroups, SUserType},
    is_default,
    options::{Level, Opt, OptBuilder},
};

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
pub struct SConfig {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "sconfig_opt"
    )]
    pub options: Option<Rc<RefCell<Opt>>>,
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
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actors: Vec<SActor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tasks: Vec<Rc<RefCell<STask>>>,
    #[serde(
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
    let mut opt = Opt::deserialize(deserializer)?;
    opt.level = Level::Role;
    Ok(Some(Rc::new(RefCell::new(opt))))
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
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

fn cmds_is_default(cmds: &SCommands) -> bool {
    cmds.default_behavior.as_ref().is_none_or(|b| *b == Default::default())
        && cmds.add.is_empty()
        && cmds.sub.is_empty()
        && cmds._extra_fields.is_empty()
}

#[derive(Deserialize, Debug, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct STask {
    #[serde(alias="n", default, skip_serializing_if = "IdTask::is_number")]
    pub name: IdTask,
    #[serde(alias="p", skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(alias="i", default, skip_serializing_if = "is_default")]
    pub cred: SCredentials,
    #[serde(alias="c", default, skip_serializing_if = "cmds_is_default")]
    pub commands: SCommands,
    #[serde(
        alias="o",
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
    let mut opt = Opt::deserialize(deserializer)?;
    opt.level = Level::Task;
    Ok(Some(Rc::new(RefCell::new(opt))))
}

#[derive(Deserialize, Debug, Builder, PartialEq, Eq)]
 #[serde(rename_all = "kebab-case")]
pub struct SCredentials {
    #[serde(alias="d", skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub setuid: Option<SUserChooser>,
    #[serde(alias="1", skip_serializing_if = "Option::is_none")]
    #[builder(into)]
    pub setgid: Option<SGroupschooser>,
    #[serde(default, alias="2", skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<SCapabilities>,
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

#[derive(Deserialize, Debug, Clone, Builder, PartialEq, Eq)]

pub struct SSetuidSet {
    #[serde(alias="d", rename = "default", default, skip_serializing_if = "is_default")]
    #[builder(default)]
    pub default: SetBehavior,
    #[builder(into)]
    #[serde(alias="1", skip_serializing_if = "Option::is_none")]
    pub fallback: Option<SUserType>,
    #[serde(default, alias="2", skip_serializing_if = "Vec::is_empty")]
    #[builder(default, with = FromIterator::from_iter)]
    pub add: Vec<SUserType>,
    #[serde(default, alias="del", alias="3", skip_serializing_if = "Vec::is_empty")]
    #[builder(default, with = FromIterator::from_iter)]
    pub sub: Vec<SUserType>,
}

#[derive(PartialEq, Eq, Display, Debug, EnumIs, Clone, Copy, FromRepr, EnumString)]
#[strum(serialize_all = "lowercase")]
#[derive(Default)]
#[repr(u8)]
pub enum SetBehavior {
    #[default]
    None,
    All,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum SGroupschooser {
    Group(SGroups),
    StructChooser(SSetgidSet),
}

impl From<SGroups> for SGroupschooser {
    fn from(group: SGroups) -> Self {
        SGroupschooser::Group(group)
    }
}

impl From<SSetgidSet> for SGroupschooser {
    fn from(set: SSetgidSet) -> Self {
        SGroupschooser::StructChooser(set)
    }
}

impl From<&str> for SGroupschooser {
    fn from(name: &str) -> Self {
        SGroupschooser::Group(name.into())
    }
}

impl From<u32> for SGroupschooser {
    fn from(id: u32) -> Self {
        SGroupschooser::Group(id.into())
    }
}

#[derive(Deserialize, Debug, Clone, Builder, PartialEq, Eq)]
pub struct SSetgidSet {

    #[serde(rename = "default", alias = "d", default, skip_serializing_if = "is_default")]
    #[builder(start_fn)]
    pub default: SetBehavior,
    #[serde(alias="f")]
    #[builder(start_fn, into)]
    pub fallback: SGroups,
    #[serde(default, alias="a", skip_serializing_if = "Vec::is_empty")]
    #[builder(default, with = FromIterator::from_iter)]
    pub add: Vec<SGroups>,
    #[serde(default, alias="s", skip_serializing_if = "Vec::is_empty")]
    #[builder(default, with = FromIterator::from_iter)]
    pub sub: Vec<SGroups>,
}

#[derive(PartialEq, Eq, Debug, Builder)]
pub struct SCapabilities {
    #[builder(start_fn)]
    pub default_behavior: SetBehavior,
    #[builder(field)]
    pub add: CapSet,
    #[builder(field)]
    pub sub: CapSet
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

impl Serialize for SetBehavior {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            return serializer.serialize_str(&self.to_string());
        } else {
            return serializer.serialize_u8(*self as u8);
        }
    }
}

impl<'de> Deserialize<'de> for SetBehavior {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SetBehaviorVisitor;

        impl<'de> Visitor<'de> for SetBehaviorVisitor {
            type Value = SetBehavior;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or a number")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse().map_err(de::Error::custom)
            }
            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
                where
                    E: de::Error, {
                if v > 1 || v < 0 {
                    return Err(de::Error::custom(format!(
                        "Invalid value for SetBehavior: {}",
                        v
                    )));
                }
                SetBehavior::from_repr(v as u8).ok_or(de::Error::custom(format!(
                    "Invalid value for SetBehavior: {}",
                    v
                )))
            }
            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
                where
                    E: de::Error, {
                self.visit_i32(v as i32)
            }
            fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
                where
                    E: de::Error, {
                self.visit_i32(v as i32)
            }
            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
                where
                    E: de::Error, {
                self.visit_i32(v as i32)
            }
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
                where
                    E: de::Error, {
                if v > i32::MAX as u64 {
                    return Err(de::Error::custom(format!(
                        "Invalid value for SetBehavior: {}",
                        v
                    )));
                }
                self.visit_i32(v as i32)
            }
            fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
                where
                    E: de::Error, {
                self.visit_i32(v as i32)
            }
            fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
                where
                    E: de::Error, {
                self.visit_i32(v as i32)
            }
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
                where
                    E: de::Error, {
                if v > i32::MAX as i64 || v < i32::MIN as i64 {
                    return Err(de::Error::custom(format!(
                        "Invalid value for SetBehavior: {}",
                        v
                    )));
                }
                self.visit_i32(v as i32)
            }
        }

        deserializer.deserialize_any(SetBehaviorVisitor)
    }
}

impl Serialize for SSetuidSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("default", &self.default)?;
            if let Some(fallback) = &self.fallback {
                map.serialize_entry("fallback", fallback)?;
            }
            if !self.add.is_empty() {
                let v: Vec<String> = self.add.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("add", &v)?;
            }
            if !self.sub.is_empty() {
                let v: Vec<String> = self.sub.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("del", &v)?;
            }
            map.end()
        } else {

            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("d", &(self.default as u8))?;
            if let Some(fallback) = &self.fallback {
                map.serialize_entry("f", fallback)?;
            }
            if !self.add.is_empty() {
                let v: Vec<String> = self.add.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("a", &v)?;
            }
            if !self.sub.is_empty() {
                let v: Vec<String> = self.sub.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("s", &v)?;
            }
            map.end()
        }
    }
}

impl Serialize for SSetgidSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.default.is_none() && self.sub.is_empty() {
            let mut seq = serializer.serialize_seq(Some(self.add.len()))?;
            for sgroups in &self.add {
                seq.serialize_element(sgroups)?;
            }
            seq.end()
        }else if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("default", &self.default)?;
            if !self.fallback.is_empty() {
                map.serialize_entry("fallback", &self.fallback)?;
            }
            if !self.add.is_empty() {
                let v: Vec<String> = self.add.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("add", &v)?;
            }
            if !self.sub.is_empty() {
                let v: Vec<String> = self.sub.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("del", &v)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("d", &(self.default as u8))?;
            if !self.fallback.is_empty() {
                map.serialize_entry("f", &self.fallback)?;
            }
            
            if !self.add.is_empty() {
                let v: Vec<String> = self.add.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("a", &v)?;
            }
            if !self.sub.is_empty() {
                let v: Vec<String> = self.sub.iter().map(|cap| cap.to_string()).collect();
                map.serialize_entry("s", &v)?;
            }
            map.end()
        }
    }
}

impl Serialize for SCapabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.default_behavior.is_none() && self.sub.is_empty() {
            super::serialize_capset(&self.add, serializer)
        } else {
            if serializer.is_human_readable() {
                let mut map = serializer.serialize_map(Some(3))?;
                if self.default_behavior.is_all() {
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
                map.end()
            } else {
                let mut map = serializer.serialize_map(Some(3))?;
                if self.default_behavior.is_all() {
                    map.serialize_entry("d", &(self.default_behavior as u8))?;
                }
                if !self.add.is_empty() {
                    let v: Vec<String> = self.add.iter().map(|cap| cap.to_string()).collect();
                    map.serialize_entry("a", &v)?;
                }
                if !self.sub.is_empty() {
                    let v: Vec<String> = self.sub.iter().map(|cap| cap.to_string()).collect();
                    map.serialize_entry("s", &v)?;
                }
                map.end()
            }

        }
    }
}

impl Serialize for SCredentials {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            if self.setuid.is_some() {
                map.serialize_entry("setuid", &self.setuid)?;
            }
            if self.setgid.is_some() {
                map.serialize_entry("setgid", &self.setgid)?;
            }
            if self.capabilities.is_some() {
                map.serialize_entry("capabilities", &self.capabilities)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            if self.setuid.is_some() {
                map.serialize_entry("u", &self.setuid)?;
            }
            if self.setgid.is_some() {
                map.serialize_entry("g", &self.setgid)?;
            }
            if self.capabilities.is_some() {
                map.serialize_entry("c", &self.capabilities)?;
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

        #[derive(Deserialize, Display)]
        #[serde(rename_all = "kebab-case")]
        #[repr(u8)]
        enum Field {
            #[serde(alias = "d")]
            Default,
            #[serde(alias = "a")]
            Add,
            #[serde(rename = "del", alias = "s")]
            Sub,
            #[serde(untagged)]
            Other(String),
        }

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

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Default => {
                            default_behavior = map
                                .next_value()
                                .expect("default entry must be either 'all' or 'none'");
                        }
                        Field::Add => {
                            let values: Vec<String> =
                                map.next_value().expect("add entry must be a list");
                            for value in values {
                                add.add(value.parse().map_err(|_| {
                                    de::Error::custom(format!("Invalid capability: {}", value))
                                })?);
                            }
                        }
                        Field::Sub => {
                            let values: Vec<String> =
                                map.next_value().expect("sub entry must be a list");
                            for value in values {
                                sub.add(value.parse().map_err(|_| {
                                    de::Error::custom(format!("Invalid capability: {}", value))
                                })?);
                            }
                        }
                        Field::Other(other) => {
                            _extra_fields.insert(other.to_string(), map.next_value()?);
                        }
                    }
                }

                Ok(SCapabilities {
                    default_behavior,
                    add,
                    sub,
                })
            }
        }

        deserializer.deserialize_any(SCapabilitiesVisitor)
    }
}


impl Serialize for STask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("name", &self.name)?;
            if let Some(purpose) = &self.purpose {
                map.serialize_entry("purpose", purpose)?;
            }
            if !is_default(&self.cred) {
                map.serialize_entry("cred", &self.cred)?;
            }
            if !cmds_is_default(&self.commands) {
                map.serialize_entry("commands", &self.commands)?;
            }
            if let Some(options) = &self.options {
                map.serialize_entry("options", options)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("n", &self.name)?;
            if let Some(purpose) = &self.purpose {
                map.serialize_entry("p", purpose)?;
            }
            if !is_default(&self.cred) {
                map.serialize_entry("i", &self.cred)?;
            }
            if !cmds_is_default(&self.commands) {
                map.serialize_entry("c", &self.commands)?;
            }
            if let Some(options) = &self.options {
                map.serialize_entry("o", options)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum SCommand {
    Simple(String),
    Complex(Value),
}

#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct SCommands {
    #[serde(rename = "default", alias = "d")]
    pub default_behavior: Option<SetBehavior>,
    #[serde(default, alias = "a", skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<SCommand>,
    #[serde(default, alias = "del", alias = "s", skip_serializing_if = "Vec::is_empty")]
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
        }
    }
}

impl Default for SSetuidSet {
    fn default() -> Self {
        SSetuidSet::builder().build()
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
        #[builder(with = |f : fn(OptBuilder) -> Opt | rc_refcell!(f(Opt::builder(Level::Global))))]
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
        #[builder(with = |f : fn(OptBuilder) -> Opt | rc_refcell!(f(Opt::builder(Level::Role))))]
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
        #[builder(with = |f : fn(OptBuilder) -> Opt | rc_refcell!(f(Opt::builder(Level::Task))))]
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

impl Serialize for SCommands {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        if self.sub.is_empty() && self._extra_fields.is_empty() {
            if self.add.is_empty() {
                return serializer.serialize_bool(self.default_behavior.as_ref().is_some_and(|b| *b == SetBehavior::All));
            } else if !self.add.is_empty() && self.default_behavior.as_ref().is_none_or(|b| *b == SetBehavior::None) {
                let mut seq = serializer.serialize_seq(Some(self.add.len()))?;
                for cmd in &self.add {
                    seq.serialize_element(cmd)?;
                }
                return seq.end()
            }
        }
        if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(Some(3))?;
            if self.default_behavior.is_none() {
                map.serialize_entry("default", &self.default_behavior)?;
            }
            if !self.add.is_empty() {
                map.serialize_entry("add", &self.add)?;
            }
            if !self.sub.is_empty() {
                map.serialize_entry("del", &self.sub)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(Some(3))?;
            if let Some(behavior) = &self.default_behavior {
                map.serialize_entry("d", &(*behavior as u8))?;
            }
            if !self.add.is_empty() {
                map.serialize_entry("a", &self.add)?;
            }
            if !self.sub.is_empty() {
                map.serialize_entry("s", &self.sub)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
        
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
        println!("START");
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
        println!("STEP 1");
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
        let setuidstruct = SSetuidSet::builder()
            .fallback("user1")
            .default(SetBehavior::All)
            .add(["user2".into()])
            .sub(["user3".into()])
            .build();
        assert!(
            matches!(cred.setuid.as_ref().unwrap(), SUserChooser::ChooserStruct(set) if set == &setuidstruct)
        );
        assert_eq!(
            *cred.setgid.as_ref().unwrap(),
            SGroupschooser::Group(SGroups::from("setgid1"))
        );

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
        assert_eq!(
            *cred.setgid.as_ref().unwrap(),
            SGroupschooser::Group(SGroups::from("setgid1"))
        );

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
                                    .setuid(SUserChooser::ChooserStruct(
                                        SSetuidSet::builder()
                                            .fallback("user1")
                                            .default(SetBehavior::All)
                                            .add(["user2".into()])
                                            .sub(["user3".into()])
                                            .build(),
                                    ))
                                    .setgid(SGroupschooser::Group(SGroups::from("setgid1")))
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
                .wildcard_denied("wildcards")
                .timeout(
                    STimeout::builder()
                        .type_field(TimestampType::PPID)
                        .duration(Duration::minutes(5))
                        .build(),
                )
                .build()
            })
            .build();
        let config = serde_json::to_string_pretty(&config).unwrap();
        println!("{}", config);
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
