use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
};

use bon::bon;
use nix::unistd::{Group, User};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use strum::EnumIs;

use crate::util::{HARDENED_ENUM_VALUE_0, HARDENED_ENUM_VALUE_1};

#[derive(Serialize, Debug, EnumIs, Clone, PartialEq, Eq, strum::Display)]
#[serde(untagged, rename_all = "lowercase")]
pub enum SGenericActorType {
    Id(u32),
    Name(String),
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct SUserType(SGenericActorType);

#[derive(Deserialize, Serialize, Debug, EnumIs, Clone, PartialEq, Eq, strum::Display)]
#[serde(untagged, rename_all = "lowercase")]
pub enum DGenericActorType<'a> {
    Id(u32),
    #[serde(borrow)]
    Name(Cow<'a, str>),
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DUserType<'a>(#[serde(borrow)] DGenericActorType<'a>);

impl SUserType {
    pub fn fetch_id(&self) -> Option<u32> {
        match &self.0 {
            SGenericActorType::Id(id) => Some(*id),
            SGenericActorType::Name(name) => match User::from_name(name) {
                Ok(Some(user)) => Some(user.uid.as_raw()),
                _ => None,
            },
        }
    }
    pub fn fetch_user(&self) -> Option<User> {
        match &self.0 {
            SGenericActorType::Id(id) => User::from_uid((*id).into()).ok().flatten(),
            SGenericActorType::Name(name) => User::from_name(name).ok().flatten(),
        }
    }
    pub fn fetch_eq(&self, other: &Self) -> bool {
        let uid = self.fetch_id();
        let ouid = other.fetch_id();
        match (uid, ouid) {
            (Some(uid), Some(ouid)) => uid == ouid,
            _ => false,
        }
    }
}

impl DUserType<'_> {
    pub fn fetch_id(&self) -> Option<u32> {
        match &self.0 {
            DGenericActorType::Id(id) => Some(*id),
            DGenericActorType::Name(name) => match User::from_name(name) {
                Ok(Some(user)) => Some(user.uid.as_raw()),
                _ => None,
            },
        }
    }
}

impl fmt::Display for SUserType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self.0 {
            SGenericActorType::Id(id) => write!(f, "{}", id),
            SGenericActorType::Name(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct SGroupType(SGenericActorType);

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct DGroupType<'a>(#[serde(borrow)] DGenericActorType<'a>);

impl fmt::Display for SGroupType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self.0 {
            SGenericActorType::Id(id) => write!(f, "{}", id),
            SGenericActorType::Name(name) => write!(f, "{}", name),
        }
    }
}

impl SGroupType {
    pub fn fetch_eq(&self, other: &Self) -> bool {
        let uid = self.fetch_id();
        let ouid = other.fetch_id();
        match (uid, ouid) {
            (Some(uid), Some(ouid)) => uid == ouid,
            _ => false,
        }
    }
    pub(super) fn fetch_id(&self) -> Option<u32> {
        match &self.0 {
            SGenericActorType::Id(id) => Some(*id),
            SGenericActorType::Name(name) => match Group::from_name(name) {
                Ok(Some(group)) => Some(group.gid.as_raw()),
                _ => None,
            },
        }
    }
    pub fn fetch_group(&self) -> Option<Group> {
        match &self.0 {
            SGenericActorType::Id(id) => Group::from_gid((*id).into()).ok().flatten(),
            SGenericActorType::Name(name) => Group::from_name(name).ok().flatten(),
        }
    }
}

impl DGroupType<'_> {
    pub fn fetch_id(&self) -> Option<u32> {
        match &self.0 {
            DGenericActorType::Id(id) => Some(*id),
            DGenericActorType::Name(name) => match Group::from_name(name) {
                Ok(Some(group)) => Some(group.gid.as_raw()),
                _ => None,
            },
        }
    }
}

impl Display for DGroupType<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self.0 {
            DGenericActorType::Id(id) => write!(f, "{}", id),
            DGenericActorType::Name(name) => write!(f, "{}", name),
        }
    }
}
impl Display for DUserType<'_> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self.0 {
            DGenericActorType::Id(id) => write!(f, "{}", id),
            DGenericActorType::Name(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Serialize, PartialEq, Eq, Debug, Clone, EnumIs)]
#[serde(untagged)]
#[repr(u32)]
pub enum SGroups {
    Single(SGroupType) = HARDENED_ENUM_VALUE_0,
    Multiple(Vec<SGroupType>) = HARDENED_ENUM_VALUE_1,
}

impl Display for SGroups {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            SGroups::Single(group) => write!(f, "[{}]", group),
            SGroups::Multiple(groups) => {
                let mut result = String::new();
                for group in groups {
                    result.push_str(&format!("{}, ", group));
                }
                result.pop(); // Remove last comma
                result.pop(); // Remove last space
                write!(f, "[{}]", result)
            }
        }
    }
}

#[derive(Serialize, PartialEq, Eq, Debug, Clone, EnumIs, strum::Display)]
#[serde(untagged)]
pub enum DGroups<'a> {
    Single(#[serde(borrow)] DGroupType<'a>),
    Multiple(#[serde(borrow)] Cow<'a, [DGroupType<'a>]>),
}

impl SGroups {
    pub fn len(&self) -> usize {
        match self {
            SGroups::Single(_) => 1,
            SGroups::Multiple(groups) => groups.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn fetch_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SGroups::Single(group), SGroups::Single(ogroup)) => group.fetch_eq(ogroup),
            (SGroups::Multiple(groups), SGroups::Multiple(ogroups)) => groups
                .iter()
                .all(|group| ogroups.iter().any(|ogroup| group.fetch_eq(ogroup))),
            _ => false,
        }
    }
}

impl DGroups<'_> {
    pub fn len(&self) -> usize {
        match self {
            DGroups::Single(_) => 1,
            DGroups::Multiple(groups) => groups.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for DGroups<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DGroupsVisitor<'a> {
            marker: std::marker::PhantomData<&'a ()>,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for DGroupsVisitor<'a> {
            type Value = DGroups<'a>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or a number")
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(group) = v.parse() {
                    Ok(DGroups::Single(DGroupType(DGenericActorType::Id(group))))
                } else {
                    Ok(DGroups::Single(DGroupType(DGenericActorType::Name(
                        Cow::Borrowed(v),
                    ))))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(group) = v.parse() {
                    Ok(DGroups::Single(DGroupType(DGenericActorType::Id(group))))
                } else {
                    Ok(DGroups::Single(DGroupType(DGenericActorType::Name(
                        Cow::Owned(v.to_string()),
                    ))))
                }
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(group) = v.parse() {
                    Ok(DGroups::Single(DGroupType(DGenericActorType::Id(group))))
                } else {
                    Ok(DGroups::Single(DGroupType(DGenericActorType::Name(
                        v.into(),
                    ))))
                }
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value > u32::MAX as u64 {
                    return Err(E::custom("value is too large"));
                }
                Ok(DGroups::Single(DGroupType(DGenericActorType::Id(
                    value as u32,
                ))))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut groups = Vec::new();
                while let Some(group) = seq.next_element::<DGroupType<'a>>()? {
                    groups.push(group);
                }
                if groups.len() == 1 {
                    Ok(DGroups::Single(groups.remove(0)))
                } else {
                    Ok(DGroups::Multiple(Cow::Owned(groups)))
                }
            }
        }
        deserializer.deserialize_any(DGroupsVisitor {
            marker: std::marker::PhantomData,
        })
    }
}

impl<'de> Deserialize<'de> for SGroups {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SGroupsVisitor;
        impl<'de> serde::de::Visitor<'de> for SGroupsVisitor {
            type Value = SGroups;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or a number")
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(group) = v.parse() {
                    Ok(SGroups::Single(SGroupType(SGenericActorType::Id(group))))
                } else {
                    Ok(SGroups::Single(SGroupType(SGenericActorType::Name(
                        v.to_string(),
                    ))))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(group) = v.parse() {
                    Ok(SGroups::Single(SGroupType(SGenericActorType::Id(group))))
                } else {
                    Ok(SGroups::Single(SGroupType(SGenericActorType::Name(
                        v.into(),
                    ))))
                }
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(group) = v.parse() {
                    Ok(SGroups::Single(SGroupType(SGenericActorType::Id(group))))
                } else {
                    Ok(SGroups::Single(SGroupType(SGenericActorType::Name(v))))
                }
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value > u32::MAX as u64 {
                    return Err(E::custom("value is too large"));
                }
                Ok(SGroups::Single(SGroupType(SGenericActorType::Id(
                    value as u32,
                ))))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut groups = Vec::new();
                while let Some(group) = seq.next_element::<SGroupType>()? {
                    groups.push(group);
                }
                if groups.len() == 1 {
                    Ok(SGroups::Single(groups.remove(0)))
                } else {
                    Ok(SGroups::Multiple(groups))
                }
            }
        }
        deserializer.deserialize_any(SGroupsVisitor)
    }
}

impl From<u32> for SUserType {
    fn from(id: u32) -> Self {
        SUserType(id.into())
    }
}

impl From<u32> for SGroupType {
    fn from(id: u32) -> Self {
        SGroupType(id.into())
    }
}

impl From<&str> for SUserType {
    fn from(name: &str) -> Self {
        SUserType(name.into())
    }
}

impl<'a> From<&'a str> for DUserType<'a> {
    fn from(name: &'a str) -> Self {
        DUserType(name.into())
    }
}

impl From<String> for DUserType<'_> {
    fn from(name: String) -> Self {
        DUserType(DGenericActorType::Name(name.into()))
    }
}

impl<'a> From<&'a str> for DGroupType<'a> {
    fn from(name: &'a str) -> Self {
        DGroupType(name.into())
    }
}

impl From<u32> for DUserType<'_> {
    fn from(id: u32) -> Self {
        DUserType(id.into())
    }
}

impl From<u32> for DGroupType<'_> {
    fn from(id: u32) -> Self {
        DGroupType(id.into())
    }
}

impl From<&str> for SGroupType {
    fn from(name: &str) -> Self {
        SGroupType(name.into())
    }
}

impl<'a> From<Cow<'a, str>> for DGroupType<'a> {
    fn from(name: Cow<'a, str>) -> Self {
        DGroupType(DGenericActorType::Name(name))
    }
}

impl From<Group> for SGroupType {
    fn from(group: Group) -> Self {
        SGroupType(SGenericActorType::Id(group.gid.as_raw()))
    }
}

impl From<&str> for SGenericActorType {
    fn from(name: &str) -> Self {
        SGenericActorType::Name(name.into())
    }
}

impl<'a> From<&'a str> for DGenericActorType<'a> {
    fn from(name: &'a str) -> Self {
        if name.parse::<u32>().is_ok() {
            DGenericActorType::Id(name.parse().unwrap())
        } else {
            DGenericActorType::Name(Cow::Borrowed(name))
        }
    }
}

impl From<u32> for DGenericActorType<'_> {
    fn from(name: u32) -> Self {
        DGenericActorType::Id(name)
    }
}

impl From<u32> for SGenericActorType {
    fn from(id: u32) -> Self {
        SGenericActorType::Id(id)
    }
}

impl PartialEq<User> for SUserType {
    fn eq(&self, other: &User) -> bool {
        let uid = self.fetch_id();
        match uid {
            Some(uid) => uid == other.uid.as_raw(),
            None => false,
        }
    }
}

impl PartialEq<User> for DUserType<'_> {
    fn eq(&self, other: &User) -> bool {
        let uid = self.fetch_id();
        match uid {
            Some(uid) => uid == other.uid.as_raw(),
            None => false,
        }
    }
}

impl PartialEq<str> for SUserType {
    fn eq(&self, other: &str) -> bool {
        self.eq(&SUserType::from(other))
    }
}

impl PartialEq<str> for SGroupType {
    fn eq(&self, other: &str) -> bool {
        self.eq(&SGroupType::from(other))
    }
}

impl PartialEq<u32> for SUserType {
    fn eq(&self, other: &u32) -> bool {
        self.eq(&SUserType::from(*other))
    }
}

impl PartialEq<u32> for DUserType<'_> {
    fn eq(&self, other: &u32) -> bool {
        self.eq(&DUserType::from(*other))
    }
}

impl PartialEq<u32> for SGroupType {
    fn eq(&self, other: &u32) -> bool {
        self.eq(&SGroupType::from(*other))
    }
}

impl PartialEq<Group> for SGroupType {
    fn eq(&self, other: &Group) -> bool {
        let gid = self.fetch_id();
        match gid {
            Some(gid) => gid == other.gid.as_raw(),
            None => false,
        }
    }
}

impl PartialEq<Group> for DGroupType<'_> {
    fn eq(&self, other: &Group) -> bool {
        let gid = self.fetch_id();
        match gid {
            Some(gid) => gid == other.gid.as_raw(),
            None => false,
        }
    }
}

impl<const N: usize> From<[SGroupType; N]> for SGroups {
    fn from(groups: [SGroupType; N]) -> Self {
        if N == 1 {
            SGroups::Single(groups[0].to_owned())
        } else {
            SGroups::Multiple(groups.iter().map(|x| x.to_owned()).collect())
        }
    }
}

impl TryInto<Vec<u32>> for &DGroups<'_> {
    type Error = String;

    fn try_into(self) -> Result<Vec<u32>, Self::Error> {
        match self {
            DGroups::Single(group) => Ok(vec![group
                .fetch_id()
                .ok_or(format!("{} group does not exist", group))?]),
            DGroups::Multiple(groups) => {
                let mut ids = Vec::new();
                for group in groups.iter() {
                    ids.push(
                        group
                            .fetch_id()
                            .ok_or(format!("{} group does not exist", group))?,
                    );
                }
                Ok(ids)
            }
        }
    }
}

impl TryInto<Vec<u32>> for SGroups {
    type Error = String;

    fn try_into(self) -> Result<Vec<u32>, Self::Error> {
        match self {
            SGroups::Single(group) => Ok(vec![group
                .fetch_id()
                .ok_or(format!("{} group does not exist", group))?]),
            SGroups::Multiple(groups) => {
                let mut ids = Vec::new();
                for group in groups {
                    ids.push(
                        group
                            .fetch_id()
                            .ok_or(format!("{} group does not exist", group))?,
                    );
                }
                Ok(ids)
            }
        }
    }
}

impl<const N: usize> From<[&str; N]> for SGroups {
    fn from(groups: [&str; N]) -> Self {
        if N == 1 {
            SGroups::Single(groups[0].into())
        } else {
            SGroups::Multiple(groups.iter().map(|&x| x.into()).collect())
        }
    }
}

impl From<Vec<u32>> for SGroups {
    fn from(groups: Vec<u32>) -> Self {
        if groups.len() == 1 {
            SGroups::Single(groups[0].into())
        } else {
            SGroups::Multiple(groups.into_iter().map(|x| x.into()).collect())
        }
    }
}

impl From<Vec<SGroupType>> for SGroups {
    fn from(groups: Vec<SGroupType>) -> Self {
        if groups.len() == 1 {
            SGroups::Single(groups[0].clone())
        } else {
            SGroups::Multiple(groups)
        }
    }
}

impl<'a> From<Vec<DGroupType<'a>>> for DGroups<'a> {
    fn from(groups: Vec<DGroupType<'a>>) -> Self {
        if groups.len() == 1 {
            DGroups::Single(groups[0].clone())
        } else {
            DGroups::Multiple(Cow::Owned(groups))
        }
    }
}

impl<'a> From<DGroupType<'a>> for DGroups<'a> {
    fn from(groups: DGroupType<'a>) -> Self {
        DGroups::Single(groups)
    }
}

impl From<u32> for SGroups {
    fn from(group: u32) -> Self {
        SGroups::Single(group.into())
    }
}

impl From<&str> for SGroups {
    fn from(group: &str) -> Self {
        SGroups::Single(group.into())
    }
}

impl PartialEq<Vec<SGroupType>> for SGroups {
    fn eq(&self, other: &Vec<SGroupType>) -> bool {
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SActor {
    #[serde(rename = "user")]
    User {
        #[serde(alias = "name", skip_serializing_if = "Option::is_none")]
        id: Option<SUserType>,
        #[serde(default, flatten, skip_serializing_if = "Map::is_empty")]
        _extra_fields: Map<String, Value>,
    },
    #[serde(rename = "group")]
    Group {
        #[serde(
            alias = "names",
            alias = "name",
            skip_serializing_if = "Option::is_none"
        )]
        groups: Option<SGroups>,
        #[serde(default, flatten)]
        _extra_fields: Map<String, Value>,
    },
    #[serde(untagged)]
    Unknown(Value),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, EnumIs, strum::Display)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DActor<'a> {
    #[serde(rename = "user")]
    #[strum(to_string = "User {id}")]
    User {
        #[serde(borrow, alias = "name")]
        id: DUserType<'a>,
    },
    #[serde(rename = "group")]
    #[strum(to_string = "Group {groups}")]
    Group {
        #[serde(borrow, alias = "names", alias = "name", alias = "id")]
        groups: DGroups<'a>,
    },
    #[serde(untagged)]
    Unknown(Value),
}

#[bon]
impl SActor {
    #[builder(finish_fn = build)]
    pub fn user(
        #[builder(start_fn, into)] id: SUserType,
        #[builder(default, with = <_>::from_iter)] _extra_fields: Map<String, Value>,
    ) -> Self {
        SActor::User {
            id: Some(id),
            _extra_fields,
        }
    }
    #[builder(finish_fn = build)]
    pub fn group(
        #[builder(start_fn, into)] groups: SGroups,
        #[builder(default, with = <_>::from_iter)] _extra_fields: Map<String, Value>,
    ) -> Self {
        SActor::Group {
            groups: Some(groups),
            _extra_fields,
        }
    }
}

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
#[cfg(test)]
mod tests {
    use nix::unistd::getuid;

    use super::*;

    #[test]
    fn test_suser_type_creation() {
        let user_by_id = SUserType::from(0);
        let user_by_name = SUserType::from("testuser");

        assert_eq!(user_by_id.to_string(), "0");
        assert_eq!(user_by_name.to_string(), "testuser");
    }
    #[test]
    fn test_fetch_id() {
        let user = SUserType::from(0);
        assert_eq!(user.fetch_id(), Some(0));

        let group = SGroupType::from(0);
        assert_eq!(group.fetch_id(), Some(0));
        let user = SUserType::from("root");
        assert_eq!(user.fetch_id(), Some(0));

        let group = SGroupType::from("root");
        assert_eq!(group.fetch_id(), Some(0));

        let group = SGroupType::from("unkown");
        assert_eq!(group.fetch_id(), None);
    }
    #[test]
    fn test_fetch_user() {
        let user = SUserType::from("testuser");
        assert!(user.fetch_user().is_none());
        let user_by_id = SUserType::from(0);
        assert!(user_by_id.fetch_user().is_some());
    }

    #[test]
    fn test_sgroups_multiple() {
        let groups = SGroups::from(0);

        assert_eq!(groups.len(), 1);
        let groups = SGroups::from(vec![SGroupType::from(0), SGroupType::from(200)]);

        assert_eq!(groups.len(), 2);
        assert!(!groups.is_empty());

        if let SGroups::Multiple(group_list) = groups {
            assert_eq!(group_list[0].to_string(), "0");
            assert_eq!(group_list[1].to_string(), "200");
        } else {
            panic!("Expected SGroups::Multiple");
        }
    }

    #[test]
    fn test_fech_group() {
        let group = SGroupType::from(0);
        assert_eq!(
            group.fetch_group(),
            Some(Group::from_gid(0.into()).unwrap().unwrap())
        );

        let group = SGroupType::from("root");
        assert_eq!(
            group.fetch_group(),
            Some(Group::from_name("root").unwrap().unwrap())
        );
    }

    #[test]
    fn test_is_empty() {
        let groups = SGroups::Multiple(vec![]);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_fetch_eq_sgroupstype_false() {
        let group1 = SGroupType::from("unkown");
        let group2 = SGroupType::from("unkown2");

        assert!(!group1.fetch_eq(&group2));
    }

    #[test]
    fn test_duser_type_creation() {
        let user_by_id = DUserType::from(0);
        let user_by_name = DUserType::from("testuser");

        assert_eq!(user_by_id.to_string(), "0");
        assert_eq!(user_by_name.to_string(), "testuser");
    }
    #[test]
    fn test_fetch_did() {
        let user = DUserType::from(0);
        assert_eq!(user.fetch_id(), Some(0));

        let group = DGroupType::from(0);
        assert_eq!(group.fetch_id(), Some(0));
        let user = DUserType::from("root");
        assert_eq!(user.fetch_id(), Some(0));

        let group = DGroupType::from("root");
        assert_eq!(group.fetch_id(), Some(0));

        let group = DGroupType::from("unkown");
        assert_eq!(group.fetch_id(), None);
    }

    #[test]
    fn test_dgroups_single() {
        let groups = DGroups::from(DGroupType::from(0));

        assert_eq!(groups.len(), 1);
        assert!(!groups.is_empty());

        if let DGroups::Single(group_list) = groups {
            assert_eq!(group_list.to_string(), "0");
        } else {
            panic!("Expected SGroups::Single");
        }
    }

    #[test]
    fn test_is_dempty() {
        let groups = DGroups::Multiple(Cow::Borrowed(&[]));
        assert!(groups.is_empty());
    }

    #[test]
    fn test_sactor_display() {
        let user = SActor::User {
            id: Some(SUserType::from(0)),
            _extra_fields: Map::new(),
        };
        let group = SActor::Group {
            groups: Some(SGroups::from(vec![SGroupType::from(0)])),
            _extra_fields: Map::new(),
        };
        assert_eq!(user.to_string(), "User: 0");
        assert_eq!(group.to_string(), "Group: [0]");
        let group = SActor::Group {
            groups: Some(SGroups::from(vec![
                SGroupType::from(0),
                SGroupType::from("test"),
            ])),
            _extra_fields: Map::new(),
        };
        assert_eq!(group.to_string(), "Group: [0, test]");
        let unknown = SActor::Unknown(Value::String("unknown".to_string()));
        assert_eq!(unknown.to_string(), "Unknown: \"unknown\"");
    }

    #[test]
    fn test_display_dgrouptype() {
        let group = DGroupType::from("test");
        assert_eq!(group.to_string(), "test");
    }

    #[test]
    fn test_partialeq_sgroups() {
        let groups = SGroups::from(vec![SGroupType::from(0), SGroupType::from("test")]);
        let other_groups = vec![SGroupType::from(0), SGroupType::from("test")];
        assert_eq!(groups, other_groups);
        let other_groups = vec![SGroupType::from(0), SGroupType::from("test2")];
        assert_ne!(groups, other_groups);
        let other_groups = vec![SGroupType::from(0)];
        assert_ne!(groups, other_groups);
        let other_groups = vec![
            SGroupType::from(0),
            SGroupType::from("test"),
            SGroupType::from("test2"),
        ];
        assert_ne!(groups, other_groups);
        let groups = SGroups::from(0);
        let other_groups = vec![SGroupType::from(0)];
        assert_eq!(groups, other_groups);
        let other_groups = vec![SGroupType::from(0), SGroupType::from("test")];
        assert_ne!(groups, other_groups);
    }

    #[test]
    fn test_sfetcheq_group() {
        let group1 = SGroupType::from(0);
        let group2 = SGroupType::from(0);

        assert!(group1.fetch_eq(&group2));
        let group2 = SGroupType::from("root");
        assert!(group1.fetch_eq(&group2));
        let group2 = SGroupType::from("unkown");
        assert!(!group1.fetch_eq(&group2));

        let groups = SGroups::from(vec![
            SGroupType::from(0),
            SGroupType::from(getuid().as_raw() + 1),
        ]);
        let other_groups = SGroups::from(vec![
            SGroupType::from(0),
            SGroupType::from(getuid().as_raw() + 1),
        ]);
        assert!(groups.fetch_eq(&other_groups));
        let other_groups = SGroups::from(vec![SGroupType::from(0), SGroupType::from("test2")]);
        assert!(!groups.fetch_eq(&other_groups));
        let other_groups = SGroups::from(0);
        assert!(!groups.fetch_eq(&other_groups));
        let groups = SGroups::from(0);
        assert!(groups.fetch_eq(&other_groups));
    }

    #[test]
    fn test_sfetcheq_user() {
        let user1 = SUserType::from(0);
        let user2 = SUserType::from(0);

        assert!(user1.fetch_eq(&user2));
        let user2 = SUserType::from("root");
        assert!(user1.fetch_eq(&user2));
        let user2 = SUserType::from("unkown");
        assert!(!user1.fetch_eq(&user2));
    }

    #[test]
    fn test_from() {
        let cow = Cow::Borrowed("test");
        let group = DGroupType::from(cow);
        assert_eq!(group.to_string(), "test");
        let group = Group::from_gid(0.into()).unwrap().unwrap();
        let group = SGroupType::from(group);
        assert_eq!(group.fetch_id(), Some(0));
        let group = SGroups::from([SGroupType::from(0)]);
        assert!(group.is_single());
        let group = SGroups::from(["test"]);
        assert!(group.is_single());
        let group = SGroups::from(["test", "test2"]);
        assert!(!group.is_single());
        let group = SGroups::from(vec![0, 1]);
        assert!(!group.is_single());
        let group = SGroups::from(vec![0]);
        assert!(group.is_single());
    }

    #[test]
    #[allow(clippy::cmp_owned)]
    fn test_partialeq_user() {
        assert!(SUserType::from(0) == 0);
        assert!(SUserType::from(0) != 1);
        assert!(DUserType::from(0) == 0);
        assert!(DUserType::from(0) != 1);
        let user = User::from_uid(0.into()).unwrap().unwrap();
        assert!(SUserType::from(0) == user);
        assert!(SUserType::from(0) != 1);
        assert!(DUserType::from(0) == user);
        assert!(DUserType::from(0) != 1);
        assert!(SUserType::from("root") == user);
        assert!(SUserType::from("test") != user);
        assert!(DUserType::from("root") == user);
        assert!(DUserType::from("test") != user);
    }

    #[test]
    fn test_partialeq_group() {
        let group = Group::from_gid(0.into()).unwrap().unwrap();
        assert!(SGroupType::from(0) == group);
        assert!(SGroupType::from(1) != group);
        assert!(SGroupType::from("root") == group);
        assert!(SGroupType::from("test") != group);
        assert!(DGroupType::from(0) == group);
        assert!(DGroupType::from(1) != group);
        assert!(DGroupType::from("root") == group);
        assert!(DGroupType::from("test") != group);
    }

    #[test]
    fn test_tryinto_sgroups() {
        let groups = SGroups::from(vec![SGroupType::from(0), SGroupType::from(1)]);
        let ids: Vec<u32> = groups.try_into().unwrap();
        assert_eq!(ids, vec![0, 1]);

        let groups = SGroups::from(vec![SGroupType::from(0)]);
        let ids: Vec<u32> = groups.try_into().unwrap();
        assert_eq!(ids, vec![0]);

        let groups = SGroups::from(vec![SGroupType::from("unkown")]);
        let ids: Result<Vec<u32>, _> = groups.try_into();
        assert!(ids.is_err());
    }

    #[test]
    fn test_tryinto_dgroups() {
        let groups: DGroups<'_> = DGroups::from(vec![0.into(), 1.into()]);
        let ids: Vec<u32> = (&groups).try_into().unwrap();
        assert_eq!(ids, vec![0, 1]);

        let groups = DGroups::from(vec![DGroupType::from(0)]);
        let ids: Vec<u32> = (&groups).try_into().unwrap();
        assert_eq!(ids, vec![0]);

        let groups = DGroups::from(vec![DGroupType::from("unkown")]);
        let ids: Result<Vec<u32>, _> = (&groups).try_into();
        assert!(ids.is_err());
    }
}
