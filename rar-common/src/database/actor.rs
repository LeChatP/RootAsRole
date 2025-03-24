use std::fmt::{self, Formatter};

use bon::bon;
use nix::unistd::{Group, User};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Value};
use strum::EnumIs;

#[derive(Serialize, Debug, EnumIs, Clone, PartialEq, Eq)]
#[serde(untagged, rename_all = "lowercase")]
pub enum SGenericActorType {
    Id(u32),
    Name(String),
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct SUserType(SGenericActorType);

impl SUserType {
    pub(super) fn fetch_id(&self) -> Option<u32> {
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

impl std::fmt::Display for SGenericActorType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            SGenericActorType::Id(id) => write!(f, "{}", id),
            SGenericActorType::Name(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, EnumIs)]
#[serde(untagged)]
pub enum SGroups {
    Single(SGroupType),
    Multiple(Vec<SGroupType>),
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

impl<'de> Deserialize<'de> for SGenericActorType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IdVisitor;

        impl<'de> Visitor<'de> for IdVisitor {
            type Value = SGenericActorType;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("user ID as a number or string")
            }

            fn visit_u32<E>(self, id: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SGenericActorType::Id(id))
            }

            fn visit_str<E>(self, id: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let rid: Result<u32, _> = id.parse();
                match rid {
                    Ok(id) => Ok(SGenericActorType::Id(id)),
                    Err(_) => Ok(SGenericActorType::Name(id.to_string())),
                }
            }
        }

        deserializer.deserialize_any(IdVisitor)
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

impl From<&str> for SGroupType {
    fn from(name: &str) -> Self {
        SGroupType(name.into())
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

impl<const N: usize> PartialEq<[SGroupType; N]> for SGroups {
    fn eq(&self, other: &[SGroupType; N]) -> bool {
        match self {
            SGroups::Single(group) => {
                if N == 1 {
                    group == &other[0]
                } else {
                    false
                }
            }
            SGroups::Multiple(groups) => {
                if groups.len() == N {
                    groups.iter().zip(other.iter()).all(|(a, b)| a == b)
                } else {
                    false
                }
            }
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

impl FromIterator<String> for SGroups {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        let mut iter = iter.into_iter();
        let first = iter.next().unwrap();
        let mut groups: Vec<SGroupType> = vec![first.as_str().into()];
        for group in iter {
            groups.push(group.as_str().into());
        }
        if groups.len() == 1 {
            SGroups::Single(groups[0].to_owned())
        } else {
            SGroups::Multiple(groups)
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
        #[serde(alias = "names", skip_serializing_if = "Option::is_none")]
        groups: Option<SGroups>,
        #[serde(default, flatten)]
        _extra_fields: Map<String, Value>,
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
}
