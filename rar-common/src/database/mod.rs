use std::error::Error;

use actor::{SGroups, SUserType};
use bon::{builder, Builder};
use chrono::Duration;
use linked_hash_set::LinkedHashSet;
use options::EnvBehavior;
use serde::{de::Deserialize, de::Deserializer, Serialize};

use self::options::EnvKey;

#[cfg(feature = "finder")]
pub mod score;

pub mod actor;
pub mod de;
pub mod migration;
pub mod options;
pub mod ser;
pub mod structs;
pub mod versionning;

#[derive(Debug, Default, Builder)]
#[builder(on(_, overwritable))]
pub struct FilterMatcher {
    pub role: Option<String>,
    pub task: Option<String>,
    pub env_behavior: Option<EnvBehavior>,
    #[builder(with = |s: impl Into<SUserType>| -> Result<_,String> { s.into().fetch_id().ok_or("This user does not exist".into()) })]
    pub user: Option<u32>,
    #[builder(with = |s: impl Into<SGroups>| -> Result<_,String> { s.into().try_into() })]
    pub group: Option<Vec<u32>>,
}

// deserialize the linked hash set
fn lhs_deserialize_envkey<'de, D>(
    deserializer: D,
) -> Result<Option<LinkedHashSet<EnvKey>>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Ok(v) = Vec::<EnvKey>::deserialize(deserializer) {
        Ok(Some(v.into_iter().collect()))
    } else {
        Ok(None)
    }
}

// serialize the linked hash set
fn lhs_serialize_envkey<S>(
    value: &Option<LinkedHashSet<EnvKey>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(v) = value {
        let v: Vec<EnvKey> = v.iter().cloned().collect();
        v.serialize(serializer)
    } else {
        serializer.serialize_none()
    }
}

// deserialize the linked hash set
fn lhs_deserialize<'de, D>(deserializer: D) -> Result<Option<LinkedHashSet<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Ok(v) = Vec::<String>::deserialize(deserializer) {
        Ok(Some(v.into_iter().collect()))
    } else {
        Ok(None)
    }
}

// serialize the linked hash set
fn lhs_serialize<S>(value: &Option<LinkedHashSet<String>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let Some(v) = value {
        let v: Vec<String> = v.iter().cloned().collect();
        v.serialize(serializer)
    } else {
        serializer.serialize_none()
    }
}

pub fn is_default<T: PartialEq + Default>(t: &T) -> bool {
    t == &T::default()
}

pub fn serialize_duration<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // hh:mm:ss format
    match value {
        Some(value) => serializer.serialize_str(&format!(
            "{:#02}:{:#02}:{:#02}",
            value.num_hours(),
            value.num_minutes() % 60,
            value.num_seconds() % 60
        )),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_duration<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match convert_string_to_duration(&s) {
        Ok(d) => Ok(d),
        Err(e) => Err(serde::de::Error::custom(e)),
    }
}

fn convert_string_to_duration(s: &str) -> Result<Option<chrono::TimeDelta>, Box<dyn Error>> {
    let mut parts = s.split(':');
    //unwrap or error
    if let (Some(hours), Some(minutes), Some(seconds)) = (parts.next(), parts.next(), parts.next())
    {
        let hours: i64 = hours.parse()?;
        let minutes: i64 = minutes.parse()?;
        let seconds: i64 = seconds.parse()?;
        return Ok(Some(
            Duration::hours(hours) + Duration::minutes(minutes) + Duration::seconds(seconds),
        ));
    }
    Err("Invalid duration format".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LinkedHashSetTester<T>(pub Option<LinkedHashSet<T>>);

    impl<'de> Deserialize<'de> for LinkedHashSetTester<EnvKey> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(lhs_deserialize_envkey(deserializer)?))
        }
    }

    impl Serialize for LinkedHashSetTester<EnvKey> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            lhs_serialize_envkey(&self.0, serializer)
        }
    }

    impl<'de> Deserialize<'de> for LinkedHashSetTester<String> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(lhs_deserialize(deserializer)?))
        }
    }

    impl Serialize for LinkedHashSetTester<String> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            lhs_serialize(&self.0, serializer)
        }
    }

    struct DurationTester(Option<Duration>);

    impl<'de> Deserialize<'de> for DurationTester {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(deserialize_duration(deserializer)?))
        }
    }

    impl Serialize for DurationTester {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serialize_duration(&self.0, serializer)
        }
    }

    #[test]
    fn test_lhs_deserialize_envkey() {
        let json = r#"["key1", "key2", "key3"]"#;
        let deserialized: Option<LinkedHashSetTester<EnvKey>> = serde_json::from_str(json).unwrap();
        assert!(deserialized.is_some());
        let set = deserialized.unwrap().0.unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&EnvKey::from("key1")));
        assert!(set.contains(&EnvKey::from("key2")));
        assert!(set.contains(&EnvKey::from("key3")));
    }

    #[test]
    fn test_lhs_deserialize() {
        let json = r#"["value1", "value2", "value3"]"#;
        let deserialized: Option<LinkedHashSetTester<String>> = serde_json::from_str(json).unwrap();
        assert!(deserialized.is_some());
        let set = deserialized.unwrap().0.unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains("value1"));
        assert!(set.contains("value2"));
        assert!(set.contains("value3"));
    }

    #[test]
    fn test_lhs_serialize() {
        let mut set = LinkedHashSetTester(Some(LinkedHashSet::new()));
        set.0.as_mut().unwrap().insert("value1".to_string());
        set.0.as_mut().unwrap().insert("value2".to_string());
        set.0.as_mut().unwrap().insert("value3".to_string());
        let serialized = serde_json::to_string(&Some(set)).unwrap();
        assert_eq!(serialized, r#"["value1","value2","value3"]"#);
    }

    #[test]
    fn test_serialize_duration() {
        let duration = DurationTester(Some(Duration::seconds(3661)));
        let serialized = serde_json::to_string(&duration).unwrap();
        assert_eq!(serialized, r#""01:01:01""#);
    }

    #[test]
    fn test_deserialize_duration() {
        let json = r#""01:01:01""#;
        let deserialized: DurationTester = serde_json::from_str(json).unwrap();
        assert!(deserialized.0.is_some());
        let duration = deserialized.0.unwrap();
        assert_eq!(duration.num_seconds(), 3661);
    }

    #[test]
    fn test_is_default() {
        assert!(is_default(&0));
        assert!(is_default(&String::new()));
        assert!(!is_default(&1));
        assert!(!is_default(&"non-default".to_string()));
    }
    #[test]
    fn test_lhs_serialize_empty() {
        let set: LinkedHashSetTester<EnvKey> = LinkedHashSetTester(None);
        let serialized = serde_json::to_string(&Some(set)).unwrap();
        assert_eq!(serialized, r#"null"#);
        let set: LinkedHashSetTester<String> = LinkedHashSetTester(None);
        let serialized = serde_json::to_string(&Some(set)).unwrap();
        assert_eq!(serialized, r#"null"#);
        let duration = DurationTester(None);
        let serialized = serde_json::to_string(&duration).unwrap();
        assert_eq!(serialized, r#"null"#);
    }
    #[test]
    fn test_lhs_deserialize_envkey_null() {
        let json = r#"null"#;
        let deserialized: Option<LinkedHashSetTester<EnvKey>> = serde_json::from_str(json).unwrap();
        assert!(deserialized.is_none());
    }

    #[test]
    fn test_lhs_deserialize_empty_object() {
        let json = r#"{}"#;
        let deserialized: Result<Option<LinkedHashSetTester<String>>, _> =
            serde_json::from_str(json);
        assert!(deserialized.is_err());
    }

    #[test]
    fn test_lhs_serialize_empty_set() {
        let set = LinkedHashSetTester(Some(LinkedHashSet::<EnvKey>::new()));
        let serialized = serde_json::to_string(&Some(set)).unwrap();
        assert_eq!(serialized, r#"[]"#);
    }

    #[test]
    fn test_serialize_duration_large() {
        let duration = Some(DurationTester(Some(Duration::seconds(3600 * 25 + 61))));
        let serialized = serde_json::to_string(&duration).unwrap();
        assert_eq!(serialized, r#""25:01:01""#);
    }

    #[test]
    fn test_deserialize_duration_leading_zeros() {
        let json = r#""001:002:003""#;
        let deserialized: DurationTester = serde_json::from_str(json).unwrap();
        assert!(deserialized.0.is_some());
        let duration = deserialized.0.unwrap();
        assert_eq!(duration.num_seconds(), 3723);
    }

    #[test]
    fn test_deserialize_duration_with_spaces() {
        let json = r#"" 01:01:01 ""#;
        let deserialized: Result<DurationTester, _> = serde_json::from_str(json);
        assert!(deserialized.is_err());
    }

    #[test]
    fn test_deserialize_duration_non_numeric() {
        let json = r#""aa:bb:cc""#;
        let deserialized: Result<DurationTester, _> = serde_json::from_str(json);
        assert!(deserialized.is_err());
    }

    #[test]
    fn test_deserialize_duration_invalid() {
        let json = r#""test""#;
        let deserialized: Result<DurationTester, _> = serde_json::from_str(json);
        assert!(deserialized.is_err());
    }

    #[test]
    fn test_lhs_deserialize_envkey_mixed_types() {
        let json = r#"["key1", 123, null]"#;
        let deserialized: Result<LinkedHashSetTester<EnvKey>, _> = serde_json::from_str(json);
        assert!(deserialized.is_err());
    }
}

#[cfg(test)]
mod serde_tests {
    use crate::{
        database::{
            actor::{SGroups, SUserType},
            structs::*,
        },
        util::*,
    };

    use capctl::Cap;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_set_behavior() {
        assert_tokens(
            &SetBehavior::All.compact(),
            &[Token::U32(HARDENED_ENUM_VALUE_1)],
        );
        assert_tokens(
            &SetBehavior::None.compact(),
            &[Token::U32(HARDENED_ENUM_VALUE_0)],
        );
        assert_tokens(&SetBehavior::All.readable(), &[Token::Str("all")]);
        assert_tokens(&SetBehavior::None.readable(), &[Token::Str("none")]);
    }

    #[test]
    fn test_scapabilities() {
        let cap = SCapabilities::builder(SetBehavior::None).build();
        assert_tokens(
            &cap.clone().compact(),
            &[Token::UnitVariant {
                name: "SetBehavior",
                variant: "none",
            }],
        );
        assert_tokens(
            &cap.readable(),
            &[Token::UnitVariant {
                name: "SetBehavior",
                variant: "none",
            }],
        );
        let cap = SCapabilities::builder(SetBehavior::All)
            .add_cap(Cap::NET_BIND_SERVICE)
            .sub_cap(Cap::CHOWN)
            .build();
        let add = optimized_serialize_capset(&cap.add);
        let sub = optimized_serialize_capset(&cap.sub);
        assert_tokens(
            &cap.clone().compact(),
            &[
                Token::Map { len: None },
                Token::Str("d"),
                Token::U32(HARDENED_ENUM_VALUE_1),
                Token::Str("a"),
                Token::U64(add),
                Token::Str("s"),
                Token::U64(sub),
                Token::MapEnd,
            ],
        );
        assert_tokens(
            &cap.readable(),
            &[
                Token::Map { len: None },
                Token::Str("default"),
                Token::Str("all"),
                Token::Str("add"),
                Token::Seq { len: Some(1) },
                Token::UnitVariant {
                    name: "Cap",
                    variant: "NET_BIND_SERVICE",
                },
                Token::SeqEnd,
                Token::Str("del"),
                Token::Seq { len: Some(1) },
                Token::UnitVariant {
                    name: "Cap",
                    variant: "CHOWN",
                },
                Token::SeqEnd,
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_susereither() {
        let setuid = SUserEither::MandatoryUser(1000.into());
        assert_tokens(
            &setuid.readable(),
            &[Token::NewtypeStruct { name: "SUserType" }, Token::U32(1000)],
        );

        let setuid = SUserEither::UserSelector(
            SSetuidSet::builder()
                .default(SetBehavior::All)
                .fallback(SUserType::from(1000))
                .add(vec![1001.into(), 1002.into()])
                .sub([1003.into()])
                .build(),
        );

        assert_tokens(
            &setuid.clone().readable(),
            &[
                Token::Map { len: None },
                Token::Str("default"),
                Token::Str("all"),
                Token::Str("fallback"),
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1000),
                Token::Str("add"),
                Token::Seq { len: Some(2) },
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1001),
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1002),
                Token::SeqEnd,
                Token::Str("del"),
                Token::Seq { len: Some(1) },
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1003),
                Token::SeqEnd,
                Token::MapEnd,
            ],
        );

        assert_tokens(
            &setuid.compact(),
            &[
                Token::Map { len: None },
                Token::Str("d"),
                Token::U32(HARDENED_ENUM_VALUE_1),
                Token::Str("f"),
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1000),
                Token::Str("a"),
                Token::Seq { len: Some(2) },
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1001),
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1002),
                Token::SeqEnd,
                Token::Str("s"),
                Token::Seq { len: Some(1) },
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1003),
                Token::SeqEnd,
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_sgroups() {
        let groups = SGroupsEither::MandatoryGroup(1000.into());
        assert_tokens(
            &groups.readable(),
            &[
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1000),
            ],
        );

        let groups =
            SGroupsEither::MandatoryGroups(SGroups::Multiple(vec![1000.into(), 1001.into()]));
        assert_tokens(
            &groups.readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1000),
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1001),
                Token::SeqEnd,
            ],
        );

        let groups = SGroupsEither::GroupSelector(
            SSetgidSet::builder(
                SetBehavior::None,
                SGroups::Multiple(vec![1000.into(), 1001.into()]),
            )
            .add(vec![
                SGroups::Multiple(vec![1002.into(), 1003.into()]),
                SGroups::Single(1003.into()),
            ])
            .sub(vec![1004.into(), 1005.into()])
            .build(),
        );

        assert_tokens(
            &groups.clone().readable(),
            &[
                Token::Map { len: None },
                Token::Str("default"),
                Token::Str("none"),
                Token::Str("fallback"),
                Token::Seq { len: Some(2) },
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1000),
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1001),
                Token::SeqEnd,
                Token::Str("add"),
                Token::Seq { len: Some(2) },
                Token::Seq { len: Some(2) },
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1002),
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1003),
                Token::SeqEnd,
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1003),
                Token::SeqEnd,
                Token::Str("del"),
                Token::Seq { len: Some(2) },
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1004),
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1005),
                Token::SeqEnd,
                Token::MapEnd,
            ],
        );

        assert_tokens(
            &groups.compact(),
            &[
                Token::Map { len: None },
                Token::Str("d"),
                Token::U32(HARDENED_ENUM_VALUE_0),
                Token::Str("f"),
                Token::Seq { len: Some(2) },
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1000),
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1001),
                Token::SeqEnd,
                Token::Str("a"),
                Token::Seq { len: Some(2) },
                Token::Seq { len: Some(2) },
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1002),
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1003),
                Token::SeqEnd,
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1003),
                Token::SeqEnd,
                Token::Str("s"),
                Token::Seq { len: Some(2) },
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1004),
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1005),
                Token::SeqEnd,
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_scredentials() {
        let cred = SCredentials::builder()
            .setuid(SUserEither::MandatoryUser(1000.into()))
            .setgid(SGroupsEither::MandatoryGroup(1000.into()))
            .capabilities(
                SCapabilities::builder(SetBehavior::None)
                    .add_cap(Cap::BPF)
                    .sub_cap(Cap::CHOWN)
                    .build(),
            )
            .build();
        assert_tokens(
            &cred.clone().readable(),
            &[
                Token::Map { len: None },
                Token::Str("setuid"),
                Token::Some,
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1000),
                Token::Str("setgid"),
                Token::Some,
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1000),
                Token::Str("capabilities"),
                Token::Some,
                Token::Map { len: None },
                Token::Str("default"),
                Token::Str("none"),
                Token::Str("add"),
                Token::Seq { len: Some(1) },
                Token::UnitVariant {
                    name: "Cap",
                    variant: "BPF",
                },
                Token::SeqEnd,
                Token::Str("del"),
                Token::Seq { len: Some(1) },
                Token::UnitVariant {
                    name: "Cap",
                    variant: "CHOWN",
                },
                Token::SeqEnd,
                Token::MapEnd,
                Token::MapEnd,
            ],
        );
        assert_tokens(
            &cred.compact(),
            &[
                Token::Map { len: None },
                Token::Str("u"),
                Token::Some,
                Token::NewtypeStruct { name: "SUserType" },
                Token::U32(1000),
                Token::Str("g"),
                Token::Some,
                Token::NewtypeStruct { name: "SGroupType" },
                Token::U32(1000),
                Token::Str("c"),
                Token::Some,
                Token::Map { len: None },
                Token::Str("d"),
                Token::U32(HARDENED_ENUM_VALUE_0),
                Token::Str("a"),
                Token::U64((1u64 << Cap::BPF as u8) as u64),
                Token::Str("s"),
                Token::U64((1u64 << Cap::CHOWN as u8) as u64),
                Token::MapEnd,
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_scommand() {
        let cmd = SCommand::Simple("/bin/true".into());
        assert_tokens(&cmd.clone().readable(), &[Token::Str("/bin/true")]);
        assert_tokens(&cmd.compact(), &[Token::Str("/bin/true")]);
    }

    #[test]
    fn test_scommands() {
        let cmds = SCommands::builder(SetBehavior::None).build();
        assert_tokens(
            &cmds.clone().readable(),
            &[Token::UnitVariant {
                name: "SetBehavior",
                variant: "none",
            }],
        );
        assert_tokens(
            &cmds.compact(),
            &[Token::UnitVariant {
                name: "SetBehavior",
                variant: "none",
            }],
        );
        let cmds = SCommands::builder(SetBehavior::None)
            .add(vec![
                SCommand::Simple("/bin/true".into()),
                SCommand::Simple("/bin/echo hello".into()),
            ])
            .build();
        assert_tokens(
            &cmds.clone().readable(),
            &[
                Token::Seq { len: Some(2) },
                Token::Str("/bin/true"),
                Token::Str("/bin/echo hello"),
                Token::SeqEnd,
            ],
        );
        assert_tokens(
            &cmds.compact(),
            &[
                Token::Seq { len: Some(2) },
                Token::Str("/bin/true"),
                Token::Str("/bin/echo hello"),
                Token::SeqEnd,
            ],
        );
        let cmds = SCommands::builder(SetBehavior::All)
            .add(vec![
                SCommand::Simple("/bin/true".into()),
                SCommand::Simple("/bin/echo hello".into()),
            ])
            .sub(vec![SCommand::Simple("/bin/false".into())])
            .build();
        assert_tokens(
            &cmds.clone().readable(),
            &[
                Token::Map { len: None },
                Token::Str("default"),
                Token::Str("all"),
                Token::Str("add"),
                Token::Seq { len: Some(2) },
                Token::Str("/bin/true"),
                Token::Str("/bin/echo hello"),
                Token::SeqEnd,
                Token::Str("del"),
                Token::Seq { len: Some(1) },
                Token::Str("/bin/false"),
                Token::SeqEnd,
                Token::MapEnd,
            ],
        );
        assert_tokens(
            &cmds.compact(),
            &[
                Token::Map { len: None },
                Token::Str("d"),
                Token::U32(HARDENED_ENUM_VALUE_1),
                Token::Str("a"),
                Token::Seq { len: Some(2) },
                Token::Str("/bin/true"),
                Token::Str("/bin/echo hello"),
                Token::SeqEnd,
                Token::Str("s"),
                Token::Seq { len: Some(1) },
                Token::Str("/bin/false"),
                Token::SeqEnd,
                Token::MapEnd,
            ],
        );
    }
}
