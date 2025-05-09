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
//#[cfg(feature = "finder")]
//pub mod finder;
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

fn convert_string_to_duration(s: &String) -> Result<Option<chrono::TimeDelta>, Box<dyn Error>> {
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

fn serialize_capset<S>(value: &capctl::CapSet, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let v: Vec<String> = value.iter().map(|cap| cap.to_string()).collect();
    v.serialize(serializer)
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
