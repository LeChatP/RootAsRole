use std::error::Error;

use actor::{SGroups, SUserType};
use bon::{builder, Builder};
use chrono::Duration;
use linked_hash_set::LinkedHashSet;
use options::EnvBehavior;
use serde::{de, Deserialize, Serialize};

use self::options::EnvKey;

#[cfg(feature = "finder")]
pub mod score;

pub mod actor;
//#[cfg(feature = "finder")]
//pub mod finder;
pub mod migration;
pub mod options;
pub mod structs;
pub mod versionning;

#[derive(Debug, Default, Builder)]
#[builder(on(_, overwritable))]
pub struct FilterMatcher {
    pub role: Option<String>,
    pub task: Option<String>,
    pub env_behavior: Option<EnvBehavior>,
    #[builder(with = |s: SUserType| -> Result<_,String> { s.fetch_id().ok_or("This user does not exist".into()) })]
    pub user: Option<u32>,
    #[builder(with = |s: SGroups| -> Result<_,String> { s.try_into() })]
    pub group: Option<Vec<u32>>,
}


// deserialize the linked hash set
fn lhs_deserialize_envkey<'de, D>(
    deserializer: D,
) -> Result<Option<LinkedHashSet<EnvKey>>, D::Error>
where
    D: de::Deserializer<'de>,
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
    D: de::Deserializer<'de>,
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
    D: de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match convert_string_to_duration(&s) {
        Ok(d) => Ok(d),
        Err(e) => Err(de::Error::custom(e)),
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

    struct LinkedHashSetTester<T>(LinkedHashSet<T>);

    impl<'de> Deserialize<'de> for LinkedHashSetTester<EnvKey> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(
                lhs_deserialize_envkey(deserializer).map(|v| v.unwrap())?,
            ))
        }
    }

    impl Serialize for LinkedHashSetTester<EnvKey> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            lhs_serialize_envkey(&Some(self.0.clone()), serializer)
        }
    }

    impl<'de> Deserialize<'de> for LinkedHashSetTester<String> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(lhs_deserialize(deserializer).map(|v| v.unwrap())?))
        }
    }

    impl Serialize for LinkedHashSetTester<String> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            lhs_serialize(&Some(self.0.clone()), serializer)
        }
    }

    struct DurationTester(Duration);

    impl<'de> Deserialize<'de> for DurationTester {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            Ok(Self(
                deserialize_duration(deserializer).map(|v| v.unwrap())?,
            ))
        }
    }

    impl Serialize for DurationTester {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serialize_duration(&Some(self.0.clone()), serializer)
        }
    }

    #[test]
    fn test_lhs_deserialize_envkey() {
        let json = r#"["key1", "key2", "key3"]"#;
        let deserialized: Option<LinkedHashSetTester<EnvKey>> = serde_json::from_str(json).unwrap();
        assert!(deserialized.is_some());
        let set = deserialized.unwrap();
        assert_eq!(set.0.len(), 3);
        assert!(set.0.contains(&EnvKey::from("key1")));
        assert!(set.0.contains(&EnvKey::from("key2")));
        assert!(set.0.contains(&EnvKey::from("key3")));
    }

    #[test]
    fn test_lhs_serialize_envkey() {
        let mut set = LinkedHashSetTester(LinkedHashSet::new());
        set.0.insert(EnvKey::from("key1"));
        set.0.insert(EnvKey::from("key2"));
        set.0.insert(EnvKey::from("key3"));
        let serialized = serde_json::to_string(&Some(set)).unwrap();
        assert_eq!(serialized, r#"["key1","key2","key3"]"#);
    }

    #[test]
    fn test_lhs_deserialize() {
        let json = r#"["value1", "value2", "value3"]"#;
        let deserialized: Option<LinkedHashSetTester<String>> = serde_json::from_str(json).unwrap();
        assert!(deserialized.is_some());
        let set = deserialized.unwrap();
        assert_eq!(set.0.len(), 3);
        assert!(set.0.contains("value1"));
        assert!(set.0.contains("value2"));
        assert!(set.0.contains("value3"));
    }

    #[test]
    fn test_lhs_serialize() {
        let mut set = LinkedHashSetTester(LinkedHashSet::new());
        set.0.insert("value1".to_string());
        set.0.insert("value2".to_string());
        set.0.insert("value3".to_string());
        let serialized = serde_json::to_string(&Some(set)).unwrap();
        assert_eq!(serialized, r#"["value1","value2","value3"]"#);
    }

    #[test]
    fn test_serialize_duration() {
        let duration = Some(DurationTester(Duration::seconds(3661)));
        let serialized = serde_json::to_string(&duration).unwrap();
        assert_eq!(serialized, r#""01:01:01""#);
    }

    #[test]
    fn test_deserialize_duration() {
        let json = r#""01:01:01""#;
        let deserialized: Option<DurationTester> = serde_json::from_str(json).unwrap();
        assert!(deserialized.is_some());
        let duration = deserialized.unwrap();
        assert_eq!(duration.0.num_seconds(), 3661);
    }

    #[test]
    fn test_is_default() {
        assert!(is_default(&0));
        assert!(is_default(&String::new()));
        assert!(!is_default(&1));
        assert!(!is_default(&"non-default".to_string()));
    }
}
