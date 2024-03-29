

use chrono::Duration;
use linked_hash_set::LinkedHashSet;
use serde::{de, Deserialize, Serialize};
use self::options::EnvKey;

mod migration;
pub mod structs;
mod version;
pub mod options;
pub mod wrapper;

// deserialize the linked hash set
fn lhs_deserialize_envkey<'de, D>(deserializer: D) -> Result<LinkedHashSet<EnvKey>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let v: Vec<EnvKey> = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().collect())
}

// serialize the linked hash set
fn lhs_serialize_envkey<S>(value: &LinkedHashSet<EnvKey>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let v: Vec<EnvKey> = value.iter().cloned().collect();
    v.serialize(serializer)
}

// deserialize the linked hash set
fn lhs_deserialize<'de, D>(deserializer: D) -> Result<LinkedHashSet<String>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let v: Vec<String> = Vec::deserialize(deserializer)?;
    Ok(v.into_iter().collect())
}

// serialize the linked hash set
fn lhs_serialize<S>(value: &LinkedHashSet<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let v: Vec<String> = value.iter().cloned().collect();
    v.serialize(serializer)
}

fn is_default<T: PartialEq + Default>(t: &T) -> bool {
    t == &T::default()
}

fn serialize_duration<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    // hh:mm:ss format
    serializer.serialize_str(&format!("{}:{}:{}", value.num_hours(), value.num_minutes() % 60, value.num_seconds() % 60))

}

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let mut parts = s.split(':');
    //unwrap or error
    if let (Some(hours), Some(minutes), Some(seconds)) = (parts.next(), parts.next(), parts.next()) {
        let hours: i64 = hours.parse().map_err(de::Error::custom)?;
        let minutes: i64 = minutes.parse().map_err(de::Error::custom)?;
        let seconds: i64 = seconds.parse().map_err(de::Error::custom)?;
        return Ok(Duration::hours(hours) + Duration::minutes(minutes) + Duration::seconds(seconds))
    }
    Err(de::Error::custom("Invalid duration format"))    
}