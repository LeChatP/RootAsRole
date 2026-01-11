use core::fmt;
use std::str::FromStr;

use log::debug;
use serde::{de::DeserializeSeed, Deserialize};

use crate::database::{
    actor::SGroups,
    structs::{SCommand, SSetgidSet, SetBehavior},
};

use super::{
    actor::SGenericActorType,
    structs::{SCapabilities, SCommands},
};
use capctl::{Cap, CapSet};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserializer,
};
use serde_json::Map;
use strum::Display;

impl<'de> Deserialize<'de> for SetBehavior {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SetBehaviorVisitor;

        impl Visitor<'_> for SetBehaviorVisitor {
            type Value = SetBehavior;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or a number")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                debug!("de_setbehavior: visit_str");
                value.parse().map_err(de::Error::custom)
            }
            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                debug!("de_setbehavior: visit_i32");
                SetBehavior::from_repr(v as u32).ok_or(de::Error::custom(format!(
                    "Invalid value for SetBehavior: {}",
                    v
                )))
            }
            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_i32(v as i32)
            }
            fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_i32(v as i32)
            }
            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_i32(v as i32)
            }
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
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
                E: de::Error,
            {
                self.visit_i32(v as i32)
            }
            fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_i32(v as i32)
            }
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v > i32::MAX as i64 {
                    return Err(de::Error::custom(format!(
                        "Invalid value for SetBehavior: {}",
                        v
                    )));
                }
                self.visit_i32(v as i32)
            }
        }
        debug!("de_setbehavior: deserialize");
        deserializer.deserialize_any(SetBehaviorVisitor)
    }
}

impl<'de> Deserialize<'de> for SCapabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SCapabilitiesVisitor;

        #[derive(Deserialize, Display)]
        #[serde(field_identifier, rename_all = "kebab-case")]
        enum Field {
            #[serde(alias = "d", alias = "default_behavior")]
            Default,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "del", alias = "s")]
            Sub,
        }

        impl<'de> Visitor<'de> for SCapabilitiesVisitor {
            type Value = SCapabilities;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of strings or a map with SCapabilities fields")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let set = SetBehavior::from_str(v).map_err(de::Error::custom)?;
                Ok(SCapabilities {
                    default_behavior: set,
                    add: CapSet::default(),
                    sub: CapSet::default(),
                })
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
                            add = map.next_value_seed(CapSetDeserializer)?;
                        }
                        Field::Sub => {
                            sub = map.next_value_seed(CapSetDeserializer)?;
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
        debug!("de_scapabilities: deserialize");
        deserializer.deserialize_any(SCapabilitiesVisitor)
    }
}

struct CapSetDeserializer;

impl<'de> DeserializeSeed<'de> for CapSetDeserializer {
    type Value = CapSet;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CapSetVisitor;

        impl<'de> Visitor<'de> for CapSetVisitor {
            type Value = CapSet;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of capability strings")
            }
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CapSet::from_bitmask_truncate(v))
            }
            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut capset = CapSet::default();
                let mut seq = seq;
                while let Some(cap) = seq.next_element_seed(CapDeserializer)? {
                    capset.add(cap);
                }
                Ok(capset)
            }
        }
        debug!("de_capset: deserialize");
        deserializer.deserialize_any(CapSetVisitor)
    }
}

struct CapDeserializer;

impl<'de> DeserializeSeed<'de> for CapDeserializer {
    type Value = Cap;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CapVisitor;

        impl<'de> Visitor<'de> for CapVisitor {
            type Value = Cap;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a capability string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let v = v.to_uppercase();
                if v.starts_with("CAP_") {
                    v.parse().map_err(de::Error::custom)
                } else {
                    format!("CAP_{}", v).parse().map_err(de::Error::custom)
                }
            }
        }
        debug!("de_cap: deserialize");
        deserializer.deserialize_any(CapVisitor)
    }
}

impl<'de> Deserialize<'de> for SSetgidSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SSetgidSetVisitor;

        #[derive(Deserialize, Display)]
        #[serde(field_identifier, rename_all = "kebab-case")]
        enum Field {
            #[serde(alias = "d", alias = "default_behavior")]
            Default,
            #[serde(alias = "f")]
            Fallback,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "del", alias = "s")]
            Sub,
        }

        impl<'de> Visitor<'de> for SSetgidSetVisitor {
            type Value = SSetgidSet;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a map")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut default_behavior = SetBehavior::None;
                let mut add = Vec::new();
                let mut sub = Vec::new();
                let mut fallback = None;

                while let Some(key) = map.next_key::<Field>()? {
                    match key {
                        Field::Default => {
                            default_behavior = map
                                .next_value()
                                .expect("default entry must be either 'all' or 'none'");
                        }
                        Field::Fallback => {
                            fallback.replace(map.next_value::<SGroups>()?);
                        }
                        Field::Add => {
                            let values: Vec<SGroups> =
                                map.next_value().expect("add entry must be a list");
                            add.extend(values);
                        }
                        Field::Sub => {
                            let values: Vec<SGroups> =
                                map.next_value().expect("sub entry must be a list");
                            sub.extend(values);
                        }
                    }
                }
                if fallback.is_none() {
                    return Err(de::Error::custom(
                        "Missing required field 'fallback' in SSetgidSet",
                    ));
                }
                Ok(SSetgidSet {
                    default_behavior,
                    fallback: fallback.unwrap(),
                    add,
                    sub,
                })
            }
        }
        debug!("de_ssetgidset: deserialize");
        deserializer.deserialize_any(SSetgidSetVisitor)
    }
}

impl<'de> Deserialize<'de> for SGenericActorType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: serde_json::Value = Deserialize::deserialize(deserializer)?;
        match raw {
            serde_json::Value::Number(num) if num.is_u64() => {
                Ok(SGenericActorType::Id(num.as_u64().unwrap() as u32))
            }
            serde_json::Value::String(ref s) => {
                if let Ok(num) = s.parse() {
                    Ok(SGenericActorType::Id(num))
                } else {
                    Ok(SGenericActorType::Name(s.clone()))
                }
            }
            _ => Err(serde::de::Error::custom(
                "Invalid input for SGenericActorType",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for SCommands {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Display)]
        #[serde(field_identifier, rename_all = "kebab-case")]
        enum Fields {
            #[serde(alias = "d", alias = "default_behavior")]
            Default,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "del", alias = "s")]
            Sub,
            #[serde(untagged)]
            Other(String),
        }
        struct SCommandsVisitor;
        impl<'de> Visitor<'de> for SCommandsVisitor {
            type Value = SCommands;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or a number")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let set = SetBehavior::from_str(v).map_err(de::Error::custom)?;
                Ok(SCommands {
                    default: Some(set),
                    add: Vec::new(),
                    sub: Vec::new(),
                    _extra_fields: Map::new(),
                })
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let set = SetBehavior::from_str(&v).map_err(de::Error::custom)?;
                Ok(SCommands {
                    default: Some(set),
                    add: Vec::new(),
                    sub: Vec::new(),
                    _extra_fields: Map::new(),
                })
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut add = Vec::new();
                while let Some(cmd) = seq.next_element::<SCommand>()? {
                    add.push(cmd);
                }
                Ok(SCommands {
                    default: Some(SetBehavior::None),
                    add,
                    sub: Vec::new(),
                    _extra_fields: Map::new(),
                })
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut default_behavior = None;
                let mut add = Vec::new();
                let mut sub = Vec::new();
                let mut _extra_fields = Map::new();

                while let Some(key) = map.next_key()? {
                    match key {
                        Fields::Default => {
                            default_behavior = Some(
                                map.next_value()
                                    .expect("default entry must be either 'all' or 'none'"),
                            );
                        }
                        Fields::Add => {
                            let values: Vec<SCommand> =
                                map.next_value().expect("add entry must be a list");
                            add.extend(values);
                        }
                        Fields::Sub => {
                            let values: Vec<SCommand> =
                                map.next_value().expect("sub entry must be a list");
                            sub.extend(values);
                        }
                        Fields::Other(other) => {
                            _extra_fields.insert(other.to_string(), map.next_value()?);
                        }
                    }
                }

                Ok(SCommands {
                    default: default_behavior,
                    add,
                    sub,
                    _extra_fields,
                })
            }
        }
        debug!("de_scommands: deserialize");
        deserializer.deserialize_any(SCommandsVisitor)
    }
}

#[cfg(test)]
mod tests {
    use crate::util::{HARDENED_ENUM_VALUE_0, HARDENED_ENUM_VALUE_1, HARDENED_ENUM_VALUE_2};

    use super::*;
    use capctl::Cap;
    use serde_json::json;

    #[test]
    fn test_set_behavior_deserialization() {
        let json_data = json!("none");
        let behavior: SetBehavior = serde_json::from_value(json_data).unwrap();
        assert_eq!(behavior, SetBehavior::None);

        let json_data = json!("all");
        let behavior: SetBehavior = serde_json::from_value(json_data).unwrap();
        assert_eq!(behavior, SetBehavior::All);

        let json_data = json!(HARDENED_ENUM_VALUE_0);
        let behavior: SetBehavior = serde_json::from_value(json_data).unwrap();
        assert_eq!(
            behavior,
            SetBehavior::from_repr(HARDENED_ENUM_VALUE_0).unwrap()
        );

        let json_data = json!(HARDENED_ENUM_VALUE_1);
        let behavior: SetBehavior = serde_json::from_value(json_data).unwrap();
        assert_eq!(
            behavior,
            SetBehavior::from_repr(HARDENED_ENUM_VALUE_1).unwrap()
        );

        let invalid_data = json!(HARDENED_ENUM_VALUE_2);
        assert!(serde_json::from_value::<SetBehavior>(invalid_data).is_err());
    }

    #[test]
    fn test_s_capabilities_deserialization_seq() {
        let json_data = json!(["CAP_SYS_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_CHOWN"]);
        let caps: SCapabilities = serde_json::from_value(json_data).unwrap();

        assert!(caps.add.has(Cap::SYS_ADMIN));
        assert!(caps.add.has(Cap::NET_BIND_SERVICE));
        assert!(caps.add.has(Cap::CHOWN));
        assert_eq!(caps.default_behavior, SetBehavior::None);
    }

    #[test]
    fn test_s_capabilities_deserialization_map() {
        let json_data = json!({
            "default": "none",
            "add": ["CAP_SYS_ADMIN", "CAP_CHOWN"],
            "sub": ["CAP_NET_RAW"]
        });

        let caps: SCapabilities = serde_json::from_value(json_data).unwrap();

        assert!(caps.add.has(Cap::SYS_ADMIN));
        assert!(caps.add.has(Cap::CHOWN));
        assert!(caps.sub.has(Cap::NET_RAW));
        assert_eq!(caps.default_behavior, SetBehavior::None);
    }

    #[test]
    fn test_invalid_capabilities() {
        let invalid_data = json!(["INVALID_CAPABILITY", "CAP_FAKE"]);
        assert!(serde_json::from_value::<SCapabilities>(invalid_data).is_err());
    }

    #[test]
    fn test_s_generic_actor_type_deserialization() {
        let json_data = json!(42);
        let actor_type: SGenericActorType = serde_json::from_value(json_data).unwrap();
        assert_eq!(actor_type, SGenericActorType::Id(42));

        let json_data = json!("actor_name");
        let actor_type: SGenericActorType = serde_json::from_value(json_data).unwrap();
        assert_eq!(
            actor_type,
            SGenericActorType::Name("actor_name".to_string())
        );

        let invalid_data = json!(null);
        assert!(serde_json::from_value::<SGenericActorType>(invalid_data).is_err());
    }

    #[test]
    fn test_s_setgid_set_deserialization() {
        let json_data = json!({
            "default": "all",
            "fallback": "group1",
            "add": ["group2", "group3"],
            "sub": ["group4"]
        });
        let setgid_set: SSetgidSet = serde_json::from_value(json_data).unwrap();
        assert_eq!(setgid_set.default_behavior, SetBehavior::All);
        assert_eq!(setgid_set.fallback, SGroups::from("group1"));
        assert_eq!(setgid_set.add.len(), 2);
        assert_eq!(setgid_set.add[0], SGroups::from("group2"));
        assert_eq!(setgid_set.add[1], SGroups::from("group3"));
        assert_eq!(setgid_set.sub.len(), 1);
        assert_eq!(setgid_set.sub[0], SGroups::from("group4"));
    }

    #[test]
    fn test_s_commands_deserialization_seq() {
        let json_data = json!(["/bin/ls", "/bin/cat"]);

        let commands: SCommands = serde_json::from_value(json_data).unwrap();

        assert_eq!(commands.add.len(), 2);
        assert_eq!(commands.add[0], "/bin/ls".into());
        assert_eq!(commands.add[1], "/bin/cat".into());
    }

    #[test]
    fn test_s_commands_deserialization_map() {
        let json_data = json!({
            "default": "all",
            "add": ["/bin/ls"],
            "sub": ["/bin/cat"]
        });

        let commands: SCommands = serde_json::from_value(json_data).unwrap();

        assert_eq!(commands.default.unwrap(), SetBehavior::All);
        assert_eq!(commands.add.len(), 1);
        assert_eq!(commands.add[0], "/bin/ls".into());
        assert_eq!(commands.sub.len(), 1);
        assert_eq!(commands.sub[0], "/bin/cat".into());
    }
}
