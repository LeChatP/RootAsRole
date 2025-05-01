use core::fmt;

use serde::Deserialize;

use crate::database::structs::{SCommand, SetBehavior};

use super::{actor::SGenericActorType, structs::{SCapabilities, SCommands}};
use capctl::CapSet;
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
            #[serde(alias = "del", alias = "s")]
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
            _ => Err(serde::de::Error::custom("Invalid input for SGenericActorType")),
        }
    }
}

impl<'de> Deserialize<'de> for SCommands {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de> {
        #[derive(Deserialize, Display)]
        #[serde(field_identifier,rename_all = "kebab-case")]
        enum Fields {
            #[serde(alias = "d")]
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

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                where
                    A: SeqAccess<'de>, {
                let mut add = Vec::new();
                while let Some(cmd) = seq.next_element::<SCommand>()? {
                    add.push(cmd);
                }
                Ok(SCommands {
                    default_behavior: Some(SetBehavior::None),
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
                            default_behavior = Some(map
                                .next_value()
                                .expect("default entry must be either 'all' or 'none'"));
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
                    default_behavior,
                    add,
                    sub,
                    _extra_fields,
                })
            }
        }
        deserializer.deserialize_any(SCommandsVisitor)
    }
}