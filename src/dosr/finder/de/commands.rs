use std::{borrow::Cow, path::PathBuf, str::FromStr};

use log::debug;
use rar_common::database::{score::CmdMin, structs::SetBehavior};
use serde::{
    Deserialize,
    de::{DeserializeSeed, IgnoredAny},
};
use serde_json::Value;

use crate::finder::{
    api::{Api, ApiEvent},
    cmd,
    de::{DCommand, DCommandList},
};

impl<'de: 'a, 'a> Deserialize<'de> for DCommandList<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            #[serde(alias = "d", alias = "default_behavior")]
            Default,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "s", alias = "sub", alias = "del")]
            Del,
        }
        #[derive(Default)]
        struct DCommandListVisitor<'a> {
            _phantom: std::marker::PhantomData<&'a ()>,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for DCommandListVisitor<'a> {
            type Value = DCommandList<'a>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("CommandList structure")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut default_behavior = None;
                let mut add: Cow<'_, [DCommand<'_>]> = Cow::Borrowed(&[]);
                let mut del: Cow<'_, [DCommand<'_>]> = Cow::Borrowed(&[]);
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Default => {
                            debug!("DCommandListVisitor: default");
                            default_behavior = Some(map.next_value()?);
                        }
                        Field::Add => {
                            debug!("DCommandListVisitor: add");
                            add = map.next_value()?;
                        }
                        Field::Del => {
                            debug!("DCommandListVisitor: del");
                            del = map.next_value()?;
                        }
                    }
                }
                Ok(DCommandList {
                    default_behavior,
                    add,
                    del,
                })
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut add = Vec::new();
                while let Some(command) = seq.next_element()? {
                    add.push(command);
                }
                Ok(DCommandList {
                    default_behavior: None,
                    add: Cow::Owned(add),
                    del: Cow::Borrowed(&[]),
                })
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let set = SetBehavior::from_str(v).map_err(serde::de::Error::custom)?;
                Ok(DCommandList {
                    default_behavior: Some(set),
                    add: Cow::Borrowed(&[]),
                    del: Cow::Borrowed(&[]),
                })
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }
        }
        deserializer.deserialize_any(DCommandListVisitor::default())
    }
}

/// This struct evaluates commands directly from deserialization
pub struct DCommandListDeserializer<'a> {
    pub env_path: &'a [&'a str],
    pub cmd_path: &'a PathBuf,
    pub cmd_args: &'a [String],
    pub final_path: &'a mut Option<PathBuf>,
    pub cmd_min: &'a mut CmdMin,
    pub blocker: bool,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for DCommandListDeserializer<'a> {
    type Value = bool;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl DCommandListDeserializer<'_> {
    const fn generate_dcommand_deserializer(&mut self) -> DCommandDeserializer<'_> {
        DCommandDeserializer {
            env_path: self.env_path,
            cmd_path: self.cmd_path,
            cmd_args: self.cmd_args,
            final_path: self.final_path,
            cmd_min: self.cmd_min,
        }
    }
}

impl<'de: 'a, 'a> serde::de::Visitor<'de> for DCommandListDeserializer<'a> {
    type Value = bool;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("CommandList Deserializer structure")
    }

    fn visit_seq<A>(mut self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut result = false;
        while let Some(bool) = seq.next_element_seed(self.generate_dcommand_deserializer())? {
            if bool && self.blocker {
                return Ok(true);
            }
            result |= bool;
        }
        Ok(result)
    }

    fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
    where
        V: serde::de::MapAccess<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            #[serde(alias = "d", alias = "default_behavior")]
            Default,
            #[serde(alias = "a")]
            Add,
            #[serde(alias = "s", alias = "sub")]
            Del,
        }
        let mut result = false;
        let mut default = SetBehavior::None;
        while let Some(key) = map.next_key()? {
            match key {
                Field::Default => {
                    debug!("DCommandListVisitor: default");
                    default = map.next_value()?;
                }
                Field::Del => {
                    let deserializer = DCommandListDeserializer {
                        env_path: self.env_path,
                        cmd_path: self.cmd_path,
                        cmd_args: self.cmd_args,
                        final_path: self.final_path,
                        cmd_min: self.cmd_min,
                        blocker: true,
                    };
                    let res = map.next_value_seed(deserializer)?;
                    if res {
                        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                        return Ok(false);
                    }
                }
                Field::Add => {
                    if default.is_all() {
                        let _ = map.next_value::<IgnoredAny>();
                    } else {
                        let deserializer = DCommandListDeserializer {
                            env_path: self.env_path,
                            cmd_path: self.cmd_path,
                            cmd_args: self.cmd_args,
                            final_path: self.final_path,
                            cmd_min: self.cmd_min,
                            blocker: false,
                        };
                        result |= map.next_value_seed(deserializer)?;
                    }
                }
            }
        }
        Ok(result)
    }
    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&v)
    }
    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let set = SetBehavior::from_str(v).map_err(serde::de::Error::custom)?;
        Ok(set.is_all())
    }
    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(v)
    }
}

pub struct DCommandDeserializer<'a> {
    pub env_path: &'a [&'a str],
    pub cmd_path: &'a PathBuf,
    pub cmd_args: &'a [String],
    pub final_path: &'a mut Option<PathBuf>,
    pub cmd_min: &'a mut CmdMin,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for DCommandDeserializer<'a> {
    type Value = bool;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DCommandVisitor<'a> {
            env_path: &'a [&'a str],
            cmd_path: &'a PathBuf,
            cmd_args: &'a [String],
            final_path: &'a mut Option<PathBuf>,
            cmd_min: &'a mut CmdMin,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for DCommandVisitor<'a> {
            type Value = bool;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("Command structure")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let mut final_path = None;
                let mut result = false;
                debug!("DCommandVisitor: command {v}");
                let cmd_min = cmd::evaluate_command_match(
                    self.env_path,
                    self.cmd_path,
                    self.cmd_args,
                    v,
                    *self.cmd_min,
                    &mut final_path,
                );
                debug!("DCommandVisitor: command result {cmd_min:?}");
                if cmd_min.better(*self.cmd_min) {
                    debug!("DCommandVisitor: better command found");
                    result = true;
                    *self.final_path = final_path;
                    *self.cmd_min = cmd_min;
                }
                Ok(result)
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut map_value = Vec::new();
                while let Some((key, value)) = map.next_entry::<&str, Value>()? {
                    map_value.push((key, value));
                }
                Api::notify(ApiEvent::ProcessComplexCommand(
                    &Value::Object(
                        map_value
                            .into_iter()
                            .map(|(k, v)| (k.to_string(), v))
                            .collect(),
                    ),
                    self.env_path,
                    self.cmd_path,
                    self.cmd_args,
                    self.cmd_min,
                    self.final_path,
                ))
                .map(|()| true)
                .map_err(|_| serde::de::Error::custom("Failed to notify process complex command"))
            }
        }
        deserializer.deserialize_any(DCommandVisitor {
            env_path: self.env_path,
            cmd_path: self.cmd_path,
            cmd_args: self.cmd_args,
            final_path: self.final_path,
            cmd_min: self.cmd_min,
        })
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use rar_common::database::score::CmdMin;
    use serde::de::DeserializeSeed;

    use crate::{
        Cli,
        finder::de::commands::{DCommandDeserializer, DCommandListDeserializer},
    };

    #[test]
    fn test_dcommandlist_seed() {
        let json = r#"{"default": "none", "add": ["/usr/bin/ls"], "del": ["/usr/bin/rm"]}"#;
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandListDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from("/usr/bin/ls"),
            cmd_args: &[],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
            blocker: false,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(final_path, Some(PathBuf::from("/usr/bin/ls")));
        assert!(result);
    }

    #[test]
    fn test_dcommand_seed() {
        let json = r#""/usr/bin/ls""#;
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from("/usr/bin/ls"),
            cmd_args: &[],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(final_path, Some(PathBuf::from("/usr/bin/ls")));
        assert!(result);
    }

    #[test]
    fn test_expecting_errors() {
        let seq = "[1, 2, 3]";
        let mut var_name = None;
        let cli = Cli::builder().build();
        let mut cmd_min = CmdMin::MATCH;
        let dcommand = DCommandDeserializer {
            env_path: &[],
            cmd_path: &cli.cmd_path,
            cmd_args: &cli.cmd_args,
            final_path: &mut var_name,
            cmd_min: &mut cmd_min,
        };
        let result = dcommand.deserialize(&mut serde_json::Deserializer::from_str(seq));
        assert!(result.is_err(), "Expected error, got: {result:?}");
    }
}
