use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize,
};

use super::{is_default, structs::*};

impl Serialize for SConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            if let Some(options) = &self.options {
                map.serialize_entry("options", options)?;
            }
            if !self.roles.is_empty() {
                map.serialize_entry("roles", &self.roles)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            if let Some(options) = &self.options {
                map.serialize_entry("o", options)?;
            }
            if !self.roles.is_empty() {
                map.serialize_entry("r", &self.roles)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
    }
}

impl Serialize for SRole {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("name", &self.name)?;
            if let Some(options) = &self.options {
                map.serialize_entry("options", options)?;
            }
            if !self.actors.is_empty() {
                map.serialize_entry("actors", &self.actors)?;
            }
            if !self.tasks.is_empty() {
                map.serialize_entry("tasks", &self.tasks)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("n", &self.name)?;
            if let Some(options) = &self.options {
                map.serialize_entry("o", options)?;
            }
            if !self.actors.is_empty() {
                map.serialize_entry("a", &self.actors)?;
            }
            if !self.tasks.is_empty() {
                map.serialize_entry("t", &self.tasks)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
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
            return serializer.serialize_u32(*self as u32);
        }
    }
}

impl Serialize for SSetuidSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
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
            map.serialize_entry("d", &(self.default as u32))?;
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
        if self.default.is_none() && self.sub.is_empty() && self.add.is_empty() {
            serializer.serialize_some(&self.fallback)
        } else if serializer.is_human_readable() {
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
            map.serialize_entry("d", &(self.default as u32))?;
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
                    map.serialize_entry("d", &(self.default_behavior as u32))?;
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

impl Serialize for STask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("name", &self.name)?;
            if let Some(options) = &self.options {
                map.serialize_entry("options", options)?;
            }
            if let Some(purpose) = &self.purpose {
                map.serialize_entry("purpose", purpose)?;
            }
            if !is_default(&self.cred) {
                map.serialize_entry("cred", &self.cred)?;
            }
            if !cmds_is_default(&self.commands) {
                map.serialize_entry("commands", &self.commands)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("n", &self.name)?;
            if let Some(options) = &self.options {
                map.serialize_entry("o", options)?;
            }
            if let Some(purpose) = &self.purpose {
                map.serialize_entry("p", purpose)?;
            }
            if !is_default(&self.cred) {
                map.serialize_entry("i", &self.cred)?;
            }
            if !cmds_is_default(&self.commands) {
                map.serialize_entry("c", &self.commands)?;
            }
            for (key, value) in &self._extra_fields {
                map.serialize_entry(key, value)?;
            }
            map.end()
        }
    }
}

impl Serialize for SCommands {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.sub.is_empty() && self._extra_fields.is_empty() {
            if self.add.is_empty() {
                return serializer.serialize_bool(
                    self.default_behavior
                        .as_ref()
                        .is_some_and(|b| *b == SetBehavior::All),
                );
            } else if !self.add.is_empty()
                && self
                    .default_behavior
                    .as_ref()
                    .is_none_or(|b| *b == SetBehavior::None)
            {
                let mut seq = serializer.serialize_seq(Some(self.add.len()))?;
                for cmd in &self.add {
                    seq.serialize_element(cmd)?;
                }
                return seq.end();
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
                map.serialize_entry("d", &(*behavior as u32))?;
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

#[cfg(test)]
mod tests {
    use capctl::Cap;
    use serde_json::{json, to_value};

    use crate::database::actor::SActor;

    use super::*;

    #[test]
    fn test_sconfig_human_readable() {
        let config = SConfig {
            options: Some(Default::default()),
            roles: vec![],
            _extra_fields: Default::default(),
        };
        let value = to_value(&config).unwrap();
        assert!(value.get("options").is_some());
    }

    #[test]
    fn test_srole_binary() {
        let role = SRole::builder("admin")
            .actor(SActor::user(0).build())
            .task(STask::builder("test").build())
            .options(|o| {
                o.bounding(crate::database::options::SBounding::Ignore)
                    .build()
            })
            .build();
        //cbor4ii encode
        let bin: Vec<u8> = Vec::new();
        let mut writer = cbor4ii::core::utils::BufWriter::new(bin);
        let mut serializer = cbor4ii::serde::Serializer::new(&mut writer);
        role.serialize(&mut serializer).unwrap();
        assert!(!writer.buffer().is_empty());
        assert!(!writer
            .buffer()
            .windows("tasks".len())
            .any(|window| window == "tasks".as_bytes()));
        assert!(!writer
            .buffer()
            .windows("name".len())
            .any(|window| window == "name".as_bytes()));
        assert!(!writer
            .buffer()
            .windows("options".len())
            .any(|window| window == "options".as_bytes()));
        assert!(!writer
            .buffer()
            .windows("actors".len())
            .any(|window| window == "actors".as_bytes()));
    }

    #[test]
    fn test_setbehavior_serialize() {
        let b = SetBehavior::All;
        let value = to_value(&b).unwrap();
        assert_eq!(value, json!("all"));
        let b = SetBehavior::None;
        let bin: Vec<u8> = Vec::new();
        let mut writer = cbor4ii::core::utils::BufWriter::new(bin);
        let mut serializer = cbor4ii::serde::Serializer::new(&mut writer);
        b.serialize(&mut serializer).unwrap();
        assert!(!writer.buffer().is_empty());
        // split HARDENED_ENUM_VALUE_0 to an array of bytes
        // cbor4ii add 0x1A prefix to the value
        let splitted = [0x1A, 0x05, 0x2A, 0x29, 0x25];
        println!("splitted: {:?}", splitted);
        println!("buffer: {:?}", writer.buffer());
        assert!(writer.buffer() == splitted);
        // test serialization of SetBehavior::All
        let b = SetBehavior::All;
        let bin: Vec<u8> = Vec::new();
        let mut writer = cbor4ii::core::utils::BufWriter::new(bin);
        let mut serializer = cbor4ii::serde::Serializer::new(&mut writer);
        b.serialize(&mut serializer).unwrap();
        assert!(!writer.buffer().is_empty());
        // split HARDENED_ENUM_VALUE_0 to an array of bytes
        // cbor4ii add 0x1A prefix to the value
        let splitted = [0x1A, 0x0A, 0xD5, 0xD6, 0xDA];
        println!("splitted: {:?}", splitted);
        println!("buffer: {:?}", writer.buffer());
        assert!(writer.buffer() == splitted);
    }

    #[test]
    fn test_ssetuidset_human_readable() {
        let set = SSetuidSet::builder()
            .default(SetBehavior::None)
            .fallback(1)
            .add(vec![1.into(), 3.into()])
            .sub(vec![4.into(), 5.into()])
            .build();
        let value = to_value(&set).unwrap();
        assert!(value.get("add").is_some());
    }

    #[test]
    fn test_ssetgidset_seq() {
        let set = SSetgidSet::builder(SetBehavior::None, vec![0, 1]).build();
        let value = to_value(&set).unwrap();
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 2);
        assert_eq!(value.as_array().unwrap()[0], json!(0));
        assert_eq!(value.as_array().unwrap()[1], json!(1));
    }

    #[test]
    fn test_scapabilities_minimal() {
        let caps = SCapabilities::builder(SetBehavior::None)
            .add_cap(Cap::SYS_ADMIN)
            .build();
        let value = to_value(&caps).unwrap();
        assert!(value.is_array());
    }

    #[test]
    fn test_scredentials_human_readable() {
        let creds = SCredentials::builder()
            .setuid(1)
            .setgid(2)
            .capabilities(
                SCapabilities::builder(SetBehavior::None)
                    .add_cap(Cap::SYS_ADMIN)
                    .build(),
            )
            .build();
        let value = to_value(&creds).unwrap();
        assert!(value.get("setuid").is_some());
        assert!(value.get("setgid").is_some());
        assert!(value.get("capabilities").is_some());
    }

    #[test]
    fn test_stask_binary() {
        let task = STask::builder("test")
            .options(|o| {
                o.bounding(crate::database::options::SBounding::Ignore)
                    .build()
            })
            .cred(SCredentials::builder().setuid(1).setgid(2).build())
            .commands(
                SCommands::builder(SetBehavior::All)
                    .add(vec!["ls".into()])
                    .build(),
            )
            .build();
        let bin: Vec<u8> = Vec::new();
        let mut writer = cbor4ii::core::utils::BufWriter::new(bin);
        let mut serializer = cbor4ii::serde::Serializer::new(&mut writer);
        task.serialize(&mut serializer).unwrap();
        assert!(!writer.buffer().is_empty());
        assert!(!writer
            .buffer()
            .windows("name".len())
            .any(|window| window == "name".as_bytes()));
        assert!(!writer
            .buffer()
            .windows("options".len())
            .any(|window| window == "options".as_bytes()));
        assert!(!writer
            .buffer()
            .windows("cred".len())
            .any(|window| window == "cred".as_bytes()));
        assert!(!writer
            .buffer()
            .windows("commands".len())
            .any(|window| window == "commands".as_bytes()));
        assert!(writer
            .buffer()
            .windows("test".len())
            .any(|window| window == "test".as_bytes()));
    }

    #[test]
    fn test_scommands_bool() {
        let cmds = SCommands {
            default_behavior: Some(SetBehavior::All),
            add: vec![],
            sub: vec![],
            _extra_fields: Default::default(),
        };
        let value = to_value(&cmds).unwrap();
        assert!(value.is_boolean());
    }

    #[test]
    fn test_scommands_seq() {
        let cmds = SCommands::builder(SetBehavior::None)
            .add(vec!["ls".into()])
            .build();
        let value = to_value(&cmds).unwrap();
        assert!(value.is_array());
    }
}
