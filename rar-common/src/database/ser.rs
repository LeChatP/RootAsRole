use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize,
};

use crate::util::optimized_serialize_capset;

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
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_u32(*self as u32)
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
                map.serialize_entry("add", &self.add)?;
            }
            if !self.sub.is_empty() {
                map.serialize_entry("del", &self.sub)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("d", &(self.default as u32))?;
            if let Some(fallback) = &self.fallback {
                map.serialize_entry("f", fallback)?;
            }
            if !self.add.is_empty() {
                map.serialize_entry("a", &self.add)?;
            }
            if !self.sub.is_empty() {
                map.serialize_entry("s", &self.sub)?;
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
        if self.default_behavior.is_none() && self.sub.is_empty() && self.add.is_empty() {
            serializer.serialize_some(&self.fallback)
        } else if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("default", &self.default_behavior)?;
            if !self.fallback.is_empty() {
                map.serialize_entry("fallback", &self.fallback)?;
            }
            if !self.add.is_empty() {
                map.serialize_entry("add", &self.add)?;
            }
            if !self.sub.is_empty() {
                map.serialize_entry("del", &self.sub)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("d", &(self.default_behavior as u32))?;
            if !self.fallback.is_empty() {
                map.serialize_entry("f", &self.fallback)?;
            }
            if !self.add.is_empty() {
                map.serialize_entry("a", &self.add)?;
            }
            if !self.sub.is_empty() {
                map.serialize_entry("s", &self.sub)?;
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
        let human = serializer.is_human_readable();
        if self.add.is_empty() && self.sub.is_empty() {
            serializer.serialize_unit_variant(
                "SetBehavior",
                self.default_behavior as u32,
                if self.default_behavior.is_all() {
                    "all"
                } else {
                    "none"
                },
            )
        } else if self.sub.is_empty() && self.default_behavior.is_none() {
            if human {
                let mut seq = serializer.serialize_seq(Some(self.add.size()))?;
                for cap in self.add {
                    seq.serialize_element(&cap)?;
                }
                seq.end()
            } else {
                optimized_serialize_capset(&self.add).serialize(serializer)
            }
        } else {
            let mut state = serializer.serialize_map(None)?;
            if human {
                state.serialize_entry("default", &self.default_behavior)?;
                if !self.add.is_empty() {
                    state.serialize_entry("add", &self.add)?;
                }
                if !self.sub.is_empty() {
                    state.serialize_entry("del", &self.sub)?;
                }
            } else {
                state.serialize_entry("d", &self.default_behavior)?;
                if !self.add.is_empty() {
                    state.serialize_entry("a", &optimized_serialize_capset(&self.add))?;
                }
                if !self.sub.is_empty() {
                    state.serialize_entry("s", &optimized_serialize_capset(&self.sub))?;
                }
            }
            state.end()
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
                if let Some(variant) = &self.default {
                    return serializer.serialize_unit_variant(
                        "SetBehavior",
                        *variant as u32,
                        if variant.is_all() { "all" } else { "none" },
                    );
                } else {
                    return serializer.serialize_none();
                }
            } else if !self.add.is_empty()
                && self
                    .default
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
            let mut map = serializer.serialize_map(None)?;
            if let Some(behavior) = &self.default {
                map.serialize_entry("default", behavior)?;
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
            let mut map = serializer.serialize_map(None)?;
            if let Some(behavior) = &self.default {
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

    use crate::database::actor::{SActor, SGroups};

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
        let value = to_value(b).unwrap();
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
    fn test_scommands_all_none() {
        let cmds = SCommands {
            default: Some(SetBehavior::All),
            add: vec![],
            sub: vec![],
            _extra_fields: Default::default(),
        };
        let value = to_value(&cmds).unwrap();
        assert!(value.is_string());
        assert_eq!(value, json!("all"));
        let cmds = SCommands {
            default: Some(SetBehavior::None),
            add: vec![],
            sub: vec![],
            _extra_fields: Default::default(),
        };
        let value = to_value(&cmds).unwrap();
        assert!(value.is_string());
        assert_eq!(value, json!("none"));
    }

    #[test]
    fn test_scommands_seq() {
        let cmds = SCommands::builder(SetBehavior::None)
            .add(vec!["ls".into()])
            .build();
        let value = to_value(&cmds).unwrap();
        assert!(value.is_array());
    }

    // CBOR serialization/deserialization tests to identify issues

    #[test]
    fn test_setbehavior_cbor_roundtrip() {
        let behaviors = vec![SetBehavior::None, SetBehavior::All];

        for behavior in behaviors {
            println!("Testing SetBehavior: {:?}", behavior);

            // Serialize to CBOR
            let mut cbor_data = Vec::new();
            cbor4ii::serde::to_writer(&mut cbor_data, &behavior).unwrap();
            println!("CBOR data: {:02x?}", cbor_data);

            // Deserialize from CBOR
            let deserialized: SetBehavior = cbor4ii::serde::from_slice(&cbor_data).unwrap();
            assert_eq!(behavior, deserialized);
        }
    }

    #[test]
    fn test_scapabilities_cbor_roundtrip() {
        use capctl::Cap;

        let caps = SCapabilities::builder(SetBehavior::All)
            .add_cap(Cap::SYS_ADMIN)
            .add_cap(Cap::NET_BIND_SERVICE)
            .sub_cap(Cap::SYS_BOOT)
            .build();

        println!("Testing SCapabilities: {:?}", caps);

        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &caps).unwrap();
        println!("CBOR data: {:?}", String::from_utf8_lossy(&cbor_data));

        // Deserialize from CBOR
        let deserialized: SCapabilities = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(caps, deserialized);
    }

    #[test]
    fn test_scommands_cbor_roundtrip() {
        let test_cases = vec![
            // Simple string case
            SCommands {
                default: Some(SetBehavior::All),
                add: vec![],
                sub: vec![],
                _extra_fields: Default::default(),
            },
            // Array case
            SCommands::builder(SetBehavior::None)
                .add(vec!["ls".into(), "cat".into()])
                .build(),
            // Map case
            SCommands::builder(SetBehavior::All)
                .add(vec!["ls".into()])
                .sub(vec!["rm".into()])
                .build(),
        ];

        for (i, cmds) in test_cases.into_iter().enumerate() {
            println!("Testing SCommands case {}: {:?}", i, cmds);

            // Serialize to CBOR
            let mut cbor_data = Vec::new();
            cbor4ii::serde::to_writer(&mut cbor_data, &cmds).unwrap();
            println!("CBOR data: {:02x?}", cbor_data);

            // Deserialize from CBOR
            let deserialized: SCommands = cbor4ii::serde::from_slice(&cbor_data).unwrap();
            assert_eq!(cmds, deserialized);
        }
    }

    #[test]
    fn test_scredentials_cbor_roundtrip() {
        let creds = SCredentials::builder()
            .setuid(1)
            .setgid(2u32)
            .capabilities(
                SCapabilities::builder(SetBehavior::All)
                    .add_cap(Cap::SYS_ADMIN)
                    .sub_cap(Cap::SYS_BOOT)
                    .build(),
            )
            .build();

        println!("Testing SCredentials: {:?}", creds);

        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &creds).unwrap();
        println!("CBOR data: {:?}", String::from_utf8_lossy(&cbor_data));

        // Deserialize from CBOR
        let deserialized: SCredentials = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(creds, deserialized);
    }

    #[test]
    fn test_groupseither_cbor_roundtrip() {
        let mandatory_single = SGroupsEither::MandatoryGroup(1.into());

        println!("Testing SSetgidSet: {:?}", mandatory_single);

        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &mandatory_single).unwrap();
        println!("CBOR data: {:02x?}", cbor_data);

        // Deserialize from CBOR
        let deserialized: SGroupsEither = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(mandatory_single, deserialized);

        let mandatory_multiple =
            SGroupsEither::MandatoryGroups(SGroups::Multiple(vec![1.into(), 2.into()]));
        println!("Testing SSetgidSet: {:?}", mandatory_multiple);
        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &mandatory_multiple).unwrap();
        println!("CBOR data: {:02x?}", cbor_data);
        // Deserialize from CBOR
        let deserialized: SGroupsEither = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(mandatory_multiple, deserialized);

        let gidset = SGroupsEither::GroupSelector(
            SSetgidSet::builder(SetBehavior::None, vec![1, 2])
                .add(vec![4.into(), 5.into()])
                .sub(vec![3.into(), 4.into()])
                .build(),
        );
        println!("Testing SSetgidSet: {:?}", gidset);
        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &gidset).unwrap();
        println!("CBOR data: {:02x?}", cbor_data);
        // Deserialize from CBOR
        let deserialized: SGroupsEither = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(gidset, deserialized);
    }

    #[test]
    fn test_stask_cbor_roundtrip() {
        let task = STask::builder("test_task")
            .cred(SCredentials::builder().setuid(1).setgid(2u32).build())
            .commands(
                SCommands::builder(SetBehavior::None)
                    .add(vec!["ls".into()])
                    .build(),
            )
            .build();

        println!("Testing STask: {:?}", task);

        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &task).unwrap();
        println!("CBOR data: {:02x?}", cbor_data);

        // Deserialize from CBOR
        let deserialized: STask = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(task.as_ref().borrow().name, deserialized.name);
        assert_eq!(task.as_ref().borrow().cred, deserialized.cred);
        assert_eq!(task.as_ref().borrow().commands, deserialized.commands);
    }

    #[test]
    fn test_minimal_cbor_roundtrips() {
        // Start with the simplest structures first

        // Test SetBehavior
        for behavior in [SetBehavior::None, SetBehavior::All] {
            println!("Testing SetBehavior: {:?}", behavior);
            let mut cbor_data = Vec::new();
            cbor4ii::serde::to_writer(&mut cbor_data, &behavior).unwrap();
            println!("CBOR data: {:02x?}", cbor_data);
            let deserialized: SetBehavior = cbor4ii::serde::from_slice(&cbor_data).unwrap();
            assert_eq!(behavior, deserialized);
        }

        // Test simple SCommands
        let cmds = SCommands {
            default: Some(SetBehavior::All),
            add: vec![],
            sub: vec![],
            _extra_fields: Default::default(),
        };
        println!("Testing SCommands: {:?}", cmds);
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &cmds).unwrap();
        println!("CBOR data: {:02x?}", cbor_data);
        let deserialized: SCommands = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(cmds, deserialized);

        // Test STask
        let task = STask::builder("test_task").build();
        println!("Testing STask: {:?}", task);
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &task).unwrap();
        println!("CBOR data: {:02x?}", cbor_data);
        let deserialized: STask = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(task.as_ref().borrow().name, deserialized.name);
    }

    #[test]
    fn test_sactor_cbor_roundtrip() {
        let actor = SActor::user(1000).build();
        println!("Testing SActor: {:?}", actor);
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &actor).unwrap();
        println!("CBOR data: {:02x?}", cbor_data);
        let deserialized: SActor = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert!(actor.is_user());
        assert_eq!(actor, deserialized);
        let actor = SActor::group(2000).build();
        println!("Testing SActor: {:?}", actor);
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &actor).unwrap();
        println!("CBOR data: {:02x?}", cbor_data);
        let deserialized: SActor = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert!(actor.is_group());
        assert_eq!(actor, deserialized);
    }
}
