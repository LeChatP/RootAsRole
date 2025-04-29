use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize,
};

use super::{
    is_default,
    structs::*,
};

impl Serialize for SConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
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
        S: serde::Serializer {
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
            return serializer.serialize_u8(*self as u8);
        }
    }
}

impl Serialize for SSetuidSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
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
            map.serialize_entry("d", &(self.default as u8))?;
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
        if self.default.is_none() && self.sub.is_empty() {
            let mut seq = serializer.serialize_seq(Some(self.add.len()))?;
            for sgroups in &self.add {
                seq.serialize_element(sgroups)?;
            }
            seq.end()
        }else if serializer.is_human_readable() {
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
            map.serialize_entry("d", &(self.default as u8))?;
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
                    map.serialize_entry("d", &(self.default_behavior as u8))?;
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
        S: serde::Serializer {
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
        S: serde::Serializer {
        if self.sub.is_empty() && self._extra_fields.is_empty() {
            if self.add.is_empty() {
                return serializer.serialize_bool(self.default_behavior.as_ref().is_some_and(|b| *b == SetBehavior::All));
            } else if !self.add.is_empty() && self.default_behavior.as_ref().is_none_or(|b| *b == SetBehavior::None) {
                let mut seq = serializer.serialize_seq(Some(self.add.len()))?;
                for cmd in &self.add {
                    seq.serialize_element(cmd)?;
                }
                return seq.end()
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
                map.serialize_entry("d", &(*behavior as u8))?;
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