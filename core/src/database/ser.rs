use indexmap::IndexSet;
use jiff::SignedDuration;
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};

use crate::util::optimized_serialize_capset;

use super::{
    actor::SActor,
    is_default,
    options::{Opt, SEnvOptions, SPassword, SPathOptions, STimeout, STty, SWorkdirSet},
    serialize_duration,
    structs::{
        SCapabilities, SCommands, SCredentials, SPolicy, SRole, SSetgidSet, SSetuidSet, STask,
        SetBehavior, cmds_is_default,
    },
    versionning::VersionedData,
};

/// A value of a field that rootasrole-core does not know (a plugin's, or a newer version's),
/// written so that a null stays a null in CBOR: `Value` writes null as a unit, which cbor4ii
/// encodes as an empty array, so `"x": null` was read back as `"x": []`. serde does not tell
/// a flattened field whether the format is human-readable: null is always written as `none`,
/// which is `null` in JSON too.
pub(crate) struct Unknown<'a>(pub(crate) &'a serde_json::Value);

impl Serialize for Unknown<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            serde_json::Value::Null => serializer.serialize_none(),
            serde_json::Value::Array(values) => serializer.collect_seq(values.iter().map(Unknown)),
            serde_json::Value::Object(fields) => {
                serializer.collect_map(fields.iter().map(|(key, value)| (key, Unknown(value))))
            }
            value => value.serialize(serializer),
        }
    }
}

/// The key of a field: `long` in a human-readable format (JSON), `short` in the binary one (CBOR),
/// which keeps the policy small to read.
pub(crate) const fn field(
    human_readable: bool,
    long: &'static str,
    short: &'static str,
) -> &'static str {
    if human_readable { long } else { short }
}

impl VersionedData for SPolicy {
    fn serialize_entries<M: SerializeMap>(
        &self,
        map: &mut M,
        human_readable: bool,
    ) -> Result<(), M::Error> {
        if let Some(options) = &self.options {
            map.serialize_entry(field(human_readable, "options", "o"), options)?;
        }
        if !self.roles.is_empty() {
            map.serialize_entry(field(human_readable, "roles", "r"), &self.roles)?;
        }
        for (key, value) in &self.extra_fields {
            map.serialize_entry(key, &Unknown(value))?;
        }
        Ok(())
    }
}

impl Serialize for SPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        self.serialize_entries(&mut map, human_readable)?;
        map.end()
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
            for (key, value) in &self.extra_fields {
                map.serialize_entry(key, &Unknown(value))?;
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
            for (key, value) in &self.extra_fields {
                map.serialize_entry(key, &Unknown(value))?;
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
            serializer.serialize_str(&format!("{self}"))
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
        if let Some(fallback) = self.fallback.as_ref().filter(|_| {
            self.default_behavior.is_none()
                && self.sub.is_empty()
                && self.add.is_empty()
                && self.from.is_none()
        }) {
            serializer.serialize_some(fallback)
        } else if serializer.is_human_readable() {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("default", &self.default_behavior)?;
            if let Some(fallback) = &self.fallback {
                map.serialize_entry("fallback", fallback)?;
            }
            if !self.add.is_empty() {
                map.serialize_entry("add", &self.add)?;
            }
            if !self.sub.is_empty() {
                map.serialize_entry("del", &self.sub)?;
            }
            if let Some(from) = &self.from {
                map.serialize_entry("from", from)?;
            }
            map.end()
        } else {
            let mut map = serializer.serialize_map(None)?;
            map.serialize_entry("d", &(self.default_behavior as u32))?;
            if let Some(fallback) = &self.fallback {
                map.serialize_entry("f", fallback)?;
            }
            if !self.add.is_empty() {
                map.serialize_entry("a", &self.add)?;
            }
            if !self.sub.is_empty() {
                map.serialize_entry("s", &self.sub)?;
            }
            if let Some(from) = &self.from {
                map.serialize_entry("o", from)?;
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
            for (key, value) in &self.extra_fields {
                map.serialize_entry(key, &Unknown(value))?;
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
            for (key, value) in &self.extra_fields {
                map.serialize_entry(key, &Unknown(value))?;
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
            for (key, value) in &self.extra_fields {
                map.serialize_entry(key, &Unknown(value))?;
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
            for (key, value) in &self.extra_fields {
                map.serialize_entry(key, &Unknown(value))?;
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
        if self.sub.is_empty() && self.extra_fields.is_empty() {
            if self.add.is_empty() {
                if let Some(variant) = &self.default {
                    return serializer.serialize_unit_variant(
                        "SetBehavior",
                        *variant as u32,
                        if variant.is_all() { "all" } else { "none" },
                    );
                }
                return serializer.serialize_none();
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
            for (key, value) in &self.extra_fields {
                map.serialize_entry(key, &Unknown(value))?;
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
            for (key, value) in &self.extra_fields {
                map.serialize_entry(key, &Unknown(value))?;
            }
            map.end()
        }
    }
}

/// A list of the policy, written as a sequence (indexmap is built without serde).
struct List<'a, T>(&'a IndexSet<T>);

impl<T: Serialize> Serialize for List<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0)
    }
}

/// A duration of the policy, written `hh:mm:ss`.
struct Duration<'a>(&'a SignedDuration);

impl Serialize for Duration<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serialize_duration(&Some(*self.0), serializer)
    }
}

impl Serialize for SActor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let human_readable = serializer.is_human_readable();
        match self {
            Self::User {
                id: Some(id),
                extra_fields,
            } if !human_readable && extra_fields.is_empty() => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("u", id)?;
                map.end()
            }
            Self::Group {
                groups: Some(groups),
                extra_fields,
            } if !human_readable && extra_fields.is_empty() => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("g", groups)?;
                map.end()
            }
            Self::User { id, extra_fields } => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("type", "user")?;
                if let Some(id) = id {
                    map.serialize_entry("id", id)?;
                }
                for (key, value) in extra_fields {
                    map.serialize_entry(key, &Unknown(value))?;
                }
                map.end()
            }
            Self::Group {
                groups,
                extra_fields,
            } => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("type", "group")?;
                if let Some(groups) = groups {
                    map.serialize_entry("groups", groups)?;
                }
                for (key, value) in extra_fields {
                    map.serialize_entry(key, &Unknown(value))?;
                }
                map.end()
            }
            Self::Unknown(value) => Unknown(value).serialize(serializer),
        }
    }
}

impl Serialize for Opt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        if let Some(path) = &self.path {
            map.serialize_entry(field(human_readable, "path", "p"), path)?;
        }
        if let Some(env) = &self.env {
            map.serialize_entry(field(human_readable, "env", "e"), env)?;
        }
        if let Some(root) = &self.root {
            map.serialize_entry(field(human_readable, "root", "r"), root)?;
        }
        if let Some(bounding) = &self.bounding {
            map.serialize_entry(field(human_readable, "bounding", "b"), bounding)?;
        }
        if let Some(authentication) = &self.authentication {
            map.serialize_entry(field(human_readable, "authentication", "a"), authentication)?;
        }
        if let Some(execinfo) = &self.execinfo {
            map.serialize_entry(field(human_readable, "execinfo", "i"), execinfo)?;
        }
        if let Some(workdir) = &self.workdir {
            map.serialize_entry(field(human_readable, "workdir", "w"), workdir)?;
        }
        if let Some(timeout) = &self.timeout {
            map.serialize_entry(field(human_readable, "timeout", "t"), timeout)?;
        }
        if let Some(password) = &self.password {
            map.serialize_entry(field(human_readable, "password", "k"), password)?;
        }
        if let Some(tty) = &self.tty {
            map.serialize_entry(field(human_readable, "tty", "y"), tty)?;
        }
        if let Some(umask) = &self.umask {
            map.serialize_entry(field(human_readable, "umask", "u"), umask)?;
        }
        for (key, value) in &self.extra_fields {
            map.serialize_entry(key, &Unknown(value))?;
        }
        map.end()
    }
}

impl Serialize for SPathOptions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        if !is_default(&self.default_behavior) {
            map.serialize_entry(
                field(human_readable, "default", "d"),
                &self.default_behavior,
            )?;
        }
        if let Some(add) = &self.add {
            map.serialize_entry(field(human_readable, "add", "a"), &List(add))?;
        }
        if let Some(sub) = &self.sub {
            map.serialize_entry(field(human_readable, "sub", "s"), &List(sub))?;
        }
        for (key, value) in &self.extra_fields {
            map.serialize_entry(key, &Unknown(value))?;
        }
        map.end()
    }
}

impl Serialize for SEnvOptions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        if !is_default(&self.default_behavior) {
            map.serialize_entry(
                field(human_readable, "default", "d"),
                &self.default_behavior,
            )?;
        }
        if let Some(override_behavior) = &self.override_behavior {
            map.serialize_entry(
                field(human_readable, "override_behavior", "o"),
                override_behavior,
            )?;
        }
        if let Some(set) = &self.set {
            map.serialize_entry(field(human_readable, "set", "v"), set)?;
        }
        for (list, long, short) in [
            (&self.keep, "keep", "k"),
            (&self.check, "check", "c"),
            (&self.delete, "delete", "s"),
        ] {
            if let Some(list) = list {
                map.serialize_entry(field(human_readable, long, short), &List(list))?;
            }
        }
        for (key, value) in &self.extra_fields {
            map.serialize_entry(key, &Unknown(value))?;
        }
        map.end()
    }
}

impl Serialize for SWorkdirSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        if !is_default(&self.default_behavior) {
            map.serialize_entry(
                field(human_readable, "default", "d"),
                &self.default_behavior,
            )?;
        }
        if let Some(fallback) = &self.fallback {
            map.serialize_entry(field(human_readable, "fallback", "f"), fallback)?;
        }
        if let Some(add) = &self.add {
            map.serialize_entry(field(human_readable, "add", "a"), &List(add))?;
        }
        if let Some(sub) = &self.sub {
            map.serialize_entry(field(human_readable, "sub", "s"), &List(sub))?;
        }
        for (key, value) in &self.extra_fields {
            map.serialize_entry(key, &Unknown(value))?;
        }
        map.end()
    }
}

impl Serialize for STimeout {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        if let Some(type_field) = &self.type_field {
            map.serialize_entry(field(human_readable, "type", "t"), type_field)?;
        }
        if let Some(duration) = &self.duration {
            map.serialize_entry(field(human_readable, "duration", "d"), &Duration(duration))?;
        }
        if let Some(max_usage) = &self.max_usage {
            map.serialize_entry(field(human_readable, "max_usage", "m"), max_usage)?;
        }
        for (key, value) in &self.extra_fields {
            map.serialize_entry(key, &Unknown(value))?;
        }
        map.end()
    }
}

impl Serialize for SPassword {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        if let Some(tries) = &self.tries {
            map.serialize_entry(field(human_readable, "tries", "t"), tries)?;
        }
        if let Some(delay) = &self.delay {
            map.serialize_entry(field(human_readable, "delay", "d"), &Duration(delay))?;
        }
        for (key, value) in &self.extra_fields {
            map.serialize_entry(key, &Unknown(value))?;
        }
        map.end()
    }
}

impl Serialize for STty {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        if let Some(owner) = &self.owner {
            map.serialize_entry(field(human_readable, "owner", "o"), owner)?;
        }
        for (key, value) in &self.extra_fields {
            map.serialize_entry(key, &Unknown(value))?;
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use capctl::Cap;
    use serde_json::{Map, json, to_value};

    use crate::{
        SettingsContent,
        database::{
            actor::{SActor, SGroups},
            structs::SGroupsEither,
            versionning::Versioning,
        },
        file::RootSettings,
    };

    use super::*;

    #[test]
    fn test_sconfig_human_readable() {
        let config = SPolicy {
            options: Some(Rc::default()),
            roles: vec![],
            extra_fields: Map::default(),
        };
        let value = to_value(&config).unwrap();
        assert!(value.get("options").is_some());
    }

    /// The keys of the top level of `versioned`, written in CBOR and in JSON.
    fn top_level_keys(versioned: &impl Serialize) -> [std::collections::BTreeSet<String>; 2] {
        let cbor = cbor4ii::serde::to_vec(Vec::new(), versioned).unwrap();
        let cbor: serde_json::Value = cbor4ii::serde::from_slice(&cbor).unwrap();
        [cbor, to_value(versioned).unwrap()]
            .map(|document| document.as_object().unwrap().keys().cloned().collect())
    }

    #[test]
    fn test_versioned_top_level_binary() {
        // with serde flatten, the data got a human-readable serializer: the top level of a CBOR
        // file had the long keys
        let policy = Rc::new(std::cell::RefCell::new(SPolicy {
            options: Some(Rc::default()),
            roles: vec![SRole::builder("r").build()],
            extra_fields: Map::default(),
        }));
        let [cbor, json] = top_level_keys(&Versioning::new(policy.clone()));
        assert_eq!(cbor, ["o", "r", "v"].map(String::from).into());
        assert_eq!(
            json,
            ["options", "roles", "version"].map(String::from).into()
        );
        let root = RootSettings::builder()
            .storage(SettingsContent::default())
            .config(policy)
            .build();
        let [cbor, json] = top_level_keys(&Versioning::new(root));
        assert_eq!(cbor, ["o", "r", "s", "v"].map(String::from).into());
        assert_eq!(
            json,
            ["options", "roles", "storage", "version"]
                .map(String::from)
                .into()
        );
    }

    /// `value` written in CBOR, read back as a document.
    fn binary_document(value: &impl Serialize) -> serde_json::Value {
        cbor4ii::serde::from_slice(&cbor4ii::serde::to_vec(Vec::new(), value).unwrap()).unwrap()
    }

    #[test]
    fn test_options_and_actors_binary() {
        // every option and every field of an option, at a level, and the actors of a role
        let written = json!({
            "options": {
                "path": {"default": "delete", "add": ["/usr/bin"], "sub": ["/tmp"]},
                "env": {
                    "default": "delete", "override_behavior": false, "set": {"LANG": "C"},
                    "keep": ["HOME"], "check": ["TZ"], "delete": ["LD_*"]
                },
                "root": "user",
                "bounding": "strict",
                "authentication": "perform",
                "execinfo": "hide",
                "workdir": {"default": "none", "fallback": "/", "add": ["/home"], "sub": ["/root"]},
                "timeout": {"type": "ppid", "duration": "00:05:00", "max_usage": 1},
                "password": {"tries": 3, "delay": "00:00:02"},
                "tty": {"owner": "caller"},
                "umask": "022",
                "future": 1
            },
            "roles": [{
                "name": "r",
                "actors": [
                    {"type": "user", "id": "alice"},
                    {"type": "group", "groups": ["adm", "wheel"]},
                    {"type": "user", "id": 0, "future": 1},
                    {"kind": "unknown"}
                ]
            }]
        });
        let policy: SPolicy = serde_json::from_value(written.clone()).unwrap();
        // JSON keeps the names, and the typed actors that 4.0 reads
        assert_eq!(to_value(&policy).unwrap(), written);
        let document = binary_document(&policy);
        assert_eq!(
            document,
            json!({
                "o": {
                    "p": {"d": "delete", "a": ["/usr/bin"], "s": ["/tmp"]},
                    "e": {
                        "d": "delete", "o": false, "v": {"LANG": "C"},
                        "k": ["HOME"], "c": ["TZ"], "s": ["LD_*"]
                    },
                    "r": "user",
                    "b": "strict",
                    "a": "perform",
                    "i": "hide",
                    "w": {"d": "none", "f": "/", "a": ["/home"], "s": ["/root"]},
                    "t": {"t": "ppid", "d": "00:05:00", "m": 1},
                    "k": {"t": 3, "d": "00:00:02"},
                    "y": {"o": "caller"},
                    "u": "022",
                    "future": 1
                },
                "r": [{
                    "n": "r",
                    "a": [
                        {"u": "alice"},
                        {"g": ["adm", "wheel"]},
                        // an actor with an unknown field keeps the typed form
                        {"type": "user", "id": 0, "future": 1},
                        {"kind": "unknown"}
                    ]
                }]
            })
        );
        // and the short keys are read back, in CBOR and in JSON
        let cbor = cbor4ii::serde::to_vec(Vec::new(), &policy).unwrap();
        assert_eq!(
            cbor4ii::serde::from_slice::<SPolicy>(&cbor).unwrap(),
            policy
        );
        assert_eq!(serde_json::from_value::<SPolicy>(document).unwrap(), policy);
    }

    // a null in a field that rootasrole-core does not know stays a null in CBOR, at each level,
    // in an array and in an object: cbor4ii writes a unit as an empty array (fuzz target
    // config_parse)
    #[test]
    fn test_unknown_null_stays_null_in_cbor() {
        let unknown = json!({"x": null, "list": [1, null, [null]], "map": {"y": null}});
        let mut written = json!({
            "options": {
                "path": {"default": "delete"},
                "env": {"default": "delete"},
                "workdir": {"default": "none"},
                "timeout": {"type": "ppid"},
                "password": {"tries": 3},
                "tty": {"owner": "caller"}
            },
            "roles": [{
                "name": "r",
                "actors": [{"type": "user", "id": 0}, {"kind": "unknown"}],
                "tasks": [{
                    "name": "t",
                    "cred": {"setuid": "root"},
                    "commands": {"default": "none", "add": ["/usr/bin/true"]}
                }]
            }]
        });
        let add = |object: &mut serde_json::Value| {
            object
                .as_object_mut()
                .unwrap()
                .extend(unknown.as_object().unwrap().clone());
        };
        add(&mut written);
        for option in ["path", "env", "workdir", "timeout", "password", "tty"] {
            add(&mut written["options"][option]);
        }
        add(&mut written["options"]);
        add(&mut written["roles"][0]);
        add(&mut written["roles"][0]["actors"][0]);
        add(&mut written["roles"][0]["actors"][1]);
        add(&mut written["roles"][0]["tasks"][0]);
        add(&mut written["roles"][0]["tasks"][0]["cred"]);
        add(&mut written["roles"][0]["tasks"][0]["commands"]);
        let policy: SPolicy = serde_json::from_value(written).unwrap();
        let json = to_value(&policy).unwrap();
        let cbor = cbor4ii::serde::to_vec(Vec::new(), &policy).unwrap();
        let from_cbor: SPolicy = cbor4ii::serde::from_slice(&cbor).unwrap();
        assert_eq!(to_value(&from_cbor).unwrap(), json);
        assert_eq!(
            json["roles"][0]["tasks"][0]["cred"]["list"],
            json!([1, null, [null]])
        );
    }

    #[test]
    fn test_root_file_binary() {
        let written = json!({
            "version": "4.3.0",
            "storage": {"method": "cbor", "settings": {"immutable": true, "path": "/etc/security/rootasrole.d"}}
        });
        let root: Versioning<RootSettings> = serde_json::from_value(written.clone()).unwrap();
        assert_eq!(to_value(&root).unwrap(), written);
        let document = binary_document(&root);
        assert_eq!(
            document,
            json!({
                "v": "4.3.0",
                "s": {"m": "cbor", "s": {"i": true, "p": "/etc/security/rootasrole.d"}}
            })
        );
        let read: Versioning<RootSettings> = serde_json::from_value(document).unwrap();
        assert_eq!(read.data, root.data);
    }

    #[test]
    fn test_list_keeps_the_order() {
        let list: IndexSet<String> = ["b", "a", "c"].map(String::from).into_iter().collect();
        assert_eq!(to_value(List(&list)).unwrap(), json!(["b", "a", "c"]));
        assert_eq!(
            to_value(List(&IndexSet::<String>::new())).unwrap(),
            json!([])
        );
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
        assert!(
            !writer
                .buffer()
                .windows("tasks".len())
                .any(|window| window == b"tasks")
        );
        assert!(
            !writer
                .buffer()
                .windows("name".len())
                .any(|window| window == b"name")
        );
        assert!(
            !writer
                .buffer()
                .windows("options".len())
                .any(|window| window == b"options")
        );
        assert!(
            !writer
                .buffer()
                .windows("actors".len())
                .any(|window| window == b"actors")
        );
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
        println!("splitted: {splitted:?}");
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
        println!("splitted: {splitted:?}");
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
        let set = SSetgidSet::builder(SetBehavior::None)
            .fallback(vec![0, 1])
            .build();
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
        assert!(
            !writer
                .buffer()
                .windows("name".len())
                .any(|window| window == b"name")
        );
        assert!(
            !writer
                .buffer()
                .windows("options".len())
                .any(|window| window == b"options")
        );
        assert!(
            !writer
                .buffer()
                .windows("cred".len())
                .any(|window| window == b"cred")
        );
        assert!(
            !writer
                .buffer()
                .windows("commands".len())
                .any(|window| window == b"commands")
        );
        assert!(
            writer
                .buffer()
                .windows("test".len())
                .any(|window| window == b"test")
        );
    }

    #[test]
    fn test_scommands_all_none() {
        let cmds = SCommands {
            default: Some(SetBehavior::All),
            add: vec![],
            sub: vec![],
            extra_fields: Map::default(),
        };
        let value = to_value(&cmds).unwrap();
        assert!(value.is_string());
        assert_eq!(value, json!("all"));
        let cmds = SCommands {
            default: Some(SetBehavior::None),
            add: vec![],
            sub: vec![],
            extra_fields: Map::default(),
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
            println!("Testing SetBehavior: {behavior:?}");

            // Serialize to CBOR
            let mut cbor_data = Vec::new();
            cbor4ii::serde::to_writer(&mut cbor_data, &behavior).unwrap();
            println!("CBOR data: {cbor_data:02x?}");

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

        println!("Testing SCapabilities: {caps:?}");

        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &caps).unwrap();
        println!("CBOR data: {:?}", String::from_utf8_lossy(&cbor_data));

        // Deserialize from CBOR
        let deserialized: SCapabilities = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(caps, deserialized);
    }

    #[test]
    fn test_scapabilities_every_form_round_trips() {
        let forms = [
            SCapabilities::builder(SetBehavior::None).build(),
            SCapabilities::builder(SetBehavior::All).build(),
            // a list of capabilities, written as a bitmask in CBOR
            SCapabilities::builder(SetBehavior::None)
                .add_cap(Cap::NET_RAW)
                .build(),
            SCapabilities::builder(SetBehavior::None)
                .add_cap(Cap::NET_RAW)
                .add_cap(Cap::LINUX_IMMUTABLE)
                .build(),
            SCapabilities::builder(SetBehavior::All)
                .sub_cap(Cap::SYS_ADMIN)
                .build(),
            SCapabilities::builder(SetBehavior::None)
                .add_cap(Cap::NET_RAW)
                .sub_cap(Cap::SYS_ADMIN)
                .build(),
        ];
        for caps in forms {
            let cbor = cbor4ii::serde::to_vec(Vec::new(), &caps).unwrap();
            let from_cbor: SCapabilities =
                cbor4ii::serde::from_slice(&cbor).unwrap_or_else(|e| panic!("CBOR {caps:?}: {e}"));
            assert_eq!(from_cbor, caps);
            let json = serde_json::to_string(&caps).unwrap();
            let from_json: SCapabilities =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("JSON {caps:?}: {e}"));
            assert_eq!(from_json, caps);
        }
    }

    #[test]
    fn test_policy_with_a_capability_list_round_trips_in_cbor() {
        // the task of the default policy that runs chsr: chsr convert must not lock it out
        let json = r#"{"version":"4.1.0","roles":[{"name":"r_root","actors":[{"type":"user","name":"root"}],"tasks":[{"name":"t_chsr","cred":{"setuid":"root","setgid":"root","capabilities":["CAP_LINUX_IMMUTABLE"]},"commands":["/usr/bin/chsr"]}]}]}"#;
        let policy: SPolicy = serde_json::from_str(json).unwrap();
        let cbor = cbor4ii::serde::to_vec(Vec::new(), &policy).unwrap();
        let again: SPolicy = cbor4ii::serde::from_slice(&cbor).unwrap();
        assert_eq!(to_value(&again).unwrap(), to_value(&policy).unwrap());
    }

    #[test]
    fn test_policy_with_a_group_selector_without_fallback() {
        // dosr accepts it, chsr must load and write it back
        let json = r#"{"version":"4.1.0","roles":[{"name":"r","actors":[{"type":"user","name":"root"}],"tasks":[{"name":"t","cred":{"setgid":{"default":"none","add":[["adm","systemd-journal"]]}},"commands":["/usr/bin/journalctl"]}]}]}"#;
        let policy: SPolicy = serde_json::from_str(json).unwrap();
        let from_json: SPolicy = serde_json::from_value(to_value(&policy).unwrap()).unwrap();
        assert_eq!(to_value(&from_json).unwrap(), to_value(&policy).unwrap());
        let cbor = cbor4ii::serde::to_vec(Vec::new(), &policy).unwrap();
        let from_cbor: SPolicy = cbor4ii::serde::from_slice(&cbor).unwrap();
        assert_eq!(to_value(&from_cbor).unwrap(), to_value(&policy).unwrap());
    }

    #[test]
    fn test_scommands_cbor_roundtrip() {
        let test_cases = vec![
            // Simple string case
            SCommands {
                default: Some(SetBehavior::All),
                add: vec![],
                sub: vec![],
                extra_fields: Map::default(),
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
            println!("Testing SCommands case {i}: {cmds:?}");

            // Serialize to CBOR
            let mut cbor_data = Vec::new();
            cbor4ii::serde::to_writer(&mut cbor_data, &cmds).unwrap();
            println!("CBOR data: {cbor_data:02x?}");

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

        println!("Testing SCredentials: {creds:?}");

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

        println!("Testing SSetgidSet: {mandatory_single:?}");

        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &mandatory_single).unwrap();
        println!("CBOR data: {cbor_data:02x?}");

        // Deserialize from CBOR
        let deserialized: SGroupsEither = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(mandatory_single, deserialized);

        let mandatory_multiple =
            SGroupsEither::MandatoryGroups(SGroups::Multiple(vec![1.into(), 2.into()]));
        println!("Testing SSetgidSet: {mandatory_multiple:?}");
        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &mandatory_multiple).unwrap();
        println!("CBOR data: {cbor_data:02x?}");
        // Deserialize from CBOR
        let deserialized: SGroupsEither = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(mandatory_multiple, deserialized);

        let gidset = SGroupsEither::GroupSelector(
            SSetgidSet::builder(SetBehavior::None)
                .fallback(vec![1, 2])
                .add(vec![4.into(), 5.into()])
                .sub(vec![3.into(), 4.into()])
                .build(),
        );
        println!("Testing SSetgidSet: {gidset:?}");
        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &gidset).unwrap();
        println!("CBOR data: {cbor_data:02x?}");
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

        println!("Testing STask: {task:?}");

        // Serialize to CBOR
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &task).unwrap();
        println!("CBOR data: {cbor_data:02x?}");

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
            println!("Testing SetBehavior: {behavior:?}");
            let mut cbor_data = Vec::new();
            cbor4ii::serde::to_writer(&mut cbor_data, &behavior).unwrap();
            println!("CBOR data: {cbor_data:02x?}");
            let deserialized: SetBehavior = cbor4ii::serde::from_slice(&cbor_data).unwrap();
            assert_eq!(behavior, deserialized);
        }

        // Test simple SCommands
        let cmds = SCommands {
            default: Some(SetBehavior::All),
            add: vec![],
            sub: vec![],
            extra_fields: Map::default(),
        };
        println!("Testing SCommands: {cmds:?}");
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &cmds).unwrap();
        println!("CBOR data: {cbor_data:02x?}");
        let deserialized: SCommands = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(cmds, deserialized);

        // Test STask
        let task = STask::builder("test_task").build();
        println!("Testing STask: {task:?}");
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &task).unwrap();
        println!("CBOR data: {cbor_data:02x?}");
        let deserialized: STask = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert_eq!(task.as_ref().borrow().name, deserialized.name);
    }

    #[test]
    fn test_sactor_cbor_roundtrip() {
        let actor = SActor::user(1000).build();
        println!("Testing SActor: {actor:?}");
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &actor).unwrap();
        println!("CBOR data: {cbor_data:02x?}");
        let deserialized: SActor = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert!(actor.is_user());
        assert_eq!(actor, deserialized);
        let actor = SActor::group(2000).build();
        println!("Testing SActor: {actor:?}");
        let mut cbor_data = Vec::new();
        cbor4ii::serde::to_writer(&mut cbor_data, &actor).unwrap();
        println!("CBOR data: {cbor_data:02x?}");
        let deserialized: SActor = cbor4ii::serde::from_slice(&cbor_data).unwrap();
        assert!(actor.is_group());
        assert_eq!(actor, deserialized);
    }
}
