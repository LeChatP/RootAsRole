use std::{borrow::Cow, collections::HashMap};

use log::{debug, info};
use nix::unistd::Group;
use rar_common::{
    Cred, StorageMethod,
    database::{
        actor::{DActor, DGroups},
        options::Level,
        score::ActorMatchMin,
    },
};
use serde::{
    Deserialize,
    de::{DeserializeSeed, IgnoredAny, Visitor},
};
use serde_json::Value;

use crate::{
    Cli,
    finder::{
        de::{DRoleFinder, DTaskFinder, tasks::TaskListFinderDeserializer, to_storage_m},
        options::{DPathOptions, Opt},
    },
};

pub(super) struct RoleListFinderDeserializer<'a, 'b> {
    pub(super) cli: &'a Cli,
    pub(super) cred: &'a Cred,
    /// spath is scoped only inside the deserialisation, useful for cbor
    pub(super) spath: &'b mut DPathOptions<'a>,
    /// The current user path
    pub(super) env_path: &'a [&'a str],
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for RoleListFinderDeserializer<'a, '_> {
    type Value = Vec<DRoleFinder<'a>>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RoleListFinderVisitor<'a, 'b> {
            cli: &'a Cli,
            cred: &'a Cred,
            spath: &'b mut DPathOptions<'a>,
            env_path: &'a [&'a str],
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for RoleListFinderVisitor<'a, '_> {
            type Value = Vec<DRoleFinder<'a>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("RoleList sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                debug!("RoleListFinderVisitor: visit_seq");
                let mut roles = Vec::new();
                while let Some(role) = seq.next_element_seed(RoleFinderDeserializer {
                    cli: self.cli,
                    cred: self.cred,
                    spath: self.spath,
                    env_path: self.env_path,
                })? {
                    if let Some(role) = role {
                        debug!("adding role {role:?}");
                        roles.push(role);
                    }
                }
                Ok(roles)
            }
        }
        deserializer.deserialize_seq(RoleListFinderVisitor {
            cli: self.cli,
            cred: self.cred,
            spath: self.spath,
            env_path: self.env_path,
        })
    }
}

struct RoleFinderDeserializer<'a, 'b> {
    cli: &'a Cli,
    cred: &'a Cred,
    /// The current user path
    env_path: &'a [&'a str],
    /// spath is scoped only inside the deserialisation, useful for cbor
    spath: &'b mut DPathOptions<'a>,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for RoleFinderDeserializer<'a, '_> {
    type Value = Option<DRoleFinder<'a>>;
    #[allow(clippy::too_many_lines)]
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field<'a> {
            #[serde(alias = "n")]
            Name,
            #[serde(alias = "a", alias = "users")]
            Actors,
            #[serde(alias = "t")]
            Tasks,
            #[serde(alias = "o")]
            Options,
            #[serde(untagged, borrow)]
            Unknown(Cow<'a, str>),
        }

        struct RoleFinderVisitor<'a, 'b> {
            cli: &'a Cli,
            cred: &'a Cred,
            env_path: &'a [&'a str],
            spath: &'b mut DPathOptions<'a>,
            // TODO: If perf problem in cbor you can trash this
            policy_format: StorageMethod,
        }

        impl<'de: 'a, 'a> Visitor<'de> for RoleFinderVisitor<'a, '_> {
            type Value = Option<DRoleFinder<'a>>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a role")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                debug!("RoleFinderVisitor: visit_map");
                let mut role = None;
                let mut tasks: Vec<DTaskFinder<'a>> = Vec::new();
                let mut options = None;
                let mut extra_values = HashMap::new();
                let mut user_min = ActorMatchMin::default();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Options => {
                            debug!("RoleFinderVisitor: options");
                            let mut opt: Opt = map.next_value()?;
                            opt.level = Level::Role;
                            if self.policy_format.is_cbor() // little perf gain in json
                               && let Some(path) = opt.path.as_ref()
                            {
                                self.spath.union(&path.clone());
                            }
                            options = Some(opt);
                        }
                        Field::Name => {
                            debug!("RoleFinderVisitor: name");
                            let role_name = map.next_value()?;
                            if self
                                .cli
                                .opt_filter
                                .as_ref()
                                .and_then(|x| x.role.as_ref())
                                .is_some_and(|r| r != &role_name)
                            {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                            role = Some(role_name);
                        }
                        Field::Actors => {
                            debug!("RoleFinderVisitor: actors");
                            user_min =
                                map.next_value_seed(ActorsFinderDeserializer { cred: self.cred })?;
                        }
                        Field::Tasks => {
                            debug!("RoleFinderVisitor: tasks");
                            tasks = map.next_value_seed(TaskListFinderDeserializer {
                                cli: self.cli,
                                spath: self.spath,
                                env_path: self.env_path,
                            })?;
                        }
                        Field::Unknown(key) => {
                            debug!("RoleFinderVisitor: unknown {key}");
                            let unknown: Value = map.next_value()?;
                            extra_values.insert(key, unknown);
                        }
                    }
                }
                Ok(Some(DRoleFinder {
                    user_min,
                    role: role.unwrap_or_default(),
                    tasks,
                    options,
                    extra_values,
                }))
            }
        }
        const FIELDS: &[&str] = &["name", "tasks", "options"];
        let human_readable = deserializer.is_human_readable();
        deserializer.deserialize_struct(
            "Role",
            FIELDS,
            RoleFinderVisitor {
                cli: self.cli,
                cred: self.cred,
                spath: self.spath,
                env_path: self.env_path,
                policy_format: to_storage_m(human_readable),
            },
        )
    }
}

struct ActorsFinderDeserializer<'a> {
    cred: &'a Cred,
}

impl<'de> DeserializeSeed<'de> for ActorsFinderDeserializer<'_> {
    type Value = ActorMatchMin;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ActorsFinderVisitor<'a> {
            cred: &'a Cred,
        }

        impl<'de> Visitor<'de> for ActorsFinderVisitor<'_> {
            type Value = ActorMatchMin;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a set of users")
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut user_matches = ActorMatchMin::NoMatch;
                while let Some(actor) = seq.next_element::<DActor>()? {
                    debug!("ActorsSettingsVisitor: actor {actor:?}");
                    let temp = Self::user_matches(self.cred, &actor);
                    if temp != ActorMatchMin::NoMatch && temp < user_matches {
                        info!("ActorsSettingsVisitor: Better actor found {temp:?}");
                        user_matches = temp;
                    }
                }
                Ok(user_matches)
            }
        }

        impl ActorsFinderVisitor<'_> {
            fn match_groups(groups: &[Group], role_groups: &[&DGroups<'_>]) -> bool {
                for role_group in role_groups {
                    if match role_group {
                        DGroups::Single(group) => groups.iter().any(|g| group == g),
                        DGroups::Multiple(multiple_actors) => multiple_actors
                            .iter()
                            .all(|actor| groups.iter().any(|g| actor == g)),
                    } {
                        return true;
                    }
                }
                false
            }
            fn user_matches(user: &Cred, actor: &DActor<'_>) -> ActorMatchMin {
                match actor {
                    DActor::User { id, .. } => {
                        if *id == user.user {
                            return ActorMatchMin::UserMatch;
                        }
                    }
                    DActor::Group { groups, .. } => {
                        if Self::match_groups(&user.groups, &[groups]) {
                            return ActorMatchMin::GroupMatch(groups.len());
                        }
                    }
                    DActor::Unknown(element) => {
                        unimplemented!("Unknown actor type: {:?}", element);
                    }
                }
                ActorMatchMin::NoMatch
            }
        }

        deserializer.deserialize_seq(ActorsFinderVisitor { cred: self.cred })
    }
}

#[cfg(test)]
mod test {
    use crate::finder::de::IdTask;

    use super::*;
    use nix::unistd::{getgid, getuid};
    use test_log::test;
    #[test]
    fn test_actors_finder_deserializer() {
        let json = format!(r#"[{{"type": "user", "id": {}}}]"#, getuid().as_raw());
        let deserializer = ActorsFinderDeserializer {
            cred: &Cred::builder().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let user_min = result.unwrap();
        assert_eq!(user_min, ActorMatchMin::UserMatch);
    }

    #[test]
    fn test_role_finder_deserializer() {
        let json = format!(
            r#"{{"name":"r_test","actors":[{{"type": "user", "id": {}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0", 0], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}"#,
            getuid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = RoleFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let role = result.unwrap().unwrap();
        assert_eq!(role.role, "r_test");
        assert_eq!(role.tasks.len(), 1);
        assert_eq!(role.tasks[0].id, IdTask::Name("test".into()));
    }

    #[test]
    fn test_role_list_finder_deserializer() {
        let json = format!(
            r#"[{{"name":"r_test","actors":[{{"type": "user", "id": {}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0", 0], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}]"#,
            getuid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = RoleListFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let role = &result.unwrap()[0];
        assert_eq!(role.role, "r_test");
        assert_eq!(role.tasks.len(), 1);
        assert_eq!(role.tasks[0].id, IdTask::Name("test".into()));
        let json = format!(
            r#"[{{"name":"r_test","actors":[{{"type": "group", "id": {}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0", 0], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}]"#,
            getgid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = RoleListFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let role = &result.unwrap()[0];
        assert_eq!(role.role, "r_test");
        assert_eq!(role.tasks.len(), 1);
        assert_eq!(role.tasks[0].id, IdTask::Name("test".into()));
        let json = r#"[{"name":"r_test","actors":[{"type": "user", "id": "874510"}], "tasks": [{"name": "test", "cred": {"setuid":"0", "setgid":["0", 0], "caps": []}, "commands": ["/usr/bin/ls"]}]}]"#.to_string();
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = RoleListFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].user_min, ActorMatchMin::NoMatch);
    }

    #[test]
    fn test_expecting_errors() {
        let int = "1";
        let cli = Cli::builder().build();
        let json = r#"{"unknown": "unknown"}"#;
        let deserializer = RoleFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(
            result.is_ok(),
            "Expected role with nothing in it, got: {result:?}"
        );
        let actors = ActorsFinderDeserializer {
            cred: &Cred::builder().build(),
        };
        let result = actors.deserialize(&mut serde_json::Deserializer::from_str(int));
        assert!(result.is_err(), "Expected error, got: {result:?}");
        let role = RoleFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = role.deserialize(&mut serde_json::Deserializer::from_str(int));
        assert!(result.is_err(), "Expected error, got: {result:?}");
    }
}
