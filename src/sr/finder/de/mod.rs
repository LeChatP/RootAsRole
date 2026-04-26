use std::{borrow::Cow, collections::HashMap, fmt::Display, ops::Deref, path::PathBuf};

use bon::Builder;
use derivative::Derivative;
use log::debug;
use rar_common::{
    Cred, StorageMethod,
    database::{
        options::Level,
        score::{ActorMatchMin, CmdMin, Score, SecurityMin, TaskScore},
        structs::SetBehavior,
    },
};
use serde::{
    Deserialize,
    de::{DeserializeSeed, IgnoredAny, Visitor},
};
use serde_json::Value;
use strum::EnumIs;

use crate::{
    Cli,
    finder::{
        de::{cred::CredData, roles::RoleListFinderDeserializer},
        options::DPathOptions,
    },
};

use super::options::Opt;

pub mod commands;
pub mod cred;
pub mod opt;
pub mod roles;
pub mod tasks;

#[cfg_attr(test, derive(Builder))]
#[derive(PartialEq, Eq, Debug, Default)]
pub struct DConfigFinder<'a> {
    pub options: Option<Opt<'a>>,
    pub roles: Vec<DRoleFinder<'a>>,
}

#[cfg_attr(test, derive(Builder))]
#[derive(Debug, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct DRoleFinder<'a> {
    #[cfg_attr(test, builder(default))]
    pub user_min: ActorMatchMin,
    #[cfg_attr(test, builder(into))]
    pub role: Cow<'a, str>,
    #[cfg_attr(test, builder(default))]
    pub tasks: Vec<DTaskFinder<'a>>,
    pub options: Option<Opt<'a>>,
    #[cfg_attr(test, builder(default))]
    pub extra_values: HashMap<Cow<'a, str>, Value>,
}

#[derive(Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum IdTask<'a> {
    Name(#[serde(borrow)] Cow<'a, str>),
    Number(usize),
}

impl Display for IdTask<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdTask::Name(name) => write!(f, "{name}"),
            IdTask::Number(num) => write!(f, "{num}"),
        }
    }
}

#[derive(Debug, Derivative, Builder)]
#[derivative(PartialEq, Eq)]
pub struct DTaskFinder<'a> {
    pub id: IdTask<'a>,
    #[builder(default)]
    pub score: TaskScore,
    pub cred: CredData<'a>,
    pub commands: Option<DCommandList<'a>>,
    pub options: Option<Opt<'a>>,
    pub final_path: Option<PathBuf>,
}

/// This struct keeps the list of commands because options may be written after
#[cfg_attr(test, derive(Builder))]
#[derive(PartialEq, Eq, Debug)]
pub struct DCommandList<'a> {
    #[cfg_attr(test, builder(start_fn, into))]
    pub default_behavior: Option<SetBehavior>,
    #[cfg_attr(test, builder(default, into))]
    pub add: Cow<'a, [DCommand<'a>]>,
    #[cfg_attr(test, builder(default, into))]
    pub del: Cow<'a, [DCommand<'a>]>,
}

#[derive(Deserialize, PartialEq, Eq, Debug, EnumIs, Clone)]
#[serde(untagged)]
pub enum DCommand<'a> {
    Simple(#[serde(borrow)] Cow<'a, str>),
    Complex(Value),
}

#[cfg(test)]
impl<'a> DCommand<'a> {
    pub fn simple(cmd: &'a str) -> Self {
        DCommand::Simple(Cow::Borrowed(cmd))
    }
    pub fn complex(cmd: Value) -> Self {
        DCommand::Complex(cmd)
    }
}

/// This is clearer for me to understanf what type is ``is_human_readable``
#[inline]
const fn to_storage_m(is_human_readable: bool) -> StorageMethod {
    if is_human_readable {
        StorageMethod::JSON
    } else {
        StorageMethod::CBOR
    }
}

impl<'a> DConfigFinder<'a> {
    pub fn roles<'s>(&'s self) -> impl Iterator<Item = DLinkedRole<'s, 'a>> {
        self.roles.iter().map(|role| DLinkedRole::new(self, role))
    }

    #[cfg(any(feature = "hierarchy", feature = "ssd"))]
    pub fn role<'s>(&'s self, role_name: &str) -> Option<DLinkedRole<'s, 'a>> {
        self.roles
            .iter()
            .find(|r| r.role == role_name)
            .map(|role| DLinkedRole::new(self, role))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DLinkedRole<'c, 'a> {
    parent: &'c DConfigFinder<'a>,
    role: &'c DRoleFinder<'a>,
}

impl<'c, 'a> DLinkedRole<'c, 'a> {
    const fn new(parent: &'c DConfigFinder<'a>, role: &'c DRoleFinder<'a>) -> Self {
        Self { parent, role }
    }

    pub fn tasks<'t>(&'t self) -> impl Iterator<Item = DLinkedTask<'t, 'c, 'a>> {
        self.role
            .tasks
            .iter()
            .map(|task| DLinkedTask::new(self, task))
    }

    pub const fn role(&self) -> &DRoleFinder<'a> {
        self.role
    }

    pub const fn config(&self) -> &DConfigFinder<'a> {
        self.parent
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DLinkedTask<'t, 'c, 'a> {
    parent: &'t DLinkedRole<'c, 'a>,
    pub task: &'t DTaskFinder<'a>,
}

impl<'t, 'c, 'a> DLinkedTask<'t, 'c, 'a> {
    const fn new(parent: &'t DLinkedRole<'c, 'a>, task: &'t DTaskFinder<'a>) -> Self {
        Self { parent, task }
    }

    pub fn commands<'l>(&'l self) -> Option<DLinkedCommandList<'l, 't, 'c, 'a>> {
        self.task
            .commands
            .as_ref()
            .map(|list| DLinkedCommandList::new(self, list))
    }

    pub const fn role(&self) -> &DLinkedRole<'c, 'a> {
        self.parent
    }

    pub const fn task(&self) -> &DTaskFinder<'a> {
        self.task
    }

    pub fn score(&self, cmd_min: CmdMin, security_min: SecurityMin) -> Score {
        Score::builder()
            .user_min(self.role().role.user_min)
            .caps_min(self.score.caps_min)
            .cmd_min(cmd_min)
            .security_min(security_min)
            .setuser_min(self.score.setuser_min)
            .build()
    }
}

impl<'a> Deref for DLinkedTask<'_, '_, 'a> {
    type Target = DTaskFinder<'a>;
    fn deref(&self) -> &Self::Target {
        self.task
    }
}

pub struct DLinkedCommandList<'l, 't, 'c, 'a> {
    #[allow(dead_code)] // TODO: remove this
    parent: &'l DLinkedTask<'t, 'c, 'a>,
    command_list: &'l DCommandList<'a>,
}

impl<'l, 't, 'c, 'a> DLinkedCommandList<'l, 't, 'c, 'a> {
    const fn new(parent: &'l DLinkedTask<'t, 'c, 'a>, list: &'l DCommandList<'a>) -> Self {
        Self {
            parent,
            command_list: list,
        }
    }

    pub fn add<'d>(&'d self) -> impl Iterator<Item = DLinkedCommand<'d, 'l, 't, 'c, 'a>> {
        self.command_list
            .add
            .iter()
            .map(|cmd| DLinkedCommand::new(self, cmd))
    }

    pub fn del<'d>(&'d self) -> impl Iterator<Item = DLinkedCommand<'d, 'l, 't, 'c, 'a>> {
        self.command_list
            .del
            .iter()
            .map(|cmd| DLinkedCommand::new(self, cmd))
    }
}

impl<'a> Deref for DLinkedCommandList<'_, '_, '_, 'a> {
    type Target = DCommandList<'a>;
    fn deref(&self) -> &Self::Target {
        self.command_list
    }
}

pub struct DLinkedCommand<'d, 'l, 't, 'c, 'a> {
    #[allow(dead_code)] // TODO: remove this
    parent: &'d DLinkedCommandList<'l, 't, 'c, 'a>,
    pub command: &'d DCommand<'a>,
}

impl<'d, 'l, 't, 'c, 'a> DLinkedCommand<'d, 'l, 't, 'c, 'a> {
    const fn new(
        parent: &'d DLinkedCommandList<'l, 't, 'c, 'a>,
        command: &'d DCommand<'a>,
    ) -> Self {
        Self { parent, command }
    }

    #[allow(dead_code)] // TODO: remove this
    pub const fn task(&self) -> &DLinkedTask<'t, 'c, 'a> {
        self.parent.parent
    }
}

impl<'a> Deref for DLinkedCommand<'_, '_, '_, '_, 'a> {
    type Target = DCommand<'a>;
    fn deref(&self) -> &Self::Target {
        self.command
    }
}

/// This is the highly efficient deserializer
/// It is a lossy deserialiser, It skips information that is not matching the current user who is running the program
pub struct ConfigFinderDeserializer<'a> {
    pub cli: &'a Cli,
    pub cred: &'a Cred,
    /// The current user path
    pub env_path: &'a [&'a str],
}

/// Let me explain a bit my deserialisation process
/// Here you get only ``Options``, ``Roles``. Options can arrive after Roles and vice-versa
/// In order to evaluate commands, you need PATH env var.
/// PATH var is defined in Options
/// So, we need to store Options for all the deserialisation process
/// (for Global case, other cases, see ``RoleFinderDeserializer``)
impl<'de: 'a, 'a> DeserializeSeed<'de> for ConfigFinderDeserializer<'a> {
    type Value = DConfigFinder<'a>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field<'a> {
            #[serde(alias = "o")]
            Options,
            #[serde(alias = "r")]
            Roles,
            #[serde(untagged, borrow)]
            #[allow(dead_code)]
            Unknown(Cow<'a, str>),
        }

        struct ConfigFinderVisitor<'a> {
            cli: &'a Cli,
            cred: &'a Cred,
            env_path: &'a [&'a str],
            policy_format: StorageMethod,
        }

        impl<'de: 'a, 'a> Visitor<'de> for ConfigFinderVisitor<'a> {
            type Value = DConfigFinder<'a>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("policy")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut options = None;
                let mut roles = Vec::new();
                let mut spath = DPathOptions::default_path();
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Options => {
                            debug!("ConfigFinderVisitor: options");
                            let mut opt: Opt = map.next_value()?;
                            opt.level = Level::Global;
                            // if we are in binary format, we know that options are before roles
                            // then it means that we can use spath for Roles
                            // so we can optimize the processing
                            if self.policy_format.is_cbor() // little perf gain in json. If perf pb, you can trash this
                                && let Some(path) = opt.path.as_ref()
                            {
                                spath.union(&path.clone());
                            }
                            options = Some(opt);
                        }
                        Field::Roles => {
                            debug!("ConfigFinderVisitor: roles");
                            roles = map.next_value_seed(RoleListFinderDeserializer {
                                cli: self.cli,
                                cred: self.cred,
                                spath: &mut spath,
                                env_path: self.env_path,
                            })?;
                        }
                        Field::Unknown(_) => {
                            debug!("ConfigFinderVisitor: unknown");
                            let _ = map.next_value::<IgnoredAny>();
                        }
                    }
                }
                Ok(DConfigFinder { options, roles })
            }
        }
        const FIELDS: &[&str] = &["options", "roles", "version"];
        let human_readable = to_storage_m(deserializer.is_human_readable());
        deserializer.deserialize_struct(
            "Config",
            FIELDS,
            ConfigFinderVisitor {
                cli: self.cli,
                cred: self.cred,
                policy_format: human_readable,
                env_path: self.env_path,
            },
        )
    }
}

#[cfg(test)]
mod tests {

    use std::fs;

    use crate::finder::de::tasks::TaskListFinderDeserializer;

    use super::*;
    use cbor4ii::core::utils::SliceReader;
    use nix::unistd::{getgid, getuid};
    use rar_common::database::{
        actor::SGroups,
        score::{CapsMin, SetUserMin, SetgidMin, SetuidMin},
    };
    use test_log::test;

    pub fn get_non_root_uid(nth: usize) -> Option<u32> {
        // list all users
        let passwd = fs::read_to_string("/etc/passwd").unwrap();
        let passwd: Vec<&str> = passwd.split('\n').collect();
        passwd
            .iter()
            .map(|line| {
                let line: Vec<&str> = line.split(':').collect();
                line[2].parse::<u32>().unwrap()
            })
            .filter(|uid| *uid != 0)
            .nth(nth)
    }

    pub fn get_non_root_gid(nth: usize) -> Option<u32> {
        // list all users
        let passwd = fs::read_to_string("/etc/group").unwrap();
        let passwd: Vec<&str> = passwd.split('\n').collect();
        passwd
            .iter()
            .map(|line| {
                let line: Vec<&str> = line.split(':').collect();
                line[2].parse::<u32>().unwrap()
            })
            .filter(|uid| *uid != 0)
            .nth(nth)
    }

    pub fn convert_json_to_cbor(json: &str) -> Vec<u8> {
        let value: Value = serde_json::from_str(json).unwrap();

        cbor4ii::serde::to_vec(Vec::new(), &value).unwrap()
    }

    #[test]
    fn test_idtask_display() {
        let name = IdTask::Name(Cow::Borrowed("test"));
        let number = IdTask::Number(42);
        assert_eq!(format!("{name}"), "test");
        assert_eq!(format!("{number}"), "42");
    }

    #[test]
    fn test_dcommandlist_deserialize_seq() {
        let json = r#"["ls", "cat"]"#;
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.add.len(), 2);
        assert!(matches!(list.add[0], DCommand::Simple(_)));
    }

    #[test]
    fn test_dcommandlist_deserialize_map() {
        let json = r#"{"default": "all", "add": ["ls"], "del": ["rm"]}"#;
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.default_behavior.unwrap(), SetBehavior::All);
        assert_eq!(list.add.len(), 1);
        assert_eq!(list.del.len(), 1);
    }

    #[test]
    fn test_dcommandlist_deserialize_all_or_none() {
        let json = "\"all\"";
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.default_behavior, Some(SetBehavior::All));
        assert_eq!(list.add.len(), 0);
        assert_eq!(list.del.len(), 0);
        let json = "\"none\"";
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.default_behavior, Some(SetBehavior::None));
        assert_eq!(list.add.len(), 0);
        assert_eq!(list.del.len(), 0);
    }

    #[test]
    fn test_dcommandlist_deserialize_empty() {
        let json = "{}";
        let list: DCommandList = serde_json::from_str(json).unwrap();
        assert_eq!(list.default_behavior, None);
        assert_eq!(list.add.len(), 0);
        assert_eq!(list.del.len(), 0);
    }

    #[test]
    fn test_dcommandlist_deserialize_invalid() {
        let json = r#"{"default": "invalid", "add": ["ls"], "del": ["rm"]}"#;
        let result: Result<DCommandList, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_finder_deserializer() {
        let json = format!(
            r#"{{"roles":[{{"name":"r_test","actors":[{{"type": "user", "id": {}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0", 0], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}]}}"#,
            getuid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().curdir().unwrap().groups().unwrap().user().unwrap().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let config = result.unwrap();
        assert_eq!(config.roles.len(), 1);
        assert_eq!(config.roles[0].role, "r_test");
    }

    #[test]
    fn test_config_finder_implementation() {
        let json = format!(
            r#"{{"roles":[{{"name":"r_test","actors":[{{"type":"user","id":{}}}],"tasks":[{{"name":"test","cred":{{"setuid":"0","setgid":["0",0],"caps":[]}},"commands":["/usr/bin/ls"]}},{{"name":"test2","cred":{{"setuid":"0","setgid":["0",0],"caps":[]}},"commands":["/usr/bin/ls","/usr/bin/cat"]}}]}},{{"name":"r_test2","actors":[{{"type":"group","names":[{}, {}]}}],"tasks":[{{"name":"test3","cred":{{"setuid":"0","setgid":["0",0],"caps":[]}},"commands":["/usr/bin/cat","/usr/bin/ls"]}}]}}]}}"#,
            getuid().as_raw(),
            getgid().as_raw(),
            getgid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().curdir().unwrap().groups().unwrap().user().unwrap().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let config = result.unwrap();
        let mut roles = config.roles();
        let role_a = roles.next().unwrap();
        assert_eq!(role_a.role().role, "r_test");
        let mut tasks = role_a.tasks();
        let task_a = tasks.next().unwrap();
        assert_eq!(task_a.task().id, IdTask::Name("test".into()));
        let commands = task_a.commands().unwrap();
        assert_eq!(commands.add().count(), 1);
        assert_eq!(
            *commands.add().next().unwrap().command,
            DCommand::Simple("/usr/bin/ls".into())
        );
        let task_b = tasks.next().unwrap();
        assert_eq!(task_b.task().id, IdTask::Name("test2".into()));
        let commands = task_b.commands().unwrap();
        assert_eq!(commands.add().count(), 2);
        assert_eq!(
            *commands.add().next().unwrap().command,
            DCommand::Simple("/usr/bin/ls".into())
        );
        assert_eq!(
            *commands.add().nth(1).unwrap().command,
            DCommand::Simple("/usr/bin/cat".into())
        );
        assert!(tasks.next().is_none());
        let role_b = roles.next().unwrap();
        assert_eq!(role_b.role().role, "r_test2");
        let mut tasks = role_b.tasks();
        let task_a = tasks.next().unwrap();
        assert_eq!(task_a.task().id, IdTask::Name("test3".into()));
        let commands = task_a.commands().unwrap();
        assert_eq!(commands.add().count(), 2);
        assert_eq!(
            *commands.add().next().unwrap().command,
            DCommand::Simple("/usr/bin/cat".into())
        );
        assert_eq!(
            *commands.add().nth(1).unwrap().command,
            DCommand::Simple("/usr/bin/ls".into())
        );
        assert_eq!(commands.del().count(), 0);
        assert!(tasks.next().is_none());
        assert!(roles.next().is_none());
        assert!(config.options.is_none());
        assert!(config.roles[0].options.is_none());
        assert!(config.roles[0].tasks[0].options.is_none());
        assert!(config.roles[0].tasks[1].options.is_none());
        assert!(config.roles[1].options.is_none());
        assert!(config.roles[1].tasks[0].options.is_none());
        assert!(config.role("r_test").is_some());
        assert!(config.role("r_test2").is_some());
        assert!(config.role("r_test3").is_none());
        assert_eq!(*config.role("r_test").unwrap().config(), config);
        assert_eq!(*config.role("r_test2").unwrap().config(), config);
        assert_eq!(
            *config
                .role("r_test")
                .unwrap()
                .tasks()
                .next()
                .unwrap()
                .role(),
            config.role("r_test").unwrap()
        );
        assert_eq!(
            *config
                .role("r_test2")
                .unwrap()
                .tasks()
                .next()
                .unwrap()
                .role(),
            config.role("r_test2").unwrap()
        );
        assert_eq!(
            config
                .role("r_test")
                .unwrap()
                .tasks()
                .next()
                .unwrap()
                .score(CmdMin::MATCH, SecurityMin::empty()),
            Score::builder()
                .user_min(ActorMatchMin::UserMatch)
                .setuser_min(SetUserMin {
                    uid: Some(SetuidMin::from(0)),
                    gid: Some(SetgidMin::from(SGroups::from(vec![0])))
                })
                .caps_min(CapsMin::NoCaps)
                .security_min(SecurityMin::empty())
                .cmd_min(CmdMin::MATCH)
                .build()
        );
    }

    #[test]
    fn test_config_with_options() {
        let json = format!(
            r#"{{
    "options": {{
        "timeout": {{
            "type": "ppid",
            "duration": "00:05:00"
        }},
        "path": {{
            "default": "delete",
            "add": [
                "/usr/bin"
            ]
        }},
        "env": {{
            "default": "delete",
            "override_behavior": false,
            "keep": [
                "keep1"
            ],
            "check": [
                "check1"
            ],
            "delete": [
                "del1"
            ],
            "set": {{
                "set1": "value1",
                "set2": "value2"
            }}
        }},
        "root": "user",
        "bounding": "strict"
    }},
    "roles": [
        {{
            "options": {{
                "timeout": {{
                    "type": "ppid",
                    "duration": "00:06:00"
                }},
                "path": {{
                    "default": "delete",
                    "add": [
                        "/usr/bin"
                    ]
                }},
                "env": {{
                    "default": "delete",
                    "override_behavior": false,
                    "keep": [
                        "keep2"
                    ],
                    "check": [
                        "check2"
                    ],
                    "delete": [
                        "del2"
                    ],
                    "set": {{
                        "set1": "value2",
                        "set3": "value3"
                    }}
                }},
                "root": "user",
                "bounding": "strict"
            }},
            "name": "role1",
            "actors": [
                {{
                    "type": "user",
                    "id": {}
                }}
            ],
            "tasks": [
                {{
                    "options": {{
                        "timeout": {{
                            "type": "ppid",
                            "duration": "00:07:00"
                        }},
                        "path": {{
                            "default": "delete",
                            "add": [
                                "/usr/bin"
                            ]
                        }},
                        "env": {{
                            "default": "delete",
                            "override_behavior": false,
                            "keep": [
                                "keep3"
                            ],
                            "check": [
                                "check3"
                            ],
                            "delete": [
                                "del3"
                            ],
                            "set": {{
                                "set1": "value3",
                                "set4": "value4"
                            }}
                        }},
                        "root": "user",
                        "bounding": "strict"
                    }},
                    "name": "task1",
                    "cred": {{
                        "setuid": 0,
                        "setgid": 0,
                        "caps": [
                            "CAP_SYS_ADMIN",
                            "CAP_SYS_RESOURCE"
                        ]
                    }}
                }}
            ]
        }}
    ]
}}"#,
            getuid().as_raw()
        );
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().curdir().unwrap().groups().unwrap().user().unwrap().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let config = result.unwrap();
        assert_eq!(config.roles.len(), 1);
        assert_eq!(config.roles[0].role, "role1");
        assert_eq!(config.roles[0].tasks.len(), 1);
        assert_eq!(config.roles[0].tasks[0].id, IdTask::Name("task1".into()));
        assert!(config.options.is_some());
        assert!(config.roles[0].options.is_some());
        assert!(config.roles[0].tasks[0].options.is_some());
    }

    #[test]
    fn test_config_optimized_with_options() {
        let json = format!(
            r#"{{
    "options": {{
        "timeout": {{
            "type": "ppid",
            "duration": "00:05:00"
        }},
        "path": {{
            "default": "delete",
            "add": [
                "/usr/bin"
            ]
        }},
        "env": {{
            "default": "delete",
            "override_behavior": false,
            "keep": [
                "keep1"
            ],
            "check": [
                "check1"
            ],
            "delete": [
                "del1"
            ],
            "set": {{
                "set1": "value1",
                "set2": "value2"
            }}
        }},
        "root": "user",
        "bounding": "strict"
    }},
    "roles": [
        {{
            "options": {{
                "timeout": {{
                    "type": "ppid",
                    "duration": "00:06:00"
                }},
                "path": {{
                    "default": "delete",
                    "add": [
                        "/usr/bin"
                    ]
                }},
                "env": {{
                    "default": "delete",
                    "override_behavior": false,
                    "keep": [
                        "keep2"
                    ],
                    "check": [
                        "check2"
                    ],
                    "delete": [
                        "del2"
                    ],
                    "set": {{
                        "set1": "value2",
                        "set3": "value3"
                    }}
                }},
                "root": "user",
                "bounding": "strict"
            }},
            "name": "role1",
            "actors": [
                {{
                    "type": "group",
                    "id": {}
                }}
            ],
            "tasks": [
                {{
                    "options": {{
                        "timeout": {{
                            "type": "ppid",
                            "duration": "00:07:00"
                        }},
                        "path": {{
                            "default": "delete",
                            "add": [
                                "/usr/bin"
                            ]
                        }},
                        "env": {{
                            "default": "delete",
                            "override_behavior": false,
                            "keep": [
                                "keep3"
                            ],
                            "check": [
                                "check3"
                            ],
                            "delete": [
                                "del3"
                            ],
                            "set": {{
                                "set1": "value3",
                                "set4": "value4"
                            }}
                        }},
                        "root": "user",
                        "bounding": "strict"
                    }},
                    "name": "task1",
                    "cred": {{
                        "setuid": 0,
                        "setgid": 0,
                        "caps": [
                            "CAP_SYS_ADMIN",
                            "CAP_SYS_RESOURCE"
                        ]
                    }},
                    "commands": ["/usr/bin/ls"]
                }}
            ]
        }}
    ]
}}"#,
            getgid().as_raw()
        );
        //convert json to cbor4ii
        let cbor = convert_json_to_cbor(&json);
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().curdir().unwrap().groups().unwrap().user().unwrap().build(),
        };
        let result: Result<DConfigFinder<'_>, _> = deserializer.deserialize(
            &mut cbor4ii::serde::Deserializer::new(SliceReader::new(cbor.as_slice())),
        );
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let config = result.unwrap();
        assert_eq!(config.roles.len(), 1);
        assert_eq!(config.roles[0].role, "role1");
        assert_eq!(config.roles[0].tasks.len(), 1);
        assert_eq!(config.roles[0].tasks[0].id, IdTask::Name("task1".into()));
        assert!(config.options.is_some());
        assert!(config.roles[0].options.is_some());
        assert!(config.roles[0].tasks[0].options.is_some());
        assert_eq!(config.roles[0].user_min, ActorMatchMin::GroupMatch(1));
        assert_eq!(config.roles[0].tasks[0].score.cmd_min, CmdMin::MATCH);
        assert_eq!(
            config.roles[0].tasks[0].score.setuser_min.uid,
            Some(SetuidMin::from(&0.into()))
        );
        assert_eq!(
            config.roles[0].tasks[0].score.setuser_min.gid,
            Some(SetgidMin::from(&vec![0]))
        );
        assert_eq!(
            config.roles[0].tasks[0].score.caps_min,
            CapsMin::CapsAdmin(2)
        );
        assert!(config.roles[0].tasks[0].commands.is_none());
        assert_eq!(
            config.roles[0].tasks[0].final_path,
            Some(PathBuf::from("/usr/bin/ls"))
        );
    }

    #[test]
    fn test_optimized_config() {
        let uid = getuid().as_raw();
        let json = format!(
            r#"{{"roles":[{{"name":"r_test","actors":[{{"type": "user", "id": {uid}}}], "tasks": [{{"name": "test", "cred": {{"setuid":"0", "setgid":["0"], "caps": []}}, "commands": ["/usr/bin/ls"]}}]}}]}}"#
        );
        //convert json to cbor4ii
        let cbor = convert_json_to_cbor(&json);
        let cli = Cli::builder().cmd_path("ls").build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &["/usr/bin"],
            cred: &Cred::builder().curdir().unwrap().groups().unwrap().user().unwrap().build(),
        };
        let result: Result<DConfigFinder<'_>, _> = deserializer.deserialize(
            &mut cbor4ii::serde::Deserializer::new(SliceReader::new(cbor.as_slice())),
        );
        assert!(result.is_ok(), "Failed to deserialize: {result:?}");
        let config = result.unwrap();
        assert_eq!(config.roles[0].user_min, ActorMatchMin::UserMatch);
        assert_eq!(config.roles[0].tasks[0].score.cmd_min, CmdMin::MATCH);
        assert_eq!(
            config.roles[0].tasks[0].score.setuser_min.uid,
            Some(SetuidMin::from(&0.into()))
        );
        assert_eq!(
            config.roles[0].tasks[0].score.setuser_min.gid,
            Some(SetgidMin::from(&vec![0]))
        );
        assert_eq!(config.roles[0].tasks[0].score.caps_min, CapsMin::NoCaps);
        assert!(config.roles[0].tasks[0].commands.is_none());
        assert_eq!(
            config.roles[0].tasks[0].final_path,
            Some(PathBuf::from("/usr/bin/ls"))
        );
    }

    #[test]
    fn test_expecting_error() {
        let seq = "[1, 2, 3]";
        let map = "{\"1\": 2, \"3\": 4}";
        let cli = Cli::builder().build();
        let config_finder = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().curdir().unwrap().groups().unwrap().user().unwrap().build(),
        };
        let result = config_finder.deserialize(&mut serde_json::Deserializer::from_str(seq));
        assert!(result.is_err(), "Expected error, got: {result:?}");

        let role_list = RoleListFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().curdir().unwrap().groups().unwrap().user().unwrap().build(),
            spath: &mut DPathOptions::default(),
        };
        let result = role_list.deserialize(&mut serde_json::Deserializer::from_str(map));
        assert!(result.is_err(), "Expected error, got: {result:?}");
        let task_list = TaskListFinderDeserializer {
            cli: &cli,
            env_path: &[],
            spath: &mut DPathOptions::default(),
        };
        let result = task_list.deserialize(&mut serde_json::Deserializer::from_str(map));
        assert!(result.is_err(), "Expected error, got: {result:?}");
    }

    // this test is to check if the deserializer can handle unknown types... It might evolve in the future
    #[test]
    fn test_unknown_type() {
        let json = r#"{"unknown": "unknown"}"#;
        let cli = Cli::builder().build();
        let deserializer = ConfigFinderDeserializer {
            cli: &cli,
            env_path: &[],
            cred: &Cred::builder().curdir().unwrap().groups().unwrap().user().unwrap().build(),
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(
            result.is_ok(),
            "Expected config with nothing in it, got: {result:?}"
        );
    }
}
