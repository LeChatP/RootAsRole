use std::borrow::Cow;

use log::debug;
use rar_common::{
    StorageMethod,
    database::{options::Level, score::TaskScore},
};
use serde::{
    Deserialize,
    de::{DeserializeSeed, IgnoredAny},
};

use crate::{
    Cli,
    finder::{
        de::{
            DTaskFinder, IdTask,
            commands::DCommandListDeserializer,
            cred::{CredData, CredFinderDeserializerReturn},
            to_storage_m,
        },
        options::{DPathOptions, Opt},
    },
};

pub(super) struct TaskListFinderDeserializer<'a, 'b> {
    pub(super) cli: &'a Cli,
    /// The current user path
    pub(super) env_path: &'a [&'a str],
    /// spath is scoped only inside the deserialisation, useful for cbor
    pub(super) spath: &'b mut DPathOptions<'a>,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for TaskListFinderDeserializer<'a, '_> {
    type Value = Vec<DTaskFinder<'a>>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TaskListFinderVisitor<'a, 'b> {
            cli: &'a Cli,
            spath: &'b mut DPathOptions<'a>,
            env_path: &'a [&'a str],
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for TaskListFinderVisitor<'a, '_> {
            type Value = Vec<DTaskFinder<'a>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("TaskList sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut tasks = Vec::new();
                let mut i = 0;
                while let Some(element) = seq.next_element_seed(TaskFinderDeserializer {
                    cli: self.cli,
                    spath: self.spath,
                    env_path: self.env_path,
                    i,
                })? {
                    if let Some(task) = element {
                        debug!("adding task {task:?}");
                        tasks.push(task);
                        i += 1;
                    }
                }
                Ok(tasks)
            }
        }
        deserializer.deserialize_seq(TaskListFinderVisitor {
            cli: self.cli,
            spath: self.spath,
            env_path: self.env_path,
        })
    }
}

struct TaskFinderDeserializer<'a, 'b> {
    cli: &'a Cli,
    i: usize,
    /// The current user path
    env_path: &'a [&'a str],
    /// spath is scoped only inside the deserialisation, useful for cbor
    spath: &'b mut DPathOptions<'a>,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for TaskFinderDeserializer<'a, '_> {
    type Value = Option<DTaskFinder<'a>>;

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
            #[serde(alias = "i", alias = "credentials")]
            Cred,
            #[serde(alias = "c", alias = "cmds")]
            Commands,
            #[serde(alias = "o")]
            Options,
            #[serde(untagged, borrow)]
            Unknown(Cow<'a, str>),
        }

        struct TaskFinderVisitor<'a, 'b> {
            cli: &'a Cli,
            i: usize,
            env_path: &'a [&'a str],
            spath: &'b mut DPathOptions<'a>,
            storage_method: StorageMethod,
        }

        impl<'de: 'a, 'a> serde::de::Visitor<'de> for TaskFinderVisitor<'a, '_> {
            type Value = Option<DTaskFinder<'a>>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("STask structure")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                // Use local temporaries for each field
                let mut id = IdTask::Number(self.i);
                let mut score = TaskScore::default();
                let mut commands = None;
                let mut options = None;
                let mut final_path = None;
                //let mut extra_values = HashMap::new();
                let mut cred = CredData::default();

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Options => {
                            debug!("TaskFinderVisitor: options");
                            let mut opt: Opt = map.next_value()?;
                            opt.level = Level::Task;
                            if self.storage_method.is_cbor()
                                && let Some(path) = opt.path.as_ref()
                            {
                                self.spath.union(&path.clone());
                            }
                            if self.cli.info && opt.execinfo.is_some_and(|i| i.is_hide()) {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                            // skip the task if env_override is required and not allowed
                            if self.cli.opt_filter.as_ref().is_some_and(|o| {
                                // we have a filter
                                o.env_behavior.as_ref().is_some_and(|_| {
                                    // the filter overrides env behavior
                                    opt.env.as_ref().is_some_and(|e| {
                                        // the task specifies env options
                                        e.override_behavior.is_some_and(|b| !b) // the task specifies override behavior and deny it
                                    })
                                })
                                // in any other case, we cannot know if this task is valid or not (as we don't know the inherited env override value)
                            }) {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                            options = Some(opt);
                        }
                        Field::Name => {
                            debug!("TaskFinderVisitor: name");
                            let task_name = map.next_value()?;
                            if self
                                .cli
                                .opt_filter
                                .as_ref()
                                .and_then(|x| x.task.as_ref())
                                .is_some_and(|t| IdTask::Name(t.into()) != task_name)
                            {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                            id = task_name;
                        }
                        Field::Cred => {
                            debug!("TaskFinderVisitor: cred");
                            let result = map
                                .next_value_seed(CredFinderDeserializerReturn { cli: self.cli })?;
                            if !result.ok {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }
                            cred = result.cred;
                            score.setuser_min = result.score.setuser_min;
                            score.caps_min = result.score.caps_min;
                        }
                        Field::Commands => {
                            debug!("TaskFinderVisitor: commands");
                            // if json -> next_value (store)
                            // else -> next_value_seed -> use deserializer, thus highly optimizing
                            if self.storage_method.is_json() {
                                commands = Some(map.next_value()?);
                            } else {
                                map.next_value_seed(DCommandListDeserializer {
                                    env_path: &self.spath.calc_path(self.env_path),
                                    cmd_path: &self.cli.cmd_path,
                                    cmd_args: &self.cli.cmd_args,
                                    final_path: &mut final_path,
                                    cmd_min: &mut score.cmd_min,
                                    blocker: false,
                                })?;
                            }
                        }
                        Field::Unknown(_key) => {
                            debug!("TaskFinderVisitor: unknown");
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                debug!("TaskFinderVisitor: final_path {final_path:?}");
                Ok(Some(DTaskFinder {
                    id,
                    score,
                    cred,
                    commands,
                    options,
                    final_path,
                }))
            }
        }

        const FIELDS: &[&str] = &["name", "cred", "commands", "options"];
        let human_readable = deserializer.is_human_readable();
        deserializer.deserialize_struct(
            "STask",
            FIELDS,
            TaskFinderVisitor {
                i: self.i,
                cli: self.cli,
                env_path: self.env_path,
                spath: self.spath,
                storage_method: to_storage_m(human_readable),
            },
        )
    }
}

#[cfg(test)]
mod test {
    use serde::de::DeserializeSeed;
    use test_log::test;

    use crate::{
        Cli,
        finder::{
            de::{DCommandList, DTaskFinder, tasks::TaskFinderDeserializer},
            options::DPathOptions,
        },
    };

    #[test]
    fn test_expecting_error() {
        let seq = "[1, 2, 3]";
        let int = "1";
        let json = r#"{"unknown": "unknown"}"#;

        let cli = Cli::builder().build();

        let deserializer = TaskFinderDeserializer {
            cli: &cli,
            i: 0,
            env_path: &[],
            spath: &mut DPathOptions::default(),
        };
        let result: Result<Option<DTaskFinder<'_>>, serde_json::Error> =
            deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(
            result.is_ok(),
            "Expected task with nothing in it, got: {result:?}"
        );
        let task = TaskFinderDeserializer {
            cli: &cli,
            i: 0,
            env_path: &[],
            spath: &mut DPathOptions::default(),
        };
        let result = task.deserialize(&mut serde_json::Deserializer::from_str(seq));
        assert!(result.is_err(), "Expected error, got: {result:?}");
        assert!(serde_json::from_str::<DCommandList>(int).is_err());
    }
}
