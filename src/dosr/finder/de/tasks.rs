use std::borrow::Cow;

use log::debug;
use rootasrole_core::database::score::TaskScore;
use serde::{
    Deserialize,
    de::{DeserializeSeed, IgnoredAny},
};

use crate::{
    Cli,
    finder::de::{
        DTaskFinder, IdTask,
        cred::{CredData, CredFinderDeserializerReturn},
    },
};

pub(super) struct TaskListFinderDeserializer<'a> {
    pub(super) cli: &'a Cli,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for TaskListFinderDeserializer<'a> {
    type Value = Vec<DTaskFinder<'a>>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TaskListFinderVisitor<'a> {
            cli: &'a Cli,
        }
        impl<'de: 'a, 'a> serde::de::Visitor<'de> for TaskListFinderVisitor<'a> {
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
                while let Some(element) =
                    seq.next_element_seed(TaskFinderDeserializer { cli: self.cli, i })?
                {
                    if let Some(task) = element {
                        debug!("adding task {task:?}");
                        tasks.push(task);
                        i += 1;
                    }
                }
                Ok(tasks)
            }
        }
        deserializer.deserialize_seq(TaskListFinderVisitor { cli: self.cli })
    }
}

struct TaskFinderDeserializer<'a> {
    cli: &'a Cli,
    i: usize,
}

impl<'de: 'a, 'a> DeserializeSeed<'de> for TaskFinderDeserializer<'a> {
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

        struct TaskFinderVisitor<'a> {
            cli: &'a Cli,
            i: usize,
        }

        impl<'de: 'a, 'a> serde::de::Visitor<'de> for TaskFinderVisitor<'a> {
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
                //let mut extra_values = HashMap::new();
                let mut cred = CredData::default();

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Options => {
                            debug!("TaskFinderVisitor: options");
                            if let Some(opt) = map.next_value()? {
                                options = Some(opt);
                            } else {
                                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                                return Ok(None);
                            }

                            /*if self.cli.info && opt.execinfo.is_some_and(|i| i.is_hide()) {
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
                            }*/
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
                            // Stored, then matched with the PATH of the task once its options
                            // are known: they may come after the commands, in any format.
                            commands = Some(map.next_value()?);
                        }
                        Field::Unknown(_key) => {
                            debug!("TaskFinderVisitor: unknown");
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Some(DTaskFinder {
                    id,
                    score,
                    cred,
                    commands,
                    options,
                }))
            }
        }
        deserializer.deserialize_map(TaskFinderVisitor {
            i: self.i,
            cli: self.cli,
        })
    }
}

#[cfg(test)]
mod test {
    use serde::de::DeserializeSeed;
    use test_log::test;

    use crate::{
        Cli,
        finder::de::{DCommandList, DTaskFinder, tasks::TaskFinderDeserializer},
    };

    #[test]
    fn test_expecting_error() {
        let seq = "[1, 2, 3]";
        let int = "1";
        let json = r#"{"unknown": "unknown"}"#;
        let cli = Cli::builder().build();

        let deserializer = TaskFinderDeserializer { cli: &cli, i: 0 };
        let result: Result<Option<DTaskFinder<'_>>, serde_json::Error> =
            deserializer.deserialize(&mut serde_json::Deserializer::from_str(json));
        assert!(
            result.is_ok(),
            "Expected task with nothing in it, got: {result:?}"
        );
        let task = TaskFinderDeserializer { cli: &cli, i: 0 };
        let result = task.deserialize(&mut serde_json::Deserializer::from_str(seq));
        assert!(result.is_err(), "Expected error, got: {result:?}");
        assert!(serde_json::from_str::<DCommandList>(int).is_err());
    }
}
