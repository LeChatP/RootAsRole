use std::{borrow::Cow, str::FromStr};

use log::debug;
use rootasrole_core::database::structs::SetBehavior;
use serde::Deserialize;

use crate::finder::de::{DCommand, DCommandList};

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

#[cfg(test)]
mod test {
    use crate::finder::de::{DCommand, DCommandList};

    #[test]
    fn test_dcommandlist_deserialize() {
        let list: DCommandList = serde_json::from_str(
            r#"{"default": "none", "add": ["/usr/bin/ls"], "del": ["/usr/bin/rm"]}"#,
        )
        .unwrap();
        assert_eq!(list.add.as_ref(), [DCommand::simple("/usr/bin/ls")]);
        assert_eq!(list.del.as_ref(), [DCommand::simple("/usr/bin/rm")]);
        let list: DCommandList = serde_json::from_str(r#"["/usr/bin/ls"]"#).unwrap();
        assert_eq!(list.add.as_ref(), [DCommand::simple("/usr/bin/ls")]);
        assert!(serde_json::from_str::<DCommandList>("1").is_err());
    }
}
