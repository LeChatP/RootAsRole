use std::{
    io::{self, BufReader},
    path::Path,
};

use log::debug;
use rar_common::{
    SettingsContent, database::versionning::Versioning, file::LockedSettingsFile,
    util::StorageMethod,
};
use serde::{
    Deserialize, Deserializer,
    de::{DeserializeSeed, IgnoredAny},
};

pub type LockedStorage = LockedSettingsFile<Versioning<SettingsContent>>;

/// # Errors
/// Returns an error if the file cannot be opened, deserialized or locked
pub fn read_storage<P>(
    rar_cfg_path: P,
    rar_cfg_type: StorageMethod,
) -> std::io::Result<LockedStorage>
where
    P: AsRef<Path>,
{
    LockedSettingsFile::open_read(rar_cfg_path, |path, file| {
        debug!("Loading root settings from {}", path.as_ref().display());

        let buf = BufReader::new(file);
        let settings: Versioning<SettingsContent> = match rar_cfg_type {
            StorageMethod::JSON => RootNoConfigDeserializer
                .deserialize(&mut serde_json::Deserializer::from_reader(buf))
                .map_err(|e| {
                    debug!("Failed to deserialize root settings: {e}");
                    io::Error::new(io::ErrorKind::InvalidData, e)
                })?,
            StorageMethod::CBOR => {
                let mut io_reader = cbor4ii::core::utils::IoReader::new(buf);
                RootNoConfigDeserializer
                    .deserialize(&mut cbor4ii::serde::Deserializer::new(&mut io_reader))
                    .map_err(|e| {
                        debug!("Failed to deserialize root settings: {e}");
                        io::Error::new(io::ErrorKind::InvalidData, e)
                    })?
            }
        };
        debug!("Loaded root settings from {}", path.as_ref().display());
        Ok(settings)
    })
}

struct RootNoConfigDeserializer;

impl<'de> DeserializeSeed<'de> for RootNoConfigDeserializer {
    type Value = Versioning<SettingsContent>;

    /// # Errors
    /// Returns an error if the deserialization process fails or if the "storage" field is missing
    fn deserialize<D>(self, deserializer: D) -> Result<Versioning<SettingsContent>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RootNoConfigVisitor;
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        #[repr(u8)]
        enum Field {
            #[serde(alias = "s")]
            Storage,
            #[serde(alias = "v")]
            Version,
            #[serde(other)]
            Unknown,
        }
        impl<'de> serde::de::Visitor<'de> for RootNoConfigVisitor {
            type Value = Versioning<SettingsContent>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a SettingsContent")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut storage = None;
                let mut version = None;
                while let Some(key) = map.next_key::<Field>()? {
                    match key {
                        Field::Storage => {
                            if storage.is_some() {
                                return Err(serde::de::Error::duplicate_field("storage"));
                            }
                            storage = Some(map.next_value()?);
                        }
                        Field::Version => {
                            if version.is_some() {
                                return Err(serde::de::Error::duplicate_field("version"));
                            }
                            version = Some(map.next_value()?);
                        }
                        Field::Unknown => {
                            // Ignore unknown fields
                            let _ = map.next_value::<IgnoredAny>()?;
                        }
                    }
                }

                let storage = storage.ok_or_else(|| serde::de::Error::missing_field("storage"))?;
                let version = version.ok_or_else(|| serde::de::Error::missing_field("version"))?;

                Ok(Versioning {
                    version,
                    data: storage,
                })
            }
        }
        deserializer.deserialize_map(RootNoConfigVisitor)
    }
}
