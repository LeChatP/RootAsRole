//
use semver::Version;
use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};
use std::{cell::RefCell, fmt::Debug, rc::Rc};

use crate::database::{
    migration::{Migration, MigrationError},
    migrations::{FORMAT_VERSION, reads_as_is},
};

#[derive(Deserialize, Debug, Clone)]
pub struct Versioning<T> {
    #[serde(alias = "v")]
    pub version: Version,
    #[serde(default, flatten)]
    pub data: T,
}

/// The data of a versioned document, whose fields are written next to its version.
///
/// `#[serde(flatten)]` gives the data a serializer that is always human-readable (serde does not
/// forward `is_human_readable`): a CBOR file got the long keys at its top level.
pub trait VersionedData {
    /// Writes the fields of the data in `map`, under their long keys if `human_readable`.
    /// # Errors
    /// Returns the error of the serializer.
    fn serialize_entries<M: SerializeMap>(
        &self,
        map: &mut M,
        human_readable: bool,
    ) -> Result<(), M::Error>;
}

impl<T: VersionedData> VersionedData for Rc<RefCell<T>> {
    fn serialize_entries<M: SerializeMap>(
        &self,
        map: &mut M,
        human_readable: bool,
    ) -> Result<(), M::Error> {
        self.as_ref()
            .borrow()
            .serialize_entries(map, human_readable)
    }
}

impl<T: VersionedData> Serialize for Versioning<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry(
            super::ser::field(human_readable, "version", "v"),
            &self.version,
        )?;
        self.data.serialize_entries(&mut map, human_readable)?;
        map.end()
    }
}

impl<T> Versioning<T> {
    pub const fn new(data: T) -> Self {
        Self {
            version: FORMAT_VERSION,
            data,
        }
    }
}

impl<T: Default> Default for Versioning<T> {
    fn default() -> Self {
        Self {
            version: FORMAT_VERSION,
            data: T::default(),
        }
    }
}

impl<T> Versioning<T> {
    /// # Errors
    /// Returns an error if the migration process fails.
    pub fn upgrade_version(&mut self, migrations: &[Migration<T>]) -> Result<bool, MigrationError> {
        // read as it is: it keeps its version until it is saved, written for FORMAT_VERSION
        if reads_as_is(&self.version) {
            return Ok(false);
        }
        let res = Migration::migrate(&self.version, &mut self.data, migrations)?;
        self.version = FORMAT_VERSION;
        Ok(res)
    }
}
