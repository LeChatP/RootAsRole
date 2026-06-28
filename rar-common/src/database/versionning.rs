use semver::Version;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::{PACKAGE_VERSION, database::migration::Migration};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Versioning<T> {
    #[serde(alias = "v")]
    pub version: Version,
    #[serde(default, flatten)]
    pub data: T,
}

impl<T> Versioning<T> {
    pub const fn new(data: T) -> Self {
        Self {
            version: PACKAGE_VERSION,
            data,
        }
    }
}

impl<T: Default> Default for Versioning<T> {
    fn default() -> Self {
        Self {
            version: PACKAGE_VERSION,
            data: T::default(),
        }
    }
}

impl<T> Versioning<T> {
    /// # Errors
    /// Returns an error if the migration process fails.
    pub fn upgrade_version(
        &mut self,
        migrations: &[Migration<T>],
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let res = Migration::migrate(&self.version, &mut self.data, migrations)?;
        self.version = PACKAGE_VERSION;
        Ok(res)
    }
}
