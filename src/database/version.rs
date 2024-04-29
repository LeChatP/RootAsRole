use semver::Version;
use serde::{Deserialize, Deserializer, Serialize};
use tracing::debug;

use super::migration::Migration;
use crate::common::version;

use super::structs::*;

#[derive(Deserialize, Serialize)]
pub struct Versioning<T: Default> {
    pub version: Version,
    #[serde(default, flatten)]
    pub data: T,
}

impl Versioning<SConfig> {
    pub fn deserialize<'de, D>(deserializer: D) -> Result<SConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize into the intermediate representation
        let mut intermediate: Versioning<SConfig> =
            <Self as Deserialize>::deserialize(deserializer)?;
        // Check version and perform migrations if necessary
        if Migration::migrate(
            &intermediate.version,
            &mut intermediate.data,
            JSON_MIGRATIONS,
        )
        .and_then(|b| {
            intermediate.version = version::PACKAGE_VERSION.to_owned().parse()?;
            debug!("Migrated from {}", intermediate.version);
            Ok(b)
        })
        .is_err()
        {
            return Err(serde::de::Error::custom("Failed to migrate data"));
        }

        // Return the migrated data
        Ok(intermediate.data)
    }
}

pub(crate) const JSON_MIGRATIONS: &[Migration<SConfig>] = &[];
