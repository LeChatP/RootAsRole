use semver::Version;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use super::migration::Migration;
use crate::version;
use crate::SettingsFile;

use super::structs::*;

#[derive(Deserialize, Serialize, Debug)]
pub struct Versioning<T: Default + Debug> {
    pub version: Version,
    #[serde(default, flatten)]
    pub data: T,
}

impl<T: Default + Debug> Versioning<T> {
    pub fn new(data: T) -> Self {
        Self {
            version: version::PACKAGE_VERSION.to_owned().parse().unwrap(),
            data,
        }
    }
}

impl<T: Default + Debug> Default for Versioning<T> {
    fn default() -> Self {
        Self {
            version: version::PACKAGE_VERSION.to_owned().parse().unwrap(),
            data: T::default(),
        }
    }
}

pub(crate) const JSON_MIGRATIONS: &[Migration<SConfig>] = &[];

pub(crate) const SETTINGS_MIGRATIONS: &[Migration<SettingsFile>] = &[];
