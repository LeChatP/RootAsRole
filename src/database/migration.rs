use std::error::Error;

use semver::Version;
use tracing::debug;

use crate::common::version::PACKAGE_VERSION;


pub struct Migration<T> {
    pub from: fn() -> Version,
    pub to: fn() -> Version,
    pub up: fn(&Self, &mut T) -> Result<(), Box<dyn Error>>,
    pub down: fn(&Self, &mut T) -> Result<(), Box<dyn Error>>,
}

#[derive(PartialEq, Eq, Debug)]
pub enum ChangeResult {
    UpgradeDirect,
    DowngradeDirect,
    UpgradeIndirect,
    DowngradeIndirect,
    None,
}

impl<T> Migration<T> {
    pub fn from(&self) -> Version {
        (self.from)()
    }
    pub fn to(&self) -> Version {
        (self.to)()
    }
    pub fn change(
        &self,
        doc: &mut T,
        from: &Version,
        to: &Version,
    ) -> Result<ChangeResult, Box<dyn Error>> {
        debug!("Checking migration from {} to {} :", self.from(), self.to());
        debug!(
            "
\tself.from() == *from -> {}\tself.from() == *to -> {}
\tself.to() == *to -> {}\tself.to() == *from -> {}
\t*from < *to -> {}\tself.to() < *to -> {}\tself.to() > *from -> {}
\t*from > *to -> {}\tself.from() < *to -> {}\tself.from() > *from -> {}",
            self.from() == *from,
            self.to() == *from,
            self.to() == *to,
            self.to() == *from,
            *from < *to,
            self.to() < *to,
            self.to() > *from,
            *from > *to,
            self.from() < *to,
            self.from() > *from
        );
        if self.from() == *from && self.to() == *to {
            debug!("Direct Upgrading from {} to {}", self.from(), self.to());
            (self.up)(self, doc)?;
            Ok(ChangeResult::UpgradeDirect)
        } else if self.to() == *from && self.from() == *to {
            debug!("Direct Downgrading from {} to {}", self.to(), self.from());
            (self.down)(self, doc)?;
            Ok(ChangeResult::DowngradeDirect)
        } else if *from < *to && self.from() == *from && self.to() < *to && self.to() > *from {
            debug!("Step Upgrading from {} to {}", self.from(), self.to());
            // 1.0.0 -> 2.0.0 -> 3.0.0
            (self.up)(self, doc)?;
            Ok(ChangeResult::UpgradeIndirect)
        } else if *from > *to && self.to() == *from && self.from() > *to && self.from() < *from {
            debug!("Step Downgrading from {} to {}", self.to(), self.from());
            // 3.0.0 -> 2.0.0 -> 1.0.0
            (self.down)(self, doc)?;
            Ok(ChangeResult::DowngradeIndirect)
        } else {
            Ok(ChangeResult::None)
        }
    }

    pub fn migrate_from(from: &Version, to: &Version, doc: &mut T, migrations : &[Self]) -> Result<bool, Box<dyn Error>> {
        let mut from = from.clone();
        let to = to.clone();
        debug!("===== Migrating from {} to {} =====", from, to);
        if from != to {
            let mut migrated = ChangeResult::UpgradeIndirect;
            while migrated == ChangeResult::UpgradeIndirect
                || migrated == ChangeResult::DowngradeIndirect
            {
                for migration in migrations {
                    match migration.change(doc, &from, &to)? {
                        ChangeResult::UpgradeDirect | ChangeResult::DowngradeDirect => {
                            return Ok(true);
                        }
                        ChangeResult::UpgradeIndirect => {
                            from = migration.to();
                            migrated = ChangeResult::UpgradeIndirect;
                            break;
                        }
                        ChangeResult::DowngradeIndirect => {
                            from = migration.from();
                            migrated = ChangeResult::DowngradeIndirect;
                            break;
                        }
                        ChangeResult::None => {
                            migrated = ChangeResult::None;
                        }
                    }
                }
                if migrated == ChangeResult::None {
                    return Err(format!("No migration from {} to {} found", from, to).into());
                }
            }
        }
        Ok(false)
    }
    
    /// Migrate the database schema to the current version.
    /// If the version is already the current version, nothing is done.
    /// If the version is older, the database is upgraded.
    /// If the version is newer, the database is downgraded.
    pub fn migrate(version: &Version, doc: &mut T, migrations : &[Self]) -> Result<bool, Box<dyn Error>>
    where
     {
        Self::migrate_from(
            &version,
            &Version::parse(PACKAGE_VERSION).unwrap(),
            doc,
            migrations,
        )
    }
}