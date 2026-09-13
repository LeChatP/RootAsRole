use std::error::Error;

use log::debug;
use semver::Version;

use crate::PACKAGE_VERSION;

type MigrationFn<T> = fn(&Migration<T>, &mut T) -> Result<(), Box<dyn Error>>;

pub struct Migration<T> {
    pub from: fn() -> Version,
    pub to: fn() -> Version,
    pub up: MigrationFn<T>,
    pub down: MigrationFn<T>,
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
    #[must_use]
    pub fn from(&self) -> Version {
        (self.from)()
    }
    #[must_use]
    pub fn to(&self) -> Version {
        (self.to)()
    }
    /// # Errors
    /// Returns an error if the migration fails.
    pub fn change(
        &self,
        doc: &mut T,
        from: &Version,
        to: &Version,
    ) -> Result<ChangeResult, Box<dyn Error>> {
        debug!("Checking migration from {} to {} :", self.from(), self.to());
        #[cfg(not(tarpaulin_include))]
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

    /// # Errors
    /// Returns an error if the migration fails or if no migration path is found.
    pub fn migrate_from(
        from: &Version,
        to: &Version,
        doc: &mut T,
        migrations: &[Self],
    ) -> Result<bool, Box<dyn Error>> {
        let mut from = from.clone();
        let to = to.clone();
        debug!("===== Migrating from {from} to {to} =====");
        if from != to {
            let mut migrated = ChangeResult::UpgradeIndirect;
            while migrated == ChangeResult::UpgradeIndirect
                || migrated == ChangeResult::DowngradeIndirect
            {
                migrated = ChangeResult::None;
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
                    return Err(format!("No migration from {from} to {to} found").into());
                }
            }
        }
        Ok(false)
    }

    /// Migrate the database schema to the current version.
    /// If the version is already the current version, nothing is done.
    /// If the version is older, the database is upgraded.
    /// If the version is newer, the database is downgraded.
    /// Returns true if the database was migrated, false if it was already at the current version.
    /// # Errors
    /// Returns an error if the migration fails or if no migration path is found.
    #[allow(clippy::missing_panics_doc)] // This function never panic because version 
    pub fn migrate(
        version: &Version,
        doc: &mut T,
        migrations: &[Self],
    ) -> Result<bool, Box<dyn Error>> {
        Self::migrate_from(version, &PACKAGE_VERSION, doc, migrations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;

    #[test]
    fn test_migration() {
        let mut doc = 0;
        let migrations = vec![
            Migration {
                from: || Version::parse("1.0.0").unwrap(),
                to: || Version::parse("2.0.0").unwrap(),
                up: |_, doc| {
                    *doc += 1;
                    Ok(())
                },
                down: |_, doc| {
                    *doc -= 1;
                    Ok(())
                },
            },
            Migration {
                from: || Version::parse("2.0.0").unwrap(),
                to: || Version::parse("3.0.0-alpha.1").unwrap(),
                up: |_, doc| {
                    *doc += 1;
                    Ok(())
                },
                down: |_, doc| {
                    *doc -= 1;
                    Ok(())
                },
            },
            Migration {
                from: || Version::parse("3.0.0-alpha.1").unwrap(),
                to: || PACKAGE_VERSION,
                up: |_, doc| {
                    *doc += 1;
                    Ok(())
                },
                down: |_, doc| {
                    *doc -= 1;
                    Ok(())
                },
            },
            Migration {
                from: || PACKAGE_VERSION,
                to: || Version::parse("99.0.0").unwrap(),
                up: |_, doc| {
                    *doc += 1;
                    Ok(())
                },
                down: |_, doc| {
                    *doc -= 1;
                    Ok(())
                },
            },
        ];
        assert!(
            Migration::migrate(&Version::parse("1.0.0").unwrap(), &mut doc, &migrations).unwrap()
        );
        assert_eq!(doc, 3);
        doc = 0;
        assert!(
            Migration::migrate(&Version::parse("2.0.0").unwrap(), &mut doc, &migrations).unwrap()
        );
        assert_eq!(doc, 2);
        doc = 0;
        assert!(
            Migration::migrate(
                &Version::parse("3.0.0-alpha.1").unwrap(),
                &mut doc,
                &migrations
            )
            .unwrap()
        );
        assert_eq!(doc, 1);
        doc = 0;
        assert!(
            Migration::migrate(&Version::parse("99.0.0").unwrap(), &mut doc, &migrations).unwrap()
        );
        assert_eq!(doc, -1);
        doc = 0;
        assert!(!Migration::migrate(&PACKAGE_VERSION, &mut doc, &migrations).unwrap());
        assert_eq!(doc, 0);
    }
}
