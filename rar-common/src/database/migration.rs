use std::error::Error;

use semver::Version;
use tracing::debug;

use crate::version::PACKAGE_VERSION;

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

    pub fn migrate_from(
        from: &Version,
        to: &Version,
        doc: &mut T,
        migrations: &[Self],
    ) -> Result<bool, Box<dyn Error>> {
        let mut from = from.clone();
        let to = to.clone();
        debug!("===== Migrating from {} to {} =====", from, to);
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
    /// Returns true if the database was migrated, false if it was already at the current version.
    pub fn migrate(
        version: &Version,
        doc: &mut T,
        migrations: &[Self],
    ) -> Result<bool, Box<dyn Error>>
where {
        Self::migrate_from(
            version,
            &Version::parse(PACKAGE_VERSION).unwrap(),
            doc,
            migrations,
        )
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
                to: || Version::parse(PACKAGE_VERSION).unwrap(),
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
                from: || Version::parse(PACKAGE_VERSION).unwrap(),
                to: || Version::parse("4.0.0").unwrap(),
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
        assert_eq!(
            Migration::migrate(&Version::parse("1.0.0").unwrap(), &mut doc, &migrations).unwrap(),
            true
        );
        assert_eq!(doc, 3);
        doc = 0;
        assert_eq!(
            Migration::migrate(&Version::parse("2.0.0").unwrap(), &mut doc, &migrations).unwrap(),
            true
        );
        assert_eq!(doc, 2);
        doc = 0;
        assert_eq!(
            Migration::migrate(
                &Version::parse("3.0.0-alpha.1").unwrap(),
                &mut doc,
                &migrations
            )
            .unwrap(),
            true
        );
        assert_eq!(doc, 1);
        doc = 0;
        assert_eq!(
            Migration::migrate(&Version::parse("4.0.0").unwrap(), &mut doc, &migrations).unwrap(),
            true
        );
        assert_eq!(doc, -1);
        doc = 0;
        assert_eq!(
            Migration::migrate(
                &Version::parse(PACKAGE_VERSION).unwrap(),
                &mut doc,
                &migrations
            )
            .unwrap(),
            false
        );
        assert_eq!(doc, 0);
    }
}
