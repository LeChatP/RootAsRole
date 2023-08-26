use std::error::Error;

use crate::xml_version::PACKAGE_VERSION;
/// This allows to upgrade or downgrade the database schema.
/// The version is stored in the database and compared to the compiled version.
use semver::Version;
use sxd_document::dom::{Document, Element};
use tracing::debug;

use super::{do_in_main_element, foreach_element};

struct Migration {
    from: fn() -> Version,
    to: fn() -> Version,
    up: fn(&Self, &Document) -> Result<(), Box<dyn Error>>,
    down: fn(&Self, &Document) -> Result<(), Box<dyn Error>>,
}

impl Migration {
    fn from(&self) -> Version {
        (self.from)()
    }
    fn to(&self) -> Version {
        (self.to)()
    }
    fn change(&self, doc: &Document) -> Result<(), Box<dyn Error>> {
        if self.from < self.to {
            (self.up)(self, doc)
        } else {
            (self.down)(self, doc)
        }
    }
}

fn _migrate(from: &Version, to: &Version, doc: &Document) -> Result<bool, Box<dyn Error>> {
    let mut from = from.clone();
    debug!("Migrating from {} to {}", from, to);
    if from != *to {
        while from != *to {
            let mut migrated = false;
            for migration in MIGRATIONS {
                if (migration.from() == from && migration.to() == *to)
                    || (migration.from() == *to && migration.to() == from)
                {
                    migration.change(doc)?;
                    return Ok(true);
                } else if migration.from() == from && *to > migration.to() {
                    migration.change(doc)?;
                    from = migration.to();
                    migrated = true;
                }
            }
            if !migrated {
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
pub(crate) fn migrate(version: &str, doc: &Document) -> Result<bool, Box<dyn Error>> {
    _migrate(
        &Version::parse(version).unwrap(),
        &Version::parse(PACKAGE_VERSION).unwrap(),
        doc,
    )
}

fn set_to_version(element: &Element, m: &Migration) {
    element.set_attribute_value("version", m.to().to_string().as_str());
}

fn set_to_version_from_doc(doc: &Document, m: &Migration) -> Result<(), Box<dyn Error>> {
    do_in_main_element(doc, "rootasrole", |main| {
        if let Some(mainelement) = main.element() {
            set_to_version(&mainelement, m);
        }
        Ok(())
    })
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        from: || "3.0.0-alpha.2".parse().unwrap(),
        to: || "3.0.0-alpha.3".parse().unwrap(),
        /// Upgrade from 3.0.0-alpha.2 to 3.0.0-alpha.3
        /// The version attribute is set to 3.0.0-alpha.3
        /// Nothing else is changed, because the new attributes are optional.
        up: |m, doc| set_to_version_from_doc(doc, m),
        /// Downgrade from 3.0.0-alpha.3 to 3.0.0-alpha.2
        /// The timestamp-timeout attribute is removed from the root element.
        /// The version attribute is set to 3.0.0-alpha.2
        /// The parents, denied-capabilities and incompatible-with attributes are removed from the role element.
        down: |s: &Migration, doc| {
            do_in_main_element(doc, "rootasrole", |main| {
                if let Some(mainelement) = main.element() {
                    set_to_version(&mainelement, s);
                    if let Some(a) = mainelement.attribute("timestamp-timeout") {
                        a.remove_from_parent();
                    }
                    foreach_element(&mainelement, |element| {
                        if let Some(subelement) = element.element() {
                            if subelement.name().local_part() == "roles" {
                                return foreach_element(&subelement, |rolechild| {
                                    if let Some(roleelement) = rolechild.element() {
                                        if roleelement.name().local_part() == "role" {
                                            if let Some(a) = roleelement.attribute("parents") {
                                                a.remove_from_parent();
                                            } else if let Some(a) =
                                                roleelement.attribute("denied-capabilities")
                                            {
                                                a.remove_from_parent();
                                            } else if let Some(a) =
                                                roleelement.attribute("incompatible-with")
                                            {
                                                a.remove_from_parent();
                                            }
                                        }
                                    }
                                    Ok(())
                                });
                            }
                        }
                        Ok(())
                    })?;
                }
                Ok(())
            })?;
            Ok(())
        },
    },
    Migration {
        from: || "3.0.0-alpha.1".parse().unwrap(),
        to: || "3.0.0-alpha.2".parse().unwrap(),
        /// Upgrade from 3.0.0-alpha.2 to 3.0.0-alpha.3
        /// The version attribute is set to 3.0.0-alpha.3
        /// Nothing else is changed, because the new attributes are optional.
        up: |m, doc| set_to_version_from_doc(doc, m),
        /// Downgrade from 3.0.0-alpha.3 to 3.0.0-alpha.2
        /// The timestamp-timeout attribute is removed from the root element.
        /// The version attribute is set to 3.0.0-alpha.2
        /// The parents, denied-capabilities and incompatible-with attributes are removed from the role element.
        down: |s, doc| set_to_version_from_doc(doc, s),
    },
];

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        config::{
            self,
            load::{load_config, load_config_from_doc},
            save::save_config,
        },
        util,
    };
    use test_log::test;

    #[test]
    fn test_migrate() {
        let pkg = config::load::load_document(
            &util::test::test_resources_file("test_migrate-3.0.0-alpha.2.xml"),
            true,
        )
        .expect("Failed to load config");
        let doc = pkg.as_document();
        let v3 = &Version::parse("3.0.0-alpha.3").unwrap();
        let v2 = &Version::parse("3.0.0-alpha.2").unwrap();
        assert_eq!(
            _migrate(v3, v3, &doc).expect(format!("Failed to migrate to {}", v3).as_str()),
            false
        );
        assert_eq!(
            _migrate(v2, v3, &doc).expect(format!("Failed to migrate to {}", v3).as_str()),
            true
        );
        assert_eq!(
            _migrate(v3, v2, &doc).expect(format!("Failed to migrate to {}", v2).as_str()),
            true
        );
        assert_eq!(
            _migrate(v2, v2, &doc).expect(format!("Failed to migrate to {}", v2).as_str()),
            false
        );
        assert_eq!(
            _migrate(v2, v3, &doc).expect(format!("Failed to migrate to {}", v3).as_str()),
            true
        );
        let config = load_config_from_doc(&doc, false).expect("Failed to load config");
        save_config("/tmp/migrate_config.xml", &config.as_ref().borrow(), false)
            .expect("Failed to save config");
        let config = load_config(&"/tmp/migrate_config.xml").expect("Failed to load config");
        assert_eq!(
            config.as_ref().borrow().version.parse::<Version>().unwrap(),
            *v3
        );
    }
}
