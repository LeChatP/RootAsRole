use std::error::Error;

use crate::version::PACKAGE_VERSION;
/// This allows to upgrade or downgrade the database schema.
/// The version is stored in the database and compared to the compiled version.
use semver::Version;
use sxd_document::dom::{Document, Element};

use super::{do_in_main_element, foreach_element};

struct Migration {
    from: fn() -> Version,
    to: fn() -> Version,
    up: fn(&Self,Document) -> Result<(), Box<dyn Error>>,
    down: fn(&Self,Document) -> Result<(), Box<dyn Error>>,
}

impl Migration {
    fn from(&self) -> Version {
        (self.from)()
    }
    fn to(&self) -> Version {
        (self.to)()
    }
    fn change(&self, doc: Document) -> Result<(), Box<dyn Error>> {
        if self.from < self.to {
            (self.up)(self, doc)
        } else {
            (self.down)(self, doc)
        }
    }
}

/// Migrate the database schema to the current version.
/// If the version is already the current version, nothing is done.
/// If the version is older, the database is upgraded.
/// If the version is newer, the database is downgraded.
pub fn migrate(version : &str ,doc : Document) -> Result<bool, Box<dyn Error>> {
    let from = Version::parse(version).unwrap();
    let to = Version::parse(PACKAGE_VERSION).unwrap();
    if from != to {
        for migration in MIGRATIONS {
            if migration.from() == from && migration.to() == to {
                migration.change(doc)?;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn set_to_version(element: &Element, m : &Migration) {
    element.set_attribute_value("version", m.to().to_string().as_str());
}

fn set_to_version_from_doc(doc: &Document, m : &Migration) -> Result<(), Box<dyn Error>> {
    do_in_main_element(*doc,"rootasrole", |main| {
        if let Some(mainelement) = main.element() {
            set_to_version(&mainelement, m);
        }
        Ok(())
    })
}

const MIGRATIONS: &[Migration] = &[Migration {
    from: || "3.0.0-alpha.2".parse().unwrap(),
    to: || "3.0.0-alpha.3".parse().unwrap(),
    /// Upgrade from 3.0.0-alpha.2 to 3.0.0-alpha.3
    /// The version attribute is set to 3.0.0-alpha.3
    /// Nothing else is changed, because the new attributes are optional.
    up: |m, doc| set_to_version_from_doc(&doc,m),
    /// Downgrade from 3.0.0-alpha.3 to 3.0.0-alpha.2
    /// The timestamp-timeout attribute is removed from the root element.
    /// The version attribute is set to 3.0.0-alpha.2
    /// The parents, denied-capabilities and incompatible-with attributes are removed from the role element.
    down: | s: &Migration, doc| {
        do_in_main_element(doc,"rootasrole", |main| {
            if let Some(mainelement) = main.element() {
                set_to_version(&mainelement, s);
                if let Some(a) = mainelement.attribute("timestamp-timeout") {
                    a.remove_from_parent();
                }
                foreach_element(&mainelement, |element| {
                    if let Some(subelement) = element.element() {
                        if subelement.name().local_part() == "roles" {
                            return foreach_element(&subelement, |rolechild|{
                                if let Some(roleelement) = rolechild.element() {
                                    if roleelement.name().local_part() == "role" {
                                        if let Some(a) = roleelement.attribute("parents") {
                                            a.remove_from_parent();
                                        } else if let Some(a) = roleelement.attribute("denied-capabilities") {
                                            a.remove_from_parent();
                                        } else if let Some(a) = roleelement.attribute("incompatible-with") {
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
    }},
];
