use std::error::Error;

use crate::xml_version::PACKAGE_VERSION;
/// This allows to upgrade or downgrade the database schema.
/// The version is stored in the database and compared to the compiled version.
use semver::Version;
use sxd_document::dom::{Document, Element};
use tracing::debug;

use super::{
    do_in_main_child, do_in_main_element, foreach_inner_elements_names,
};

struct Migration {
    from: fn() -> Version,
    to: fn() -> Version,
    up: fn(&Self, &Document) -> Result<(), Box<dyn Error>>,
    down: fn(&Self, &Document) -> Result<(), Box<dyn Error>>,
}

#[derive(PartialEq, Eq, Debug)]
enum ChangeResult {
    UpgradeDirect,
    DowngradeDirect,
    UpgradeIndirect,
    DowngradeIndirect,
    None,
}

impl Migration {
    fn from(&self) -> Version {
        (self.from)()
    }
    fn to(&self) -> Version {
        (self.to)()
    }
    fn change(
        &self,
        doc: &Document,
        from: &Version,
        to: &Version,
    ) -> Result<ChangeResult, Box<dyn Error>> {
        debug!("Checking migration from {} to {} :", self.from(), self.to());
        debug!("
\tself.from() == *from -> {}\tself.from() == *to -> {}
\tself.to() == *to -> {}\tself.to() == *from -> {}
\t*from < *to -> {}\tself.to() < *to -> {}\tself.to() > *from -> {}
\t*from > *to -> {}\tself.from() < *to -> {}\tself.from() > *from -> {}",self.from() == *from, self.to() == *from,
self.to() == *to, 
self.to() == *from, 
*from < *to, 
self.to() < *to, 
self.to() > *from, 
*from > *to, 
self.from() < *to, 
self.from() > *from);
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
}

fn _migrate(from: &Version, to: &Version, doc: &Document) -> Result<bool, Box<dyn Error>> {
    let mut from = from.clone();
    let to = to.clone();
    debug!("===== Migrating from {} to {} =====", from, to);
    if from != to {
        let mut migrated = ChangeResult::UpgradeIndirect;
        while migrated == ChangeResult::UpgradeIndirect || migrated == ChangeResult::DowngradeIndirect {
            for migration in MIGRATIONS {
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
pub(crate) fn migrate(version: &str, doc: &Document) -> Result<bool, Box<dyn Error>> {
    _migrate(
        &Version::parse(version).unwrap(),
        &Version::parse(PACKAGE_VERSION).unwrap(),
        doc,
    )
}

fn set_to_version(element: &Element, to: &Version) {
    element.set_attribute_value("version", to.to_string().as_str());
}

fn set_to_version_from_doc(doc: &Document, to: &Version) -> Result<(), Box<dyn Error>> {
    do_in_main_child(doc, "rootasrole", |main| {
        if let Some(mainelement) = main.element() {
            set_to_version(&mainelement, to);
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
        up: |m, doc| {
            do_in_main_element(doc, "rootasrole", |main| {
                set_to_version(&main,  &m.to());
                foreach_inner_elements_names(
                    &main,
                    &mut vec!["roles", "role", "task", "command"],
                    |cmdelement| {
                        cmdelement.remove_attribute("regex");
                        Ok(())
                    },
                )?;
                Ok(())
            })?;
            Ok(())
        },
        /// Downgrade from 3.0.0-alpha.3 to 3.0.0-alpha.2
        /// The timestamp-timeout attribute is removed from the root element.
        /// The version attribute is set to 3.0.0-alpha.2
        /// The parents, denied-capabilities and incompatible-with attributes are removed from the role element.
        down: |s: &Migration, doc| {
            do_in_main_element(doc, "rootasrole", |main| {
                set_to_version(&main,  &s.from());
                if let Some(a) = main.attribute("timestamp-timeout") {
                    a.remove_from_parent();
                }
                return foreach_inner_elements_names(&main, &mut vec!["roles", "role"], |role| {
                    if let Some(a) = role.attribute("parents") {
                        a.remove_from_parent();
                    }
                    if let Some(a) = role.attribute("denied-capabilities") {
                        a.remove_from_parent();
                    }
                    if let Some(a) = role.attribute("incompatible-with") {
                        a.remove_from_parent();
                    }
                    Ok(())
                });
            })?;
            Ok(())
        },
    },
    Migration {
        from: || "3.0.0-alpha.1".parse().unwrap(),
        to: || "3.0.0-alpha.2".parse().unwrap(),
        up: |m, doc| set_to_version_from_doc(doc, &m.to()),
        down: |s, doc| set_to_version_from_doc(doc, &s.from()),
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
            &util::test::test_resources_file("test_migrate-3.0.0-alpha.1.xml"),
            true,
        )
        .expect("Failed to load config");
        let doc = pkg.as_document();
        let v1 = &Version::parse("3.0.0-alpha.1").unwrap();
        let v2 = &Version::parse("3.0.0-alpha.2").unwrap();
        let v3 = &Version::parse("3.0.0-alpha.3").unwrap();
        
        do_in_main_element(&doc, "rootasrole", |main| {
            assert_eq!(
                main.attribute("version").unwrap().value(),
                v1.to_string().as_str()
            );
            Ok(())
        }).expect("Failed to get rootasrole element");

        //this migration should remove regex attribute on command element
        assert_eq!(
            _migrate(v1, v2, &doc).expect(format!("Failed to migrate to {}", v3).as_str()),
            true
        );

        do_in_main_element(&doc, "rootasrole", |main| {
            assert_eq!(
                main.attribute("version").unwrap().value(),
                v2.to_string().as_str()
            );
            Ok(())
        }).expect("Failed to get rootasrole element");

        //this migration should remove regex attribute on command element
        assert_eq!(
            _migrate(v2, v3, &doc).expect(format!("Failed to migrate to {}", v3).as_str()),
            true
        );

        do_in_main_element(&doc, "rootasrole", |main| {
            assert_eq!(
                main.attribute("version").unwrap().value(),
                v3.to_string().as_str()
            );
            foreach_inner_elements_names(
                &main,
                &mut vec!["roles", "role", "task", "command"],
                |cmdelement| {
                    assert_eq!(cmdelement.attribute("regex"), None);
                    Ok(())
                },
            )?;
            Ok(())
        }).expect("Failed to get rootasrole element");

        //this migration should do nothing
        assert_eq!(
            _migrate(v3, v2, &doc).expect(format!("Failed to migrate to {}", v3).as_str()),
            true
        );

        do_in_main_element(&doc, "rootasrole", |main| {
            assert_eq!(
                main.attribute("version").unwrap().value(),
                v2.to_string().as_str()
            );
            Ok(())
        }).expect("Failed to get rootasrole element");

        //this migration should do nothing
        assert_eq!(
            _migrate(v2, v3, &doc).expect(format!("Failed to migrate to {}", v3).as_str()),
            true
        );
        do_in_main_element(&doc, "rootasrole", |main| {
            assert_eq!(
                main.attribute("version").unwrap().value(),
                v3.to_string().as_str()
            );
            Ok(())
        }).expect("Failed to get rootasrole element");
        
        //we add v3 features on document
        do_in_main_child(&doc, "rootasrole", |element| {
            let element = element.element().unwrap();
            element.set_attribute_value("timestamp-timeout", "10");
            return foreach_inner_elements_names(&element, &mut vec!["roles", "role"], |role| {
                role.set_attribute_value("parents", "role1");
                role.set_attribute_value("denied-capabilities", "CAP_CHOWN");
                role.set_attribute_value("incompatible-with", "role2");
                Ok(())
            });
        })
        .expect("Failed to add v3 features on document");
        assert_eq!(
            _migrate(v3, v1, &doc).expect(format!("Failed to migrate to {}", v2).as_str()),
            true
        );
        do_in_main_element(&doc, "rootasrole", |main| {
            assert_eq!(
                main.attribute("version").unwrap().value(),
                v1.to_string().as_str()
            );
            assert_eq!(main.attribute("timestamp-timeout"), None);
            foreach_inner_elements_names(
                &main,
                &mut vec!["roles", "role"],
                |role| {
                    assert_eq!(role.attribute("parents"), None);
                    assert_eq!(role.attribute("denied-capabilities"), None);
                    assert_eq!(role.attribute("incompatible-with"), None);
                    Ok(())
                },
            )?;
            Ok(())
        }).expect("Failed to get rootasrole element");
        assert_eq!(
            _migrate(v1, v3, &doc).expect(format!("Failed to migrate to {}", v3).as_str()),
            true
        );
        do_in_main_element(&doc, "rootasrole", |main| {
            assert_eq!(
                main.attribute("version").unwrap().value(),
                v3.to_string().as_str()
            );
            Ok(())
        }).expect("Failed to get rootasrole element");
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
