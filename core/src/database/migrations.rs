//! Migrations of policy documents.
//!
//! They apply to the raw document before it is deserialized: a change of syntax
//! (e.g. environment regexes becoming wildcards) cannot be parsed by the current types.

use std::collections::HashSet;

use log::{debug, info};
use semver::Version;
use serde_json::Value;

use crate::{
    PACKAGE_VERSION,
    database::migration::{Migration, MigrationError},
    util::{ENV_DELETE_LIST_SLICE, is_valid_env_pattern},
};

/// The default delete list up to 4.0.3.
const DELETE_LIST_4_0_3: &[&str] = &[
    "PS4",
    "SHELLOPTS",
    "PERLLIB",
    "PERL5LIB",
    "PERL5OPT",
    "PYTHONINSPECT",
];

#[allow(clippy::unnecessary_wraps)] // signature of a migration
const fn unchanged(_: &Migration<Value>, _: &mut Value) -> Result<(), MigrationError> {
    Ok(())
}

/// Migrations of policy documents. Every released version needs an edge to the next one,
/// even when its format did not change, otherwise its documents cannot be migrated.
pub const DOCUMENT_MIGRATIONS: &[Migration<Value>] = &[
    Migration {
        from: || Version::new(4, 0, 0),
        to: || Version::new(4, 0, 1),
        up: unchanged,
        down: unchanged,
    },
    Migration {
        from: || Version::new(4, 0, 1),
        to: || Version::new(4, 0, 2),
        up: unchanged,
        down: unchanged,
    },
    Migration {
        from: || Version::new(4, 0, 2),
        to: || Version::new(4, 0, 3),
        up: unchanged,
        down: unchanged,
    },
    Migration {
        from: || Version::new(4, 0, 3),
        to: || Version::new(4, 0, 4),
        up: |_, document| {
            rewrite_env_entries(document, regex_to_wildcard);
            replace_default_delete_list(document, DELETE_LIST_4_0_3, ENV_DELETE_LIST_SLICE);
            Ok(())
        },
        down: |_, document| {
            replace_default_delete_list(document, ENV_DELETE_LIST_SLICE, DELETE_LIST_4_0_3);
            rewrite_env_entries(document, wildcard_to_regex);
            Ok(())
        },
    },
];

/// `LC_.*` -> `LC_*`: the simple regexes used before 4.0.4 become wildcards.
/// Anything else is left unchanged, and rejected with an explicit error when parsed.
fn regex_to_wildcard(entry: &str) -> Option<String> {
    if is_valid_env_pattern(entry) {
        return None;
    }
    let anchored = entry.strip_prefix('^').unwrap_or(entry);
    let anchored = anchored.strip_suffix('$').unwrap_or(anchored);
    let wildcard = anchored.replace(".*", "*");
    is_valid_env_pattern(&wildcard).then_some(wildcard)
}

/// `LC_*` -> `LC_.*`, for versions before 4.0.4.
fn wildcard_to_regex(entry: &str) -> Option<String> {
    entry.contains('*').then(|| entry.replace('*', ".*"))
}

/// Replace the global delete list by `to` when it is exactly the default list `from`,
/// in any order. A list written by the administrator is kept as it is.
fn replace_default_delete_list(document: &mut Value, from: &[&str], to: &[&str]) {
    let Some(Value::Array(delete)) = document.pointer_mut("/options/env/delete") else {
        return;
    };
    let entries: HashSet<&str> = delete.iter().filter_map(Value::as_str).collect();
    if entries.len() == delete.len() && entries == from.iter().copied().collect() {
        info!("Migrating the global env delete list to the default of this version");
        *delete = to
            .iter()
            .map(|entry| Value::String((*entry).to_string()))
            .collect();
    }
}

/// Rewrite the keep, check and delete entries of every `env` option of the document.
fn rewrite_env_entries(document: &mut Value, rewrite: fn(&str) -> Option<String>) {
    match document {
        Value::Object(map) => {
            if let Some(Value::Object(env)) = map.get_mut("env") {
                for list in ["keep", "check", "delete"] {
                    let Some(Value::Array(entries)) = env.get_mut(list) else {
                        continue;
                    };
                    for entry in entries {
                        if let Value::String(entry) = entry
                            && let Some(rewritten) = rewrite(entry)
                        {
                            info!("Migrating env {list} entry `{entry}` to `{rewritten}`");
                            *entry = rewritten;
                        }
                    }
                }
            }
            map.values_mut()
                .for_each(|value| rewrite_env_entries(value, rewrite));
        }
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| rewrite_env_entries(value, rewrite)),
        _ => {}
    }
}

/// Migrate a raw policy document to the current version, before it is deserialized.
/// A document without a parsable version is left unchanged.
/// Returns true if the document was migrated.
/// # Errors
/// Returns an error if a migration fails or if there is no migration path to the current version.
pub fn migrate_document(document: &mut Value) -> Result<bool, MigrationError> {
    let Some(version) = document
        .get("version")
        .or_else(|| document.get("v"))
        .and_then(Value::as_str)
        .and_then(|version| Version::parse(version).ok())
    else {
        return Ok(false);
    };
    let migrated = Migration::migrate(&version, document, DOCUMENT_MIGRATIONS)?;
    if migrated && let Value::Object(map) = document {
        debug!("Policy document migrated from {version} to {PACKAGE_VERSION}");
        map.remove("v");
        map.insert(
            "version".to_string(),
            Value::String(PACKAGE_VERSION.to_string()),
        );
    }
    Ok(migrated)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::database::{structs::SPolicy, versionning::Versioning};

    #[test]
    fn test_regex_to_wildcard() {
        assert_eq!(regex_to_wildcard("LC_.*").as_deref(), Some("LC_*"));
        assert_eq!(
            regex_to_wildcard("^XDG_.*_DIR$").as_deref(),
            Some("XDG_*_DIR")
        );
        assert_eq!(regex_to_wildcard(".*").as_deref(), Some("*"));
        // already valid
        assert_eq!(regex_to_wildcard("HOME"), None);
        assert_eq!(regex_to_wildcard("LC_*"), None);
        // not convertible: kept, then rejected when parsed
        assert_eq!(regex_to_wildcard("PS[1-4]"), None);
        assert_eq!(regex_to_wildcard("A|B"), None);
    }

    #[test]
    fn test_migrate_document_from_4_0_0() {
        let mut document = json!({
            "version": "4.0.0",
            "options": {"env": {"check": ["LC_.*", "TZ"], "keep": ["^HOME$"], "set": {"A": "LC_.*"}}},
            "roles": [{
                "name": "r1",
                "tasks": [{"name": "t1", "options": {"env": {"delete": ["XDG_.*_DIR"]}}}]
            }]
        });
        assert!(migrate_document(&mut document).unwrap());
        assert_eq!(document["version"], PACKAGE_VERSION.to_string());
        assert_eq!(document["options"]["env"]["check"], json!(["LC_*", "TZ"]));
        assert_eq!(document["options"]["env"]["keep"], json!(["HOME"]));
        // values of the set list are not patterns
        assert_eq!(document["options"]["env"]["set"]["A"], "LC_.*");
        assert_eq!(
            document["roles"][0]["tasks"][0]["options"]["env"]["delete"],
            json!(["XDG_*_DIR"])
        );
        // the migrated document is valid for the current version
        serde_json::from_value::<Versioning<SPolicy>>(document).unwrap();
    }

    #[test]
    fn test_migrate_document_keeps_invalid_entries_for_an_explicit_error() {
        let mut document = json!({
            "version": "4.0.3",
            "options": {"env": {"keep": ["PS[1-4]"]}},
            "roles": []
        });
        assert!(migrate_document(&mut document).unwrap());
        assert_eq!(document["options"]["env"]["keep"], json!(["PS[1-4]"]));
        let error = serde_json::from_value::<Versioning<SPolicy>>(document)
            .expect_err("an invalid entry must be an error")
            .to_string();
        assert!(error.contains("PS[1-4]"), "{error}");
    }

    #[test]
    fn test_migrate_document_current_or_unknown_version() {
        let mut document = json!({"version": PACKAGE_VERSION.to_string(), "options": {"env": {"keep": ["LC_.*"]}}});
        assert!(!migrate_document(&mut document).unwrap());
        assert_eq!(document["options"]["env"]["keep"], json!(["LC_.*"]));
        let mut document = json!({"options": {}});
        assert!(!migrate_document(&mut document).unwrap());
        let mut document = json!({"version": "3.0.0"});
        assert!(matches!(
            migrate_document(&mut document),
            Err(MigrationError::NoMigrationPath(_, _))
        ));
    }

    #[test]
    fn test_migrate_default_delete_list() {
        let new_default = json!(ENV_DELETE_LIST_SLICE);
        // the global list is the 4.0.3 default, in any order
        let mut document = json!({
            "version": "4.0.3",
            "options": {"env": {"delete": ["PYTHONINSPECT", "PS4", "SHELLOPTS", "PERLLIB", "PERL5LIB", "PERL5OPT"]}},
            "roles": [{"name": "r1", "options": {"env": {"delete": DELETE_LIST_4_0_3}}}]
        });
        migrate_document(&mut document).unwrap();
        assert_eq!(document["options"]["env"]["delete"], new_default);
        // only the global list is replaced
        assert_eq!(
            document["roles"][0]["options"]["env"]["delete"],
            json!(DELETE_LIST_4_0_3)
        );
        // a list written by the administrator is kept
        let mut document = json!({
            "version": "4.0.3",
            "options": {"env": {"delete": ["PS4", "SHELLOPTS", "PERLLIB", "PERL5LIB", "PERL5OPT", "PYTHONINSPECT", "FOO"]}},
            "roles": []
        });
        migrate_document(&mut document).unwrap();
        assert_eq!(
            document["options"]["env"]["delete"]
                .as_array()
                .unwrap()
                .len(),
            7
        );
        // the downgrade restores the 4.0.3 default
        let mut document = json!({"options": {"env": {"delete": new_default}}});
        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 0, 3),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(
            document["options"]["env"]["delete"],
            json!(DELETE_LIST_4_0_3)
        );
    }

    #[test]
    fn test_downgrade_to_4_0_3() {
        let mut document = json!({"options": {"env": {"keep": ["LC_*", "HOME"]}}});
        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 0, 3),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document["options"]["env"]["keep"], json!(["LC_.*", "HOME"]));
    }
}
