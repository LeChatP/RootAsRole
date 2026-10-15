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
        to: || Version::new(4, 1, 0),
        up: |_, document| {
            rewrite_env_entries(document, regex_to_wildcard);
            replace_default_delete_list(document, DELETE_LIST_4_0_3, ENV_DELETE_LIST_SLICE);
            keep_delete_mode_levels_strict(document);
            Ok(())
        },
        down: |_, document| {
            replace_default_delete_list(document, ENV_DELETE_LIST_SLICE, DELETE_LIST_4_0_3);
            rewrite_env_entries(document, wildcard_to_regex);
            Ok(())
        },
    },
];

/// `LC_.*` -> `LC_*`: the simple regexes used before 4.1.0 become wildcards.
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

/// `LC_*` -> `LC_.*`, for versions before 4.1.0.
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

/// Up to 4.0.3, a level that set its env `default` started from empty lists. Since 4.1.0, the
/// lists that it does not define are inherited: a delete mode level would pass the inherited keep
/// and check lists, so they are written empty to keep it as strict as it was. A keep mode level is
/// not changed, inheriting the delete and check lists only removes or checks more variables.
/// The downgrade does not change anything, an empty list means the same in 4.0.3.
fn keep_delete_mode_levels_strict(document: &mut Value) {
    match document {
        Value::Object(map) => {
            if let Some(Value::Object(env)) = map.get_mut("env")
                && env.get("default").and_then(Value::as_str) == Some("delete")
            {
                for list in ["keep", "check"] {
                    env.entry(list).or_insert_with(|| Value::Array(Vec::new()));
                }
            }
            map.values_mut().for_each(keep_delete_mode_levels_strict);
        }
        Value::Array(values) => values.iter_mut().for_each(keep_delete_mode_levels_strict),
        _ => {}
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

/// What a migration changed in a policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentMigration {
    /// The version the document was saved with.
    pub from: Version,
    /// The changed values, as `/json/pointer: old -> new`.
    pub changes: Vec<String>,
}

/// A JSON pointer segment (RFC 6901), with control characters escaped for display.
fn pointer_segment(key: &str) -> String {
    key.replace('~', "~0")
        .replace('/', "~1")
        .escape_debug()
        .to_string()
}

/// Describe the values changed between two versions of a document.
fn describe_changes(before: &Value, after: &Value, pointer: &str, changes: &mut Vec<String>) {
    match (before, after) {
        (Value::Object(before), Value::Object(after)) => {
            for (key, old) in before {
                let pointer = format!("{pointer}/{}", pointer_segment(key));
                match after.get(key) {
                    Some(new) => describe_changes(old, new, &pointer, changes),
                    None => changes.push(format!("{pointer}: {old} removed")),
                }
            }
            for (key, new) in after.iter().filter(|(key, _)| !before.contains_key(*key)) {
                changes.push(format!("{pointer}/{}: {new} added", pointer_segment(key)));
            }
        }
        (Value::Array(before), Value::Array(after)) if before.len() == after.len() => {
            for (index, (old, new)) in before.iter().zip(after).enumerate() {
                describe_changes(old, new, &format!("{pointer}/{index}"), changes);
            }
        }
        _ if before != after => changes.push(format!("{pointer}: {before} -> {after}")),
        _ => {}
    }
}

/// Migrate a raw policy document to the current version, before it is deserialized.
///
/// A document without a parsable version, or already at the current version, is left unchanged.
/// Returns what the migration changed, if the document was migrated.
/// # Errors
/// Returns an error if a migration fails or if there is no migration path to the current version.
pub fn migrate_document(document: &mut Value) -> Result<Option<DocumentMigration>, MigrationError> {
    let Some(version) = document
        .get("version")
        .or_else(|| document.get("v"))
        .and_then(Value::as_str)
        .and_then(|version| Version::parse(version).ok())
    else {
        return Ok(None);
    };
    if version == PACKAGE_VERSION {
        return Ok(None);
    }
    let before = document.clone();
    if !Migration::migrate(&version, document, DOCUMENT_MIGRATIONS)? {
        return Ok(None);
    }
    let mut changes = Vec::new();
    describe_changes(&before, document, "", &mut changes);
    if let Value::Object(map) = document {
        debug!("Policy document migrated from {version} to {PACKAGE_VERSION}");
        map.remove("v");
        map.insert(
            "version".to_string(),
            Value::String(PACKAGE_VERSION.to_string()),
        );
    }
    Ok(Some(DocumentMigration {
        from: version,
        changes,
    }))
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
        let migration = migrate_document(&mut document).unwrap().unwrap();
        assert_eq!(migration.from, Version::new(4, 0, 0));
        assert_eq!(
            migration.changes,
            [
                r#"/options/env/check/0: "LC_.*" -> "LC_*""#,
                r#"/options/env/keep/0: "^HOME$" -> "HOME""#,
                r#"/roles/0/tasks/0/options/env/delete/0: "XDG_.*_DIR" -> "XDG_*_DIR""#,
            ]
        );
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
        let migration = migrate_document(&mut document).unwrap().unwrap();
        assert!(migration.changes.is_empty());
        assert_eq!(document["options"]["env"]["keep"], json!(["PS[1-4]"]));
        let error = serde_json::from_value::<Versioning<SPolicy>>(document)
            .expect_err("an invalid entry must be an error")
            .to_string();
        assert!(error.contains("PS[1-4]"), "{error}");
    }

    #[test]
    fn test_migrate_document_current_or_unknown_version() {
        let mut document = json!({"version": PACKAGE_VERSION.to_string(), "options": {"env": {"keep": ["LC_.*"]}}});
        assert_eq!(migrate_document(&mut document).unwrap(), None);
        assert_eq!(document["options"]["env"]["keep"], json!(["LC_.*"]));
        let mut document = json!({"options": {}});
        assert_eq!(migrate_document(&mut document).unwrap(), None);
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
    fn test_describe_changes() {
        let mut changes = Vec::new();
        describe_changes(
            &json!({"a": 1, "b": [1, 2], "c": {"d/e": "x"}}),
            &json!({"a": 1, "b": [1], "c": {"d/e": "\u{1b}"}, "f": true}),
            "",
            &mut changes,
        );
        assert_eq!(
            changes,
            [
                "/b: [1,2] -> [1]",
                r#"/c/d~1e: "x" -> "\u001b""#,
                "/f: true added",
            ]
        );
    }

    #[test]
    fn test_migrate_keeps_delete_mode_levels_strict() {
        let mut document = json!({
            "version": "4.0.3",
            "options": {"env": {"default": "delete", "keep": ["HOME"]}},
            "roles": [{"name": "r1", "tasks": [
                {"name": "t1", "options": {"env": {"default": "delete"}}},
                {"name": "t2", "options": {"env": {"default": "keep"}}},
                {"name": "t3", "options": {"env": {"keep": ["FOO"]}}}
            ]}]
        });
        let migration = migrate_document(&mut document).unwrap().unwrap();
        assert_eq!(document["options"]["env"]["keep"], json!(["HOME"]));
        assert_eq!(document["options"]["env"]["check"], json!([]));
        let tasks = &document["roles"][0]["tasks"];
        assert_eq!(
            tasks[0]["options"]["env"],
            json!({"default": "delete", "keep": [], "check": []})
        );
        // keep mode and inheriting levels are not changed
        assert_eq!(tasks[1]["options"]["env"], json!({"default": "keep"}));
        assert_eq!(tasks[2]["options"]["env"], json!({"keep": ["FOO"]}));
        // chsr upgrade shows the lists it adds
        assert!(
            migration
                .changes
                .contains(&"/roles/0/tasks/0/options/env/keep: [] added".to_string())
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
