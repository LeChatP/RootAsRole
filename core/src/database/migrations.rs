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
    database::{
        command::{
            anchored_regex, has_top_level_alternation, regex_arguments, regex_body, split_command,
        },
        migration::{Migration, MigrationError},
    },
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
            rewrite_path_behaviors(document, path_behavior_4_1_0);
            Ok(())
        },
        down: |_, document| {
            replace_default_delete_list(document, ENV_DELETE_LIST_SLICE, DELETE_LIST_4_0_3);
            rewrite_env_entries(document, wildcard_to_regex);
            rewrite_path_behaviors(document, path_behavior_4_0_3);
            rewrite_commands(document, command_with_no_argument);
            Ok(())
        },
    },
    Migration {
        from: || Version::new(4, 1, 0),
        to: || Version::new(4, 2, 0),
        up: unchanged,
        down: |_, document| {
            remove_options_of_4_2(document);
            remove_groups_from(document);
            rewrite_commands(document, group_top_level_alternation);
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

/// Since 4.1.0, the PATH behaviors are written like in chsr: `keep-safe` and `keep-unsafe`.
fn path_behavior_4_1_0(behavior: &str) -> Option<&'static str> {
    match behavior {
        "keepsafe" | "keep_safe" => Some("keep-safe"),
        "keepunsafe" | "keep_unsafe" => Some("keep-unsafe"),
        _ => None,
    }
}

/// Up to 4.0.3, only `keepsafe` and `keepunsafe` are read.
fn path_behavior_4_0_3(behavior: &str) -> Option<&'static str> {
    match behavior {
        "keep-safe" | "keep_safe" => Some("keepsafe"),
        "keep-unsafe" | "keep_unsafe" => Some("keepunsafe"),
        _ => None,
    }
}

/// Rewrite the `default` behavior of every `path` option of the document.
fn rewrite_path_behaviors(document: &mut Value, rewrite: fn(&str) -> Option<&'static str>) {
    match document {
        Value::Object(map) => {
            if let Some(Value::Object(path)) = map.get_mut("path")
                && let Some(Value::String(behavior)) = path.get_mut("default")
                && let Some(rewritten) = rewrite(behavior)
            {
                info!("Migrating path default `{behavior}` to `{rewritten}`");
                *behavior = rewritten.to_string();
            }
            map.values_mut()
                .for_each(|value| rewrite_path_behaviors(value, rewrite));
        }
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| rewrite_path_behaviors(value, rewrite)),
        _ => {}
    }
}

/// 4.1.0 has neither the `password` nor the `tty` option: they are removed from the options of
/// every level. Without `tty`, 4.1.0 leaves the terminal to the caller, as `"owner": "caller"`.
fn remove_options_of_4_2(document: &mut Value) {
    match document {
        Value::Object(map) => {
            if let Some(Value::Object(options)) = map.get_mut("options") {
                for name in ["password", "tty"] {
                    if options.remove(name).is_some() {
                        info!("Removing the {name} option, unknown before 4.2.0");
                    }
                }
            }
            map.values_mut().for_each(remove_options_of_4_2);
        }
        Value::Array(values) => values.iter_mut().for_each(remove_options_of_4_2),
        _ => {}
    }
}

/// `from` of a `setgid` selector is unknown before 4.2.0, whatever its key (the CBOR format writes
/// `o`). A selector with nothing else than `"default": "none"` is removed with it: 4.1.0 then
/// keeps the groups of the caller, as `from: caller` did, instead of requiring `-g`. 4.1.0 cannot
/// give the groups of the target user, which `from: target` and a task without `setgid` do.
fn remove_groups_from(document: &mut Value) {
    let Value::Object(document) = document else {
        return;
    };
    for roles in ["roles", "r"] {
        let Some(Value::Array(roles)) = document.get_mut(roles) else {
            continue;
        };
        for role in roles {
            for tasks in ["tasks", "t"] {
                let Some(Value::Array(tasks)) = role.get_mut(tasks) else {
                    continue;
                };
                for task in tasks {
                    for cred in ["cred", "credentials", "i"] {
                        if let Some(Value::Object(cred)) = task.get_mut(cred) {
                            remove_cred_groups_from(cred);
                        }
                    }
                }
            }
        }
    }
}

fn remove_cred_groups_from(cred: &mut serde_json::Map<String, Value>) {
    for setgid in ["setgid", "g"] {
        let Some(Value::Object(selector)) = cred.get_mut(setgid) else {
            continue;
        };
        let Some(from) = selector.remove("from").or_else(|| selector.remove("o")) else {
            continue;
        };
        info!("Removing from: {from} of a setgid selector, unknown before 4.2.0");
        let nothing_else = selector.iter().all(|(key, value)| {
            matches!(key.as_str(), "default" | "d") && (value == "none" || value == 0)
        });
        if nothing_else {
            cred.remove(setgid);
        }
    }
}

/// A top-level alternation grouped for 4.1.0, which allows no more than 4.2.0.
///
/// Since 4.2.0, a regular expression on the arguments matches the whole arguments whatever its
/// alternations, where 4.1.0 read `^start|stop$` as `^start` or `stop$`. The upgrade leaves it as
/// written, since it now allows less; the downgrade writes `^(?:start|stop)$`.
fn group_top_level_alternation(command: &str) -> Option<String> {
    let (path, args) = split_command(command)?;
    let regex = regex_arguments(args)?;
    has_top_level_alternation(regex_body(regex))
        .then(|| format!("{path} {}", anchored_regex(regex)))
}

/// Whether a command of the policy is only a path, without arguments.
fn path_only(command: &str) -> bool {
    let command = command.trim();
    !command.is_empty() && !command.contains(char::is_whitespace)
}

/// Since 4.1.0, a command written without arguments allows none; 4.0.3 read it as any arguments.
/// The upgrade leaves it as written, the downgrade writes `^$` after it, which 4.0.3 reads as no
/// argument, so that a downgrade never allows more.
fn command_with_no_argument(command: &str) -> Option<String> {
    path_only(command).then(|| format!("{} ^$", command.trim()))
}

/// Rewrite every command of the tasks of the document, in its lists and in the lists of its
/// selectors, whatever the keys (the CBOR format writes short ones).
fn rewrite_commands(document: &mut Value, rewrite: fn(&str) -> Option<String>) {
    let Value::Object(document) = document else {
        return;
    };
    for roles in ["roles", "r"] {
        let Some(Value::Array(roles)) = document.get_mut(roles) else {
            continue;
        };
        for role in roles {
            for tasks in ["tasks", "t"] {
                let Some(Value::Array(tasks)) = role.get_mut(tasks) else {
                    continue;
                };
                for task in tasks {
                    for commands in ["commands", "cmds", "c"] {
                        match task.get_mut(commands) {
                            Some(Value::Array(list)) => rewrite_command_list(list, rewrite),
                            Some(Value::Object(selector)) => {
                                for list in ["add", "a", "sub", "del", "s"] {
                                    if let Some(Value::Array(list)) = selector.get_mut(list) {
                                        rewrite_command_list(list, rewrite);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

/// Rewrite the commands of a list, the ones of plugins (an object with a `command`) included.
fn rewrite_command_list(list: &mut [Value], rewrite: fn(&str) -> Option<String>) {
    for command in list {
        let command = match command {
            Value::String(command) => command,
            Value::Object(object) => match object.get_mut("command") {
                Some(Value::String(command)) => command,
                _ => continue,
            },
            _ => continue,
        };
        if let Some(rewritten) = rewrite(command) {
            info!("Migrating command `{command}` to `{rewritten}`");
            *command = rewritten;
        }
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

    #[test]
    fn test_commands_without_arguments_up_and_down() {
        // the upgrade leaves them as written: since 4.1.0 they allow no argument
        let commands = json!(["/usr/bin/id", "**", "/usr/bin/ls ^.*$"]);
        let mut document = json!({"roles": [{"tasks": [{"commands": commands}]}]});
        Migration::migrate_from(
            &Version::new(4, 0, 3),
            &PACKAGE_VERSION,
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document["roles"][0]["tasks"][0]["commands"], commands);

        // the downgrade writes ^$: 4.0.3 would read them as any arguments
        let mut document = json!({
            "roles": [{"tasks": [
                {"commands": ["/usr/bin/id", "/usr/bin/ls -l", "/usr/bin/ls ^.*$"]},
                {"commands": {"default": "none", "add": ["/usr/bin/cat"], "del": ["/usr/bin/rm"]}},
                {"commands": [{"command": "/usr/bin/ls", "sha256": "00"}]},
                {"commands": "all"}
            ]}]
        });
        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 0, 3),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        let tasks = &document["roles"][0]["tasks"];
        assert_eq!(
            tasks[0]["commands"],
            json!(["/usr/bin/id ^$", "/usr/bin/ls -l", "/usr/bin/ls ^.*$"])
        );
        assert_eq!(
            tasks[1]["commands"],
            json!({"default": "none", "add": ["/usr/bin/cat ^$"], "del": ["/usr/bin/rm ^$"]})
        );
        assert_eq!(tasks[2]["commands"][0]["command"], "/usr/bin/ls ^$");
        assert_eq!(tasks[3]["commands"], "all");

        // the short keys of the CBOR format
        let mut document = json!({"r": [{"t": [{"c": ["/usr/bin/id"]}]}]});
        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 0, 3),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document["r"][0]["t"][0]["c"], json!(["/usr/bin/id ^$"]));
    }

    #[test]
    fn test_password_option_up_and_down() {
        let mut document = json!({
            "options": {"password": {"tries": 5}, "timeout": {"type": "tty"}},
            "roles": [{
                "name": "r",
                "options": {"password": {"delay": "00:00:01"}},
                "tasks": [{"name": "t", "options": {"password": {"tries": 1}}}]
            }]
        });
        let before = document.clone();
        Migration::migrate_from(
            &Version::new(4, 1, 0),
            &PACKAGE_VERSION,
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document, before, "the upgrade keeps the option");

        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 1, 0),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document["options"], json!({"timeout": {"type": "tty"}}));
        assert_eq!(document["roles"][0]["options"], json!({}));
        assert_eq!(document["roles"][0]["tasks"][0]["options"], json!({}));
    }

    #[test]
    fn test_tty_option_up_and_down() {
        let mut document = json!({
            "options": {"tty": {"owner": "target"}, "timeout": {"type": "tty"}},
            "roles": [{
                "name": "r",
                "options": {"tty": {"owner": "caller"}},
                "tasks": [{"name": "t", "options": {"tty": {"owner": "target"}, "umask": "022"}}]
            }]
        });
        let before = document.clone();
        Migration::migrate_from(
            &Version::new(4, 1, 0),
            &PACKAGE_VERSION,
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document, before, "the upgrade keeps the option");

        // 4.1.0 always leaves the terminal to the caller
        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 1, 0),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document["options"], json!({"timeout": {"type": "tty"}}));
        assert_eq!(document["roles"][0]["options"], json!({}));
        assert_eq!(
            document["roles"][0]["tasks"][0]["options"],
            json!({"umask": "022"})
        );
    }

    #[test]
    fn test_groups_from_is_removed_down() {
        let task = |cred: Value| json!({"name": "t", "cred": cred});
        let mut document = json!({
            "roles": [{
                "name": "r",
                "tasks": [
                    task(json!({"setuid": "nobody", "setgid": {"from": "caller"}})),
                    task(json!({"setgid": {"default": "none", "add": [["adm"]], "from": "caller"}})),
                    task(json!({"setgid": {"default": "all", "from": "target"}})),
                    task(json!({"setgid": {"default": "none", "fallback": ["adm"], "from": "target"}})),
                    task(json!({"setgid": "adm"}))
                ]
            }, {
                // the short keys of the CBOR format
                "name": "c",
                "t": [{"name": "t", "i": {"g": {"d": 0, "o": "caller"}}}]
            }]
        });
        let before = document.clone();
        Migration::migrate_from(
            &Version::new(4, 1, 0),
            &PACKAGE_VERSION,
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document, before, "the upgrade writes no from");

        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 1, 0),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        let creds: Vec<&Value> = document["roles"][0]["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|task| &task["cred"])
            .collect();
        // nothing else than from: no setgid, 4.1.0 keeps the groups of the caller
        assert_eq!(creds[0], &json!({"setuid": "nobody"}));
        assert_eq!(
            creds[1],
            &json!({"setgid": {"default": "none", "add": [["adm"]]}})
        );
        assert_eq!(creds[2], &json!({"setgid": {"default": "all"}}));
        assert_eq!(
            creds[3],
            &json!({"setgid": {"default": "none", "fallback": ["adm"]}})
        );
        assert_eq!(creds[4], &json!({"setgid": "adm"}));
        assert_eq!(document["roles"][1]["t"][0]["i"], json!({}));
    }

    #[test]
    fn test_top_level_alternation_is_grouped_down() {
        let mut document = json!({
            "roles": [{
                "name": "r",
                "tasks": [{
                    "name": "t",
                    "commands": [
                        "/usr/bin/systemctl ^start|stop$",
                        "/usr/bin/systemctl '^start|restart$'",
                        "/usr/bin/systemctl ^(start|stop) caddy$",
                        "/usr/bin/tail ^-n [0-9]+$",
                        "/usr/bin/apt update"
                    ]
                }, {
                    "name": "selector",
                    "commands": {"default": "none", "del": ["/usr/bin/kill ^-9|-KILL$"]}
                }]
            }, {
                // the short keys of the CBOR format
                "name": "c",
                "t": [{"name": "t", "c": ["/usr/bin/systemctl ^a|b$"]}]
            }]
        });
        let before = document.clone();
        Migration::migrate_from(
            &Version::new(4, 1, 0),
            &PACKAGE_VERSION,
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(
            document, before,
            "the upgrade leaves the commands as written"
        );

        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 1, 0),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(
            document["roles"][0]["tasks"][0]["commands"],
            json!([
                "/usr/bin/systemctl ^(?:start|stop)$",
                "/usr/bin/systemctl ^(?:start|restart)$",
                "/usr/bin/systemctl ^(start|stop) caddy$",
                "/usr/bin/tail ^-n [0-9]+$",
                "/usr/bin/apt update"
            ])
        );
        assert_eq!(
            document["roles"][0]["tasks"][1]["commands"]["del"],
            json!(["/usr/bin/kill ^(?:-9|-KILL)$"])
        );
        assert_eq!(
            document["roles"][1]["t"][0]["c"],
            json!(["/usr/bin/systemctl ^(?:a|b)$"])
        );
    }

    #[test]
    fn test_4_1_0_documents_up_and_down() {
        let original = json!({
            "version": "4.1.0",
            "options": {"env": {"default": "delete", "check": ["LC_*"]}, "path": {"default": "keep-safe"}},
            "roles": [{"name": "r", "tasks": [{"name": "t", "commands": ["/usr/bin/ls ^.*$"]}]}]
        });
        let mut document = original.clone();
        let migration = migrate_document(&mut document).unwrap().unwrap();
        assert_eq!(migration.from, Version::new(4, 1, 0));
        assert_eq!(document["version"], PACKAGE_VERSION.to_string());
        let mut unchanged = original.clone();
        unchanged["version"] = document["version"].clone();
        assert_eq!(
            document, unchanged,
            "4.1.0 to 4.2.0 changes nothing but the version"
        );

        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 1, 0),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document["version"], PACKAGE_VERSION.to_string());
        document["version"] = original["version"].clone();
        assert_eq!(document, original);
    }

    #[test]
    fn test_path_behaviors_up_and_down() {
        let mut document = json!({
            "options": {"path": {"default": "keepsafe"}},
            "roles": [{"options": {"path": {"default": "keep_unsafe"}}, "tasks": [
                {"options": {"path": {"default": "delete"}}}
            ]}]
        });
        Migration::migrate_from(
            &Version::new(4, 0, 3),
            &PACKAGE_VERSION,
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document["options"]["path"]["default"], "keep-safe");
        assert_eq!(
            document["roles"][0]["options"]["path"]["default"],
            "keep-unsafe"
        );
        assert_eq!(
            document["roles"][0]["tasks"][0]["options"]["path"]["default"],
            "delete"
        );
        Migration::migrate_from(
            &PACKAGE_VERSION,
            &Version::new(4, 0, 3),
            &mut document,
            DOCUMENT_MIGRATIONS,
        )
        .unwrap();
        assert_eq!(document["options"]["path"]["default"], "keepsafe");
        assert_eq!(
            document["roles"][0]["options"]["path"]["default"],
            "keepunsafe"
        );
    }
}
