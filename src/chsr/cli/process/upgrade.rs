use std::error::Error;

use log::debug;
use rootasrole_core::{PACKAGE_VERSION, file::FileSettings};

/// Escape control characters: paths, entries and errors come from the policy files.
fn printable(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Save the files migrated when they were loaded, and report the version of every file.
/// With `check`, nothing is saved and an error is returned if a file needs an upgrade.
/// Returns false: only the migrated files are saved, here.
pub fn upgrade(settings: &mut FileSettings, check: bool) -> Result<bool, Box<dyn Error>> {
    let mut report = Vec::new();
    let mut pending = false;
    let mut blocked = false;
    for file in settings.get_versions() {
        let path = printable(&file.path.display().to_string());
        if let Some(migration) = file.migration {
            pending = true;
            if check {
                report.push(format!(
                    "{path}: {}, can be upgraded to {PACKAGE_VERSION}",
                    migration.from
                ));
            } else {
                report.push(format!(
                    "{path}: upgraded from {} to {PACKAGE_VERSION}",
                    migration.from
                ));
            }
            report.extend(
                migration
                    .changes
                    .iter()
                    .map(|change| format!("  {}", printable(change))),
            );
        } else if *file.version == PACKAGE_VERSION {
            report.push(format!("{path}: {PACKAGE_VERSION}, up to date"));
        } else {
            blocked = true;
            report.push(format!(
                "{path}: {}, cannot be upgraded to {PACKAGE_VERSION}",
                file.version
            ));
        }
    }
    for (path, error) in settings.get_ignored() {
        blocked = true;
        report.push(format!(
            "{}: cannot be loaded, {}",
            printable(&path.display().to_string()),
            printable(error)
        ));
    }
    if pending && !check {
        debug!("Saving the upgraded files");
        if let Err(e) = settings.save_migrated() {
            eprintln!("{}", printable(&e.to_string()));
            return Err(e);
        }
    }
    for line in report {
        println!("{line}");
    }
    if blocked {
        Err("One or more policy files cannot be upgraded".into())
    } else if pending && check {
        Err("The policy files must be upgraded".into())
    } else {
        Ok(false)
    }
}
