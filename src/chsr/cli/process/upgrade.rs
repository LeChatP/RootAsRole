use rootasrole_core::{eprintln_ignore_io_error, println_ignore_io_error};
use std::error::Error;

use log::debug;
use rootasrole_core::{PACKAGE_VERSION, database::migrations::read_as_is, file::FileSettings};

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

/// Report the policy files of a directory that could not be loaded: whether there is one.
fn report_ignored(settings: &FileSettings, report: &mut Vec<String>) -> bool {
    for (path, error) in settings.get_ignored() {
        report.push(format!(
            "{}: cannot be loaded, {}",
            printable(&path.display().to_string()),
            printable(error)
        ));
    }
    !settings.get_ignored().is_empty()
}

/// `chsr upgrade`: with `to`, write the policy for that older version, otherwise save the files
/// migrated when they were loaded. With `check`, nothing is saved and an error is returned if a
/// file needs to be written. Returns false: the files are saved here.
pub fn upgrade(
    settings: &mut FileSettings,
    check: bool,
    to: Option<&str>,
) -> Result<bool, Box<dyn Error>> {
    match to {
        Some(to) if to != PACKAGE_VERSION.to_string() => write_for(settings, check, to),
        _ => upgrade_to_current(settings, check),
    }
}

/// Save the files migrated when they were loaded, and report the version of every file.
fn upgrade_to_current(settings: &mut FileSettings, check: bool) -> Result<bool, Box<dyn Error>> {
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
    blocked |= report_ignored(settings, &mut report);
    if pending && !check {
        debug!("Saving the upgraded files");
        if let Err(e) = settings.save_migrated() {
            eprintln_ignore_io_error!("{}", printable(&e.to_string()));
            return Err(e);
        }
    }
    for line in report {
        println_ignore_io_error!("{line}");
    }
    if blocked {
        Err("One or more policy files cannot be upgraded".into())
    } else if pending && check {
        Err("The policy files must be upgraded".into())
    } else {
        Ok(false)
    }
}

/// Write every file for the older version `to`, before it is installed: the migrations down
/// from this version, which only this version knows, give the policy the meaning that it has
/// for this version, or less (see the migrations of rootasrole-core). Every file needs it, so
/// with `check` an error is always returned.
fn write_for(settings: &mut FileSettings, check: bool, to: &str) -> Result<bool, Box<dyn Error>> {
    let files = settings.write_for(to, check)?;
    let mut report = Vec::new();
    let mut blocked = false;
    for file in files {
        let path = printable(&file.path.display().to_string());
        match file.result {
            Ok(migration) => {
                report.push(if check {
                    format!("{path}: {}, can be written for {to}", migration.from)
                } else {
                    format!("{path}: written for {to}, from {}", migration.from)
                });
                report.extend(
                    migration
                        .changes
                        .iter()
                        .map(|change| format!("  {}", printable(change))),
                );
            }
            Err(error) => {
                blocked = true;
                report.push(format!(
                    "{path}: cannot be written for {to}, {}",
                    printable(&error)
                ));
            }
        }
    }
    blocked |= report_ignored(settings, &mut report);
    if !check && read_as_is(Some(to)).is_err() {
        report.push(format!(
            "dosr {PACKAGE_VERSION} refuses a policy written for {to}: install RootAsRole {to} now"
        ));
    }
    for line in report {
        println_ignore_io_error!("{line}");
    }
    if blocked {
        Err(format!("One or more policy files cannot be written for {to}").into())
    } else if check {
        Err(format!("The policy files must be written for {to}").into())
    } else {
        Ok(false)
    }
}
