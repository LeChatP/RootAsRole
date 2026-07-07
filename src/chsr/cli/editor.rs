use std::{
    error::Error,
    fmt::Debug,
    io::{BufRead, Seek, Write},
    os::unix::process::CommandExt,
    path::Path,
};

use log::{debug, warn};
use rar_common::database::warn::Warn;
use serde::{Serialize, de::DeserializeOwned};
use std::os::unix::fs::PermissionsExt;
use std::{fs::File, io::stdin, process::Command};

use crate::security::seccomp_lock;

pub struct Defer<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Defer<F> {
    pub const fn new(f: F) -> Self {
        Self(Some(f))
    }
}

impl<F: FnOnce()> Drop for Defer<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

pub const fn defer<F: FnOnce()>(f: F) -> Defer<F> {
    Defer::new(f)
}

pub const SYSTEM_EDITOR_LIST: &[&str] = &konst::iter::collect_const!(&str =>
    konst::string::split(env!("RAR_CHSR_EDITOR_PATH"), ","),
        map(str::trim_ascii),
);

fn is_vim(editor: &str) -> bool {
    editor.ends_with("vim") || editor.ends_with("nvim")
}

fn is_executable_file(path: &str) -> bool {
    if !Path::new(path).is_absolute() {
        return false;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    meta.permissions().mode() & 0o111 != 0
}

#[cfg_attr(tarpaulin, ignore)]
pub fn start_editing<P, T: Serialize + DeserializeOwned + Warn + Debug>(
    folder: &P,
    config: &mut T,
) -> Result<bool, Box<dyn Error>>
where
    P: AsRef<Path>,
{
    let stdin = stdin();
    let mut input = stdin.lock();
    let mut stdout = std::io::stdout();
    // Use RAR_EDITOR only if it is in the build-time whitelist and executable.
    let env_editor = std::env::var("RAR_EDITOR").ok();
    let editor = env_editor.map_or_else(String::new, |editor| {
        if SYSTEM_EDITOR_LIST.iter().any(|&allowed| allowed == editor)
            && is_executable_file(&editor)
        {
            debug!("Using editor from RAR_EDITOR env variable: {editor}");
            editor
        } else {
            warn!("Ignoring RAR_EDITOR: not in whitelist or not executable.");
            String::new()
        }
    });

    let editor = if editor.is_empty() {
        let mut found_editor = None;
        for &editor in SYSTEM_EDITOR_LIST {
            if is_executable_file(editor) {
                found_editor = Some(editor);
                break;
            }
        }
        if let Some(editor) = found_editor {
            debug!("Using editor from SYSTEM_EDITOR_LIST: {editor}");
            editor.to_string()
        } else {
            return Err(
                "No editor found. Please set RAR_EDITOR to a whitelisted editor path.".into(),
            );
        }
    } else {
        editor
    };

    edit_internal(folder, config, &editor, &mut input, &mut stdout, |msg| {
        warn!("{msg}");
    })
}

fn edit_internal<P, R, W, F, T: Serialize + DeserializeOwned + Warn + Debug>(
    folder: &P,
    config: &mut T,
    editor: &str,
    input: &mut R,
    output: &mut W,
    mut warn_handler: F,
) -> Result<bool, Box<dyn Error>>
where
    R: BufRead,
    W: Write,
    F: FnMut(String),
    P: AsRef<Path>,
{
    debug!("Using editor: {editor}");

    debug!("Created temporary folder: {}", folder.as_ref().display());
    let (fd, path) = nix::unistd::mkstemp(&folder.as_ref().join("config_XXXXXX"))?;
    debug!("Created temporary file: {}", path.display());

    let mut file = File::from(fd);

    // Write current config to temp file
    serde_json::to_writer_pretty(&mut file, &config)?;
    debug!("Wrote current config to temporary file");
    file.flush()?;
    debug!("Flushed temporary file");
    file.rewind()?;
    debug!("Rewound temporary file");

    loop {
        let mut cmd = Command::new(editor);
        if is_vim(editor) {
            cmd.arg("-u")
                .arg("NONE")
                .arg("-U")
                .arg("NONE")
                .arg("-N")
                .arg("-i")
                .arg("NONE")
                .arg("--noplugin")
                .arg("-c")
                .arg("syntax on")
                .arg("-c")
                .arg("set ft=json")
                .arg("--");
        }
        cmd.arg(&path);
        debug!("Launching editor: {cmd:?}");
        unsafe { cmd.pre_exec(seccomp_lock) };
        let status = cmd
            .spawn()
            .map_err(|e| format!("Failed to launch editor: {e}"))?
            .wait_with_output()?;
        debug!("Editor exited with status: {:?}", status.status);
        if !status.status.success() {
            writeln!(output, "Editor exited with an error.")?;
            return Ok(false);
        }
        let seek_pos = file.stream_position()?;
        debug!("Current file position: {seek_pos}");
        file.rewind()?;
        debug!("Rewound temporary file for reading");
        match serde_json::from_reader::<_, T>(&mut file) {
            Ok(new_config) => {
                new_config.warn_anomalies(&mut warn_handler);
                debug!("config: {new_config:#?}");
                let after = serde_json::to_string_pretty(&new_config)?;
                writeln!(output, "Resulting confguration: {after}")?;
                let after = serde_json::from_str::<T>(&after)?;
                debug!("re-serialised: {after:#?}");
                // Yes == save, No and edit again == continue loop, abort == return false
                writeln!(
                    output,
                    "Is this configuration valid? (the Deserializer might delete unknown fields)"
                )?;
                writeln!(output, "  [Y]es to save and exit")?;
                writeln!(output, "  [N]o to continue editing")?;
                writeln!(output, "  [A]bort to exit without saving")?;
                write!(output, "Your choice [Y/n/a]: ")?;
                output.flush()?;

                let mut line = String::new();
                input.read_line(&mut line)?;
                let choice = line.trim().to_lowercase();
                if choice == "n" || choice == "no" {
                    // Replace the cursor position to the last position before reading
                    file.seek(std::io::SeekFrom::Start(seek_pos))?;
                    continue;
                } else if choice == "a" || choice == "abort" {
                    return Ok(false);
                }
                // else save and exit
                *config = new_config;
                return Ok(true);
            }
            Err(e) => {
                writeln!(output, "Your modifications are invalid:\n{e}")?;
                writeln!(output, "Do you want to continue editing?")?;
                writeln!(output, "  [Y]ontinue editing (Recommended)")?;
                writeln!(output, "  [A]bort to exit without saving")?;
                write!(output, "Your choice [Y/a]: ")?;
                output.flush()?;

                let mut line = String::new();
                input.read_line(&mut line)?;
                let choice = line.trim().to_lowercase();
                if choice == "a" || choice == "abort" {
                    return Ok(false);
                }
                // else Replace the cursor position to the last position before reading
                file.seek(std::io::SeekFrom::Start(seek_pos))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rar_common::database::actor::SActor;
    use rar_common::database::structs::{
        SCommand, SCommands, SCredentials, SPolicy, SRole, STask, SetBehavior,
    };
    use rar_common::file::RootSettings;
    use rar_common::util::StorageMethod;
    use rar_common::{RemoteStorageSettings, SettingsContent};

    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_edit_config_success() {
        // Setup a unique temp folder
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir_path = std::env::temp_dir().join(format!("rar_test_{timestamp}"));
        fs::create_dir_all(&temp_dir_path).unwrap();

        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });

        let mut config = RootSettings::default();

        // Create a mock editor script
        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        // We write valid JSON to the file passed as argument
        // Versioning uses flattened data, so fields of FullSettings are at root
        let script = format!(
            r#"#!/bin/sh
for last; do true; done
file="$last"
echo '{}' > "$file"
"#,
            serde_json::to_string_pretty(&Rc::new(RefCell::new(
                RootSettings::builder()
                    .storage(
                        SettingsContent::builder()
                            .method(StorageMethod::JSON)
                            .settings(
                                RemoteStorageSettings::builder()
                                    .path(mock_editor_path.clone())
                                    .not_immutable()
                                    .build(),
                            )
                            .build(),
                    )
                    .config(
                        SPolicy::builder()
                            .role(
                                SRole::builder("test_role")
                                    .actor(SActor::user(0).build())
                                    .task(
                                        STask::builder("test_task")
                                            .cred(
                                                SCredentials::builder().setuid(0).setgid(0).build()
                                            )
                                            .commands(
                                                SCommands::builder(SetBehavior::None)
                                                    .add(vec![SCommand::Simple(
                                                        "/usr/bin/true".to_string(),
                                                    )])
                                                    .build(),
                                            )
                                            .build(),
                                    )
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )))
            .unwrap()
        );
        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();

        // Inputs/Outputs
        let input_data = b"y\na\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        let mut warnings = Vec::new();

        let result = edit_internal(
            &temp_dir_path,
            &mut config,
            mock_editor_path.to_str().unwrap(),
            &mut input,
            &mut output,
            |msg| warnings.push(msg),
        );

        if let Err(e) = &result {
            println!("Error: {e}");
            println!("Output: {}", String::from_utf8_lossy(&output));
        }

        let output_str = String::from_utf8(output.clone()).unwrap();
        assert!(
            result.unwrap_or(false),
            "Result failed (or was false). Output:\n{output_str}"
        );

        assert!(output_str.contains("Is this configuration valid?"));
        assert!(
            warnings.is_empty(),
            "Expected no warnings, but got: {warnings:?}"
        );
    }

    #[test]
    fn test_edit_config_abort() {
        // Setup a unique temp folder
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir_path = std::env::temp_dir().join(format!("rar_test_abort_{timestamp}"));
        fs::create_dir_all(&temp_dir_path).unwrap();

        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });

        let mut config = RootSettings::default();

        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        let script = r#"#!/bin/sh
for last; do true; done
file="$last"
echo '{ "version": "1.0.0", "storage": { "method": "json" }, "unknown_config_field": "foo" }' > "$file"
"#;
        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();

        let input_data = b"a\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = edit_internal(
            &temp_dir_path,
            &mut config,
            mock_editor_path.to_str().unwrap(),
            &mut input,
            &mut output,
            |_| {},
        );

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_edit_config_err() {
        // Setup a unique temp folder
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir_path = std::env::temp_dir().join(format!("rar_test_abort_{timestamp}"));
        fs::create_dir_all(&temp_dir_path).unwrap();

        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });

        let mut config = RootSettings::default();

        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        let script = r#"#!/bin/sh
for last; do true; done
file="$last"
echo '{ "version": "1.0.0", "storage": { "method": "json" }, mistake  }' > "$file"
"#;
        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();

        let input_data = b"y\na\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = edit_internal(
            &temp_dir_path,
            &mut config,
            mock_editor_path.to_str().unwrap(),
            &mut input,
            &mut output,
            |_| {},
        );

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_warn_no_config() {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir_path =
            std::env::temp_dir().join(format!("rar_test_warn_no_config_{timestamp}"));
        fs::create_dir_all(&temp_dir_path).unwrap();

        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });

        let mut config = RootSettings::default();

        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        let script = r#"#!/bin/sh
for last; do true; done
file="$last"
echo '{ "storage": { "method": "json" } }' > "$file"
"#;
        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();

        let input_data = b"y\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        let mut warnings = Vec::new();

        let result = edit_internal(
            &temp_dir_path,
            &mut config,
            mock_editor_path.to_str().unwrap(),
            &mut input,
            &mut output,
            |msg| warnings.push(msg),
        );

        assert!(result.unwrap());
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("No configuration section found"))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_warn_anomalies() {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir_path =
            std::env::temp_dir().join(format!("rar_test_warn_anomalies_{timestamp}"));
        fs::create_dir_all(&temp_dir_path).unwrap();

        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });

        let mut config = RootSettings::default();

        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        // We construct a JSON with many unknown fields to trigger warnings
        let json_content = r#"{
    "version": "1.0.0",
    "storage": { "method": "json" },
    "unknown_config_field": "foo",
    "options": {
        "unknown_options_field": "bar"
    },
    "roles": [
        {
            "name": "role1",
            "unknown_role_field": "baz",
            "actors": [
                { "type": "user", "id": "rar_missing_u", "unknown_user_field": "u" },
                { "type": "group", "groups": "rar_missing_g", "unknown_group_field": "g" },
                { "type": "group", "groups": ["rar_missing_g0"] },
                { "type": "group", "groups": ["rar_missing_g1","rar_missing_g2"] },
                { "type": "group", "groups": [] },
                { "unknown_actor_type": "something" }
            ],
            "options": {
                "unknown_role_opt": "val"
            },
            "tasks": [
                {
                    "name": "task1",
                    "unknown_task_field": "tval",
                    "options": { "unknown_task_opt": "oval" },
                    "cred": {
                        "unknown_cred_field": "cval",
                        "setuid": "rar_missing_u2",
                        "setgid": "rar_missing_g2"
                    },
                    "commands": {
                         "unknown_cmd_field": "cmdval",
                         "add": [ "", 123 ],
                         "sub": [ "", 456 ]
                    }
                },
                {
                    "name": "task2",
                    "cred": {
                        "setuid": {
                            "fallback": "rar_missing_u3",
                            "add": [ "rar_missing_u4" ],
                            "sub": [ "rar_missing_u5" ]
                        },
                        "setgid": {
                            "fallback": "rar_missing_g3",
                            "add": [ "rar_missing_g4" ],
                            "sub": [ "rar_missing_g5" ]
                        }
                    },
                    "commands": { "add": ["/bin/true"] }
                },
                {
                    "name": "task3",
                    "cred": {
                        "setgid": [ "rar_missing_g6", "rar_missing_g7" ]
                    },
                    "commands": { "default": "none" }
                },
                {
                    "name": "task4",
                    "cred": {
                        "setgid": [ "rar_missing_g8" ]
                    }
                },
                {
                    "name": "task5",
                    "cred": {
                        "setgid": {
                            "fallback": [ "rar_missing_g9", "rar_missing_g10" ],
                            "add": [ ["rar_missing_g11", "rar_missing_g12"] ],
                            "sub": [ ["rar_missing_g13", "rar_missing_g14"] ]
                        }
                    }
                }
            ]
        }
    ]
}"#;
        let script = format!(
            r#"#!/bin/sh
for last; do true; done
file="$last"
cat > "$file" <<EOF
{json_content}
EOF
"#
        );

        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();

        let input_data = b"y\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();
        let mut warnings = Vec::new();

        let result = edit_internal(
            &temp_dir_path,
            &mut config,
            mock_editor_path.to_str().unwrap(),
            &mut input,
            &mut output,
            |msg| warnings.push(msg),
        );

        if let Err(e) = &result {
            println!("Error: {e}");
            println!("Output: {}", String::from_utf8_lossy(&output));
        }

        assert!(result.unwrap());

        let w = |s: &str| warnings.iter().any(|msg| msg.contains(s));

        assert!(w("Unknown configuration field 'unknown_config_field'"));
        assert!(w("Unknown options field")); // matches multiple
        assert!(w("Unknown role field"));
        assert!(w("Unknown actor type"));
        assert!(w("Unknown user in role"));
        assert!(w("Unknown user field"));
        assert!(w("Unknown group in role"));
        assert!(w("Unknown group field"));
        assert!(w("Unknown task field"));
        assert!(w("Unknown cred field"));
        assert!(w("Unknown commands field"));
        assert!(w("Empty command in role"));
        assert!(w("Complex command is not an dictionnary"));
        assert!(w("setuid fallback"));
        assert!(w("setuid add"));
        assert!(w("setuid sub"));
        assert!(w("setgid fallback"));
        assert!(w("setgid add"));
        assert!(w("setgid sub"));
    }
}
