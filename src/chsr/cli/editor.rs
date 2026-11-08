use std::{
    error::Error,
    fmt::Debug,
    io::{BufRead, Read, Write},
    os::unix::process::CommandExt,
    path::Path,
};

use log::{debug, warn};
use rootasrole_core::{
    PACKAGE_VERSION,
    database::{
        migrations::{
            DocumentMigration, FORMAT_VERSION, UnreadableVersion, migrate_document, read_as_is,
        },
        structs::SPolicy,
        warn::Warn,
    },
    file::RootSettings,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{File, OpenOptions},
    io::stdin,
    process::Command,
};

use crate::security::{editor_lock, seccomp_lock};

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

/// A configuration edited without its version, which chsr writes when it saves the file.
pub trait WithoutVersion {
    /// Forget a version typed in the configuration, kept with the unknown fields.
    fn forget_version(&mut self);
}

impl WithoutVersion for SPolicy {
    fn forget_version(&mut self) {
        self.extra_fields.remove("version");
        self.extra_fields.remove("v");
    }
}

impl WithoutVersion for RootSettings {
    fn forget_version(&mut self) {
        self.config.borrow_mut().forget_version();
    }
}

/// The configuration typed in the editor, and its migration. chsr writes the version when it
/// saves the file: a version typed in the editor was saved next to it, and dosr refuses a policy
/// with two. A typed version is read like the version of a file: the content of an older one is
/// migrated from it, an unknown one is refused, and it is not kept.
fn edited<T: DeserializeOwned + WithoutVersion>(
    text: &str,
) -> Result<(T, Option<DocumentMigration>), String> {
    let mut document: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    match document.get("version").or_else(|| document.get("v")) {
        Some(Value::String(version)) if *version != PACKAGE_VERSION.to_string() => {
            if let Err(UnreadableVersion::Invalid(version)) = read_as_is(Some(version)) {
                return Err(format!("the version \"{version}\" is not valid"));
            }
            let migration = migrate_document(&mut document).map_err(|e| e.to_string())?;
            if let Value::Object(map) = &mut document {
                map.remove("version");
                map.remove("v");
            }
            let config = serde_json::from_value(document).map_err(|e| e.to_string())?;
            Ok((config, migration))
        }
        // read from the text, whose errors tell the line and the column
        Some(Value::String(_)) | None => {
            let mut config: T = serde_json::from_str(text).map_err(|e| e.to_string())?;
            config.forget_version();
            Ok((config, None))
        }
        Some(version) => Err(format!("the version {version} is not valid")),
    }
}

pub const SYSTEM_EDITOR_LIST: &[&str] = &konst::iter::collect_const!(&str =>
    konst::string::split(env!("RAR_CHSR_EDITOR_PATH"), ","),
        map(str::trim_ascii),
);

/// The link to the editor of the system, which root chooses (update-alternatives on Debian).
const SYSTEM_EDITOR: &str = "/usr/bin/editor";

/// The editor of `list` that `link` points to. The link only chooses among the editors of the
/// list, each tested under the sandbox; one outside it (ed, vim.tiny...) is ignored, with a
/// warning in the log. chsr runs it by its path in the list, whose name tells its options:
/// `/usr/bin/vim` where the link resolves to `vim.basic`, joe for jpico, which is a link to joe.
fn system_editor<'a>(link: &str, list: &[&'a str]) -> Option<&'a str> {
    let target = std::fs::canonicalize(link).ok()?;
    let editor = list.iter().copied().find(|&editor| {
        editor != link
            && is_executable_file(editor)
            && std::fs::canonicalize(editor).is_ok_and(|path| path == target)
    });
    if editor.is_none() {
        warn!(
            "Ignoring {link}: {} is not an editor of the list of chsr",
            target.display()
        );
    }
    editor
}

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

/// Edit `config` in an editor, until `check` accepts it or the user aborts.
#[cfg_attr(tarpaulin, ignore)]
pub fn start_editing<P, T: Serialize + DeserializeOwned + Warn + Debug + WithoutVersion>(
    folder: &P,
    config: &mut T,
    check: impl Fn(&T) -> Result<(), String>,
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
        // the editor of the system when it is one of the list, else the first one installed
        let found_editor = system_editor(SYSTEM_EDITOR, SYSTEM_EDITOR_LIST).or_else(|| {
            SYSTEM_EDITOR_LIST
                .iter()
                .copied()
                .find(|&editor| is_executable_file(editor))
        });
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

    edit_internal(
        folder,
        config,
        &editor,
        &mut input,
        &mut stdout,
        |msg| {
            warn!("{msg}");
        },
        check,
    )
}

/// The answer of the user, in lowercase, or `None` at the end of the input: nobody answers, which
/// is no yes (an empty line is the default answer).
fn answer<R: BufRead>(input: &mut R) -> std::io::Result<Option<String>> {
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim().to_lowercase()))
}

/// The command that opens `path` in `editor`, without the configuration of vim.
fn editor_command(editor: &str, path: &Path) -> Command {
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
    } else if editor_name(editor).starts_with("emacs") {
        // in the terminal, without the init files of the user or of the site, like vim above
        cmd.arg("-nw").arg("-Q");
    } else if editor_name(editor) == "micro" {
        // an empty configuration, in the temporary folder: micro loads none of the user, and
        // writes its backups in the only place where the sandbox lets it write; micro creates
        // this directory, where it ignores -config-dir for one that does not exist yet
        if let Some(folder) = path.parent() {
            cmd.env("MICRO_CONFIG_HOME", folder.join("micro"));
        }
    }
    cmd.arg(path);
    cmd
}

/// The file name of the editor, which tells the options it gets.
fn editor_name(editor: &str) -> &str {
    Path::new(editor)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(editor)
}

#[allow(clippy::too_many_lines)]
fn edit_internal<P, R, W, F, T: Serialize + DeserializeOwned + Warn + Debug + WithoutVersion>(
    folder: &P,
    config: &mut T,
    editor: &str,
    input: &mut R,
    output: &mut W,
    mut warn_handler: F,
    check: impl Fn(&T) -> Result<(), String>,
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
    // the editor saves the copy by its path, where chsr reads it again (read_copy)
    drop(file);

    // owned, so the pre_exec closure of the child can hold them (the editor sandbox below)
    let lock_folder = folder.as_ref().to_path_buf();
    let lock_editor = editor.to_string();

    loop {
        let mut cmd = editor_command(editor, &path);
        debug!("Launching editor: {cmd:?}");
        // The editor child is confined: a nested Landlock domain (write only the temporary folder,
        // run only the editor and its interpreter) then the seccomp filter. Skipped under tests,
        // whose editor is a shell-script mock that the sandbox would stop; the sandbox is covered
        // by the security module's own tests and the VM end-to-end checks.
        if !cfg!(test) {
            let child_folder = lock_folder.clone();
            let child_editor = lock_editor.clone();
            // SAFETY: chsr is single-threaded when it launches the editor, so the forked child
            // cannot inherit a lock held by another thread. editor_lock and seccomp_lock only
            // restrict the child.
            unsafe {
                cmd.pre_exec(move || {
                    editor_lock(&child_folder, &child_editor)?;
                    seccomp_lock()
                });
            }
        }
        let status = cmd
            .spawn()
            .map_err(|e| format!("Failed to launch editor: {e}"))?
            .wait_with_output()?;
        debug!("Editor exited with status: {:?}", status.status);
        if !status.status.success() {
            writeln!(output, "Editor exited with an error.")?;
            return Ok(false);
        }
        let text = read_copy(&path)?;
        // a configuration that does not pass the check is invalid like one that does not parse
        match edited::<T>(&text).and_then(|(new_config, migration)| {
            check(&new_config).map(|()| (new_config, migration))
        }) {
            Ok((new_config, migration)) => {
                if let Some(migration) = migration {
                    writeln!(
                        output,
                        "Written for RootAsRole {}, migrated to {FORMAT_VERSION}:",
                        migration.from
                    )?;
                    // the values are JSON, and the keys escaped
                    for change in &migration.changes {
                        writeln!(output, "  {change}")?;
                    }
                }
                new_config.warn_anomalies(&mut warn_handler);
                debug!("config: {new_config:#?}");
                let after = serde_json::to_string_pretty(&new_config)?;
                writeln!(output, "Resulting configuration: {after}")?;
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

                // the end of the input saved the configuration, without a yes
                let Some(choice) = answer(input)? else {
                    writeln!(output, "\nNo answer: nothing is saved.")?;
                    return Ok(false);
                };
                if choice == "n" || choice == "no" {
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
                writeln!(output, "  [Y]es to continue editing (Recommended)")?;
                writeln!(output, "  [A]bort to exit without saving")?;
                write!(output, "Your choice [Y/a]: ")?;
                output.flush()?;

                // the end of the input started the editor again, forever
                let Some(choice) = answer(input)? else {
                    writeln!(output, "\nNo answer: nothing is saved.")?;
                    return Ok(false);
                };
                if choice == "a" || choice == "abort" {
                    return Ok(false);
                }
            }
        }
    }
}

/// The copy that the editor saved, read again by its path: an editor that writes a new file and
/// renames it over the copy (vim and emacs when they keep a backup, which they do outside /tmp)
/// left the descriptor of chsr on the former content, and the edit was lost. Only a regular file:
/// not a link, a FIFO or a device that the editor could have put there.
fn read_copy(path: &Path) -> std::io::Result<String> {
    let not_a_file = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is no longer a regular file", path.display()),
        )
    };
    let before = std::fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(not_a_file());
    }
    // O_NONBLOCK: a FIFO put there between the two would block the open
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file() || (opened.dev(), opened.ino()) != (before.dev(), before.ino())
    {
        return Err(not_a_file());
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use rootasrole_core::database::actor::SActor;
    use rootasrole_core::database::structs::{
        SCommand, SCommands, SCredentials, SPolicy, SRole, STask, SetBehavior,
    };
    use rootasrole_core::file::RootSettings;
    use rootasrole_core::util::StorageMethod;
    use rootasrole_core::{RemoteStorageSettings, SettingsContent};

    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_temp_dir(prefix: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "{prefix}_{}_{}_{}",
            std::process::id(),
            timestamp,
            counter
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    // emacs stays in the terminal without init files, micro gets an empty configuration in the
    // temporary folder, the only place where the sandbox lets it write; the others get the file
    #[test]
    fn test_editor_command_options() {
        let path = Path::new("/tmp/chsr_x/config_y");
        let args = |editor| {
            editor_command(editor, path)
                .get_args()
                .map(|arg| arg.to_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            args("/usr/bin/emacs"),
            ["-nw", "-Q", "/tmp/chsr_x/config_y"]
        );
        assert_eq!(args("/usr/bin/micro"), ["/tmp/chsr_x/config_y"]);
        let micro = editor_command("/usr/bin/micro", path);
        let config = micro
            .get_envs()
            .find(|(key, _)| *key == "MICRO_CONFIG_HOME")
            .and_then(|(_, value)| value);
        assert_eq!(config, Some(std::ffi::OsStr::new("/tmp/chsr_x/micro")));
        assert_eq!(args("/usr/bin/nano"), ["/tmp/chsr_x/config_y"]);
        assert_eq!(args("/usr/bin/joe"), ["/tmp/chsr_x/config_y"]);
        assert_eq!(args("/usr/bin/vim").last().unwrap(), "/tmp/chsr_x/config_y");
    }

    // /usr/bin/editor chooses among the editors of the list, by the file it resolves to, and the
    // editor is run by its path in the list; an editor outside the list, or no link, chooses none
    #[test]
    fn test_system_editor_chooses_among_the_list() {
        use std::os::unix::fs::symlink;
        let dir = test_temp_dir("rar_test_system_editor");
        let path = |name: &str| dir.join(name).to_str().unwrap().to_string();
        for name in ["vim.basic", "nano", "ed"] {
            fs::write(dir.join(name), "").unwrap();
            fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o755)).unwrap();
        }
        // the list names vim by a link, as Debian does through /etc/alternatives/vim
        symlink(dir.join("vim.basic"), dir.join("vim")).unwrap();
        let (vim, nano) = (path("vim"), path("nano"));
        let list = [vim.as_str(), nano.as_str()];
        let link = path("editor");
        assert_eq!(system_editor(&link, &list), None);
        symlink(dir.join("nano"), &link).unwrap();
        assert_eq!(system_editor(&link, &list), Some(nano.as_str()));
        fs::remove_file(&link).unwrap();
        symlink(dir.join("vim.basic"), &link).unwrap();
        assert_eq!(system_editor(&link, &list), Some(vim.as_str()));
        fs::remove_file(&link).unwrap();
        symlink(dir.join("ed"), &link).unwrap();
        assert_eq!(system_editor(&link, &list), None);
        // the link itself in the list does not stand for an editor
        assert_eq!(system_editor(&link, &[link.as_str()]), None);
        let _ = fs::remove_dir_all(&dir);
    }

    // an editor that saves to a new file and renames it over the copy, like vim and emacs when
    // they keep a backup: chsr read the former content through its descriptor and lost the edit
    #[test]
    fn test_edit_saved_by_rename_reaches_chsr() {
        let _lock = LOCK.lock().unwrap();
        let temp_dir_path = test_temp_dir("rar_test_rename");
        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        let script = r#"#!/bin/sh
for last; do true; done
printf '%s' '{"roles": 1}' > "$last.new" && mv "$last.new" "$last"
"#;
        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = RootSettings::default();
        let mut input = Cursor::new(b"a\n");
        let mut output = Vec::new();
        let result = edit_internal(
            &temp_dir_path,
            &mut config,
            mock_editor_path.to_str().unwrap(),
            &mut input,
            &mut output,
            |_| {},
            |_| Ok(()),
        );
        let _ = fs::remove_dir_all(&temp_dir_path);
        assert!(!result.unwrap());
        let output = String::from_utf8(output).unwrap();
        assert!(
            output.contains("Your modifications are invalid"),
            "{output}"
        );
    }

    // the copy replaced by a link: chsr does not follow it, it reads nothing through it
    #[test]
    fn test_copy_replaced_by_a_link_is_refused() {
        let _lock = LOCK.lock().unwrap();
        let temp_dir_path = test_temp_dir("rar_test_link");
        let target = temp_dir_path.join("elsewhere.json");
        fs::write(&target, r#"{"roles": []}"#).unwrap();
        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        let script = format!(
            "#!/bin/sh\nfor last; do true; done\nrm \"$last\" && ln -s '{}' \"$last\"\n",
            target.display()
        );
        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = RootSettings::default();
        let mut input = Cursor::new(b"Y\n");
        let mut output = Vec::new();
        let result = edit_internal(
            &temp_dir_path,
            &mut config,
            mock_editor_path.to_str().unwrap(),
            &mut input,
            &mut output,
            |_| {},
            |_| Ok(()),
        );
        let _ = fs::remove_dir_all(&temp_dir_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_edit_config_success() {
        let temp_dir_path = test_temp_dir("rar_test");
        let _lock = LOCK.lock().unwrap();

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
            |_| Ok(()),
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
        let _lock = LOCK.lock().unwrap();
        let temp_dir_path = test_temp_dir("rar_test_abort");

        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });

        let mut config = RootSettings::default();

        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        let script = r#"#!/bin/sh
for last; do true; done
file="$last"
echo '{ "storage": { "method": "json" }, "unknown_config_field": "foo" }' > "$file"
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
            |_| Ok(()),
        );

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // nobody answers, like `chsr editor < /dev/null`: a valid edit was saved without a yes, and an
    // invalid one started the editor again forever
    #[test]
    fn test_edit_config_end_of_input_saves_nothing() {
        let _lock = LOCK.lock().unwrap();
        for content in [r#"{"roles": [{"name": "r"}]}"#, r#"{"roles": 1}"#] {
            let temp_dir_path = test_temp_dir("rar_test_eof");
            let temp_dir_path_clone = temp_dir_path.clone();
            let _defer = defer(move || {
                let _ = fs::remove_dir_all(&temp_dir_path_clone);
            });
            let mock_editor_path = temp_dir_path.join("mock_editor.sh");
            let runs = temp_dir_path.join("runs");
            let script = format!(
                "#!/bin/sh\nfor last; do true; done\necho '{content}' > \"$last\"\necho run >> '{}'\n",
                runs.display()
            );
            fs::write(&mock_editor_path, script).unwrap();
            fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();

            let (done, finished) = std::sync::mpsc::channel();
            let folder = temp_dir_path.clone();
            std::thread::spawn(move || {
                let mut config = SPolicy::default();
                let mut output = Vec::new();
                let result = edit_internal(
                    &folder,
                    &mut config,
                    mock_editor_path.to_str().unwrap(),
                    &mut Cursor::new(b""),
                    &mut output,
                    |_| {},
                    |_| Ok(()),
                )
                .map_err(|e| e.to_string());
                let unchanged = config == SPolicy::default();
                done.send((result, unchanged, String::from_utf8(output).unwrap()))
                    .unwrap();
            });
            let (result, unchanged, output) = finished
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("the editor is not started again without an answer");
            assert_eq!(result, Ok(false), "{content}");
            assert!(unchanged, "{content}");
            assert!(
                output.ends_with("No answer: nothing is saved.\n"),
                "{output}"
            );
            assert_eq!(fs::read_to_string(&runs).unwrap().lines().count(), 1);
        }
    }

    // the root file edited to name its JSON policy file in CBOR: saved, neither chsr nor dosr
    // read the policy anymore; the check of the storage settings asks to edit again
    #[test]
    fn test_edit_root_storage_is_checked() {
        let _lock = LOCK.lock().unwrap();
        let temp_dir_path = test_temp_dir("rar_test_storage");
        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });
        let version = rootasrole_core::PACKAGE_VERSION.to_string();
        let root = temp_dir_path.join("rootasrole.json");
        let policy = temp_dir_path.join("policy.json");
        fs::write(
            &policy,
            serde_json::json!({"version": version, "roles": []}).to_string(),
        )
        .unwrap();
        let storage = |method: &str| serde_json::json!({"method": method, "settings": {"path": policy, "immutable": false}});
        fs::write(
            &root,
            serde_json::json!({"version": version, "storage": storage("json")}).to_string(),
        )
        .unwrap();
        let mut settings =
            rootasrole_core::file::FileSettings::write_all(&root, &root, StorageMethod::JSON)
                .unwrap();
        let check = settings.storage_check();

        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        let script = format!(
            "#!/bin/sh\nfor last; do true; done\necho '{}' > \"$last\"\n",
            serde_json::json!({"storage": storage("cbor")})
        );
        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut output = Vec::new();
        let result = edit_internal(
            &temp_dir_path,
            settings.get_root_mut(),
            mock_editor_path.to_str().unwrap(),
            &mut Cursor::new(b"a\n"),
            &mut output,
            |_| {},
            |root: &RootSettings| check.check(&root.storage),
        );
        let output = String::from_utf8(output).unwrap();
        assert!(!result.unwrap(), "{output}");
        assert!(output.contains("is not a policy in cbor"), "{output}");
        assert!(!output.contains("Resulting configuration"), "{output}");
        assert_eq!(settings.get_root().storage.method, StorageMethod::JSON);
    }

    // chsr writes the version when it saves the file: a version typed in the editor (the policy
    // of the book has one) was saved next to it, which dosr refuses, and on the next load chsr
    // took the typed one; it is now read like the version of a file
    #[test]
    fn test_edit_typed_version() {
        let _lock = LOCK.lock().unwrap();
        let temp_dir_path = test_temp_dir("rar_test_version");
        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });
        let version = rootasrole_core::PACKAGE_VERSION.to_string();
        let root = temp_dir_path.join("rootasrole.json");
        let policy = temp_dir_path.join("policy.json");
        fs::write(
            &root,
            serde_json::json!({"version": version, "storage": {"method": "json", "settings": {"path": policy, "immutable": false}}}).to_string(),
        )
        .unwrap();
        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        let edit = |typed: &serde_json::Value, answers: &'static [u8]| {
            let before = serde_json::json!({"version": version, "roles": []}).to_string();
            fs::write(&policy, &before).unwrap();
            let script =
                format!("#!/bin/sh\nfor last; do true; done\necho '{typed}' > \"$last\"\n");
            fs::write(&mock_editor_path, script).unwrap();
            fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();
            let mut settings =
                rootasrole_core::file::FileSettings::write_all(&root, &root, StorageMethod::JSON)
                    .unwrap();
            let target = settings.get_policies()[0].clone();
            let mut output = Vec::new();
            let saved = edit_internal(
                &temp_dir_path,
                &mut *target.borrow_mut(),
                mock_editor_path.to_str().unwrap(),
                &mut Cursor::new(answers),
                &mut output,
                |_| {},
                |_| Ok(()),
            )
            .unwrap();
            if saved {
                settings.save_all().unwrap();
            }
            (
                String::from_utf8(output).unwrap(),
                fs::read_to_string(&policy).unwrap(),
            )
        };
        let roles = serde_json::json!([{"name": "r"}]);
        for typed in [
            serde_json::json!({"roles": roles}),
            serde_json::json!({"version": version, "roles": roles}),
            serde_json::json!({"v": version, "roles": roles}),
        ] {
            let (output, saved) = edit(&typed, b"y\n");
            assert_eq!(saved.matches("\"version\"").count(), 1, "{typed}: {saved}");
            assert!(!saved.contains("\"v\""), "{typed}: {saved}");
            assert_eq!(
                serde_json::from_str::<Value>(&saved).unwrap()["roles"],
                roles
            );
            assert!(!output.contains("migrated"), "{output}");
        }
        // an older version: the content is migrated from it, and the migration shown
        let (output, saved) = edit(
            &serde_json::json!({"version": "4.0.3", "options": {"env": {"check": ["LC_.*"]}}}),
            b"y\n",
        );
        // written for the format, which this version reads
        let format = rootasrole_core::database::migrations::FORMAT_VERSION.to_string();
        assert!(
            output.contains(&format!(
                "Written for RootAsRole 4.0.3, migrated to {format}:"
            )),
            "{output}"
        );
        assert!(
            output.contains(r#"/options/env/check/0: "LC_.*" -> "LC_*""#),
            "{output}"
        );
        let saved: Value = serde_json::from_str(&saved).unwrap();
        assert_eq!(saved["version"], format.as_str());
        assert_eq!(
            saved["options"]["env"]["check"],
            serde_json::json!(["LC_*"])
        );
        // unknown or invalid: edited again, here aborted
        let newer = format!("{}.0.0", rootasrole_core::PACKAGE_VERSION.major + 1);
        for (typed, reason) in [
            ("3.0.0".into(), "No migration path"),
            (serde_json::json!(newer), "No migration path"),
            ("x".into(), "is not valid"),
            (serde_json::json!(4.2), "is not valid"),
        ] {
            let (output, saved) = edit(
                &serde_json::json!({"version": typed, "roles": roles}),
                b"a\n",
            );
            assert!(output.contains(reason), "{typed}: {output}");
            assert_eq!(
                saved,
                serde_json::json!({"version": version, "roles": []}).to_string()
            );
        }
    }

    #[test]
    fn test_edit_config_err() {
        let _lock = LOCK.lock().unwrap();
        let temp_dir_path = test_temp_dir("rar_test_abort");

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
            |_| Ok(()),
        );

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_warn_no_config() {
        let _lock = LOCK.lock().unwrap();
        let temp_dir_path = test_temp_dir("rar_test_warn_no_config");

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
            |_| Ok(()),
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
        let _lock = LOCK.lock().unwrap();
        let temp_dir_path = test_temp_dir("rar_test_warn_anomalies");

        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });

        let mut config = RootSettings::default();

        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        // We construct a JSON with many unknown fields to trigger warnings
        let json_content = r#"{
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
            |_| Ok(()),
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
        // the fields of the task, once, not those of its role for each task
        assert!(w(
            "Unknown task field in role 'role1' task 'Name(\"task1\")' : 'unknown_task_field'"
        ));
        assert!(w(
            "in role 'role1' task 'Name(\"task1\")' : 'unknown_task_opt'"
        ));
        assert!(!w("task field in role 'role1' task 'Name(\"task2\")'"));
        assert_eq!(
            warnings
                .iter()
                .filter(|msg| msg.contains("'unknown_role_field'"))
                .count(),
            1
        );
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
