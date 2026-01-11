use std::{
    cell::RefCell,
    error::Error,
    io::{BufRead, Seek, Write},
    os::fd::FromRawFd,
    path::PathBuf,
    rc::Rc,
};

use log::{debug, warn};
use rar_common::{
    database::{
        actor::{SActor, SGroups},
        structs::{SCommands, SCredentials, SGroupsEither, SRole, STask},
        versionning::Versioning,
    },
    migrate_settings, FullSettings,
};
use std::{fs::File, io::stdin, process::Command};

pub struct Defer<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Defer<F> {
    pub fn new(f: F) -> Self {
        Defer(Some(f))
    }
}

impl<F: FnOnce()> Drop for Defer<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

pub fn defer<F: FnOnce()>(f: F) -> Defer<F> {
    Defer::new(f)
}

fn warn_anomalies(full_settings: &Versioning<FullSettings>) {
    let config = &full_settings.data.config;
    if let Some(config) = config {
        for key in config.as_ref().borrow()._extra_fields.keys() {
            warn!("Warning: Unknown configuration field '{}'", key);
        }
        if let Some(opt) = &config.as_ref().borrow().options {
            for key in opt.as_ref().borrow()._extra_fields.keys() {
                warn!(
                    "Warning: Unknown options field at {:?} level '{}'",
                    opt.as_ref().borrow().level,
                    key
                );
            }
        }
        for role in config.as_ref().borrow().roles.iter() {
            for key in role.as_ref().borrow()._extra_fields.keys() {
                warn!(
                    "Warning: Unknown role field in role '{}' : '{}'",
                    role.as_ref().borrow().name,
                    key
                );
            }
            warn_actors(role);
            if let Some(opt) = &role.as_ref().borrow().options {
                for key in opt.as_ref().borrow()._extra_fields.keys() {
                    warn!(
                        "Warning: Unknown options field at {:?} level in role '{}' : '{}'",
                        opt.as_ref().borrow().level,
                        role.as_ref().borrow().name,
                        key
                    );
                }
            }
            for task in role.as_ref().borrow().tasks.iter() {
                for key in task.as_ref().borrow()._extra_fields.keys() {
                    warn!(
                        "Warning: Unknown task field in role '{}' task '{:?}' : '{}'",
                        role.as_ref().borrow().name,
                        task.as_ref().borrow().name,
                        key
                    );
                }
                warn_cred(role.clone(), task.clone(), &task.as_ref().borrow().cred);
                warn_cmds(role.clone(), task.clone(), &task.as_ref().borrow().commands);
                if let Some(opt) = &task.as_ref().borrow().options {
                    for key in opt.as_ref().borrow()._extra_fields.keys() {
                        warn!("Warning: Unknown options field at {:?} level in role '{}' task '{:?}' : '{}'", opt.as_ref().borrow().level, role.as_ref().borrow().name, task.as_ref().borrow().name, key);
                    }
                }
            }
        }
    } else {
        warn!("Warning: No configuration section found in settings.");
    }
}

fn warn_cmds(role: Rc<RefCell<SRole>>, task: Rc<RefCell<STask>>, cmds: &SCommands) {
    cmds._extra_fields.keys().for_each(|key| {
        warn!(
            "Warning: Unknown commands field in role '{}' task '{:?}' : '{}'",
            role.as_ref().borrow().name,
            task.as_ref().borrow().name,
            key
        );
    });
    if cmds.add.is_empty()
        && !cmds
            .default
            .as_ref()
            .is_some_and(|b| *b == rar_common::database::structs::SetBehavior::All)
    {
        warn!(
            "Warning: No commands can be performed in role '{}' task '{:?}'",
            role.as_ref().borrow().name,
            task.as_ref().borrow().name
        );
    }
    for cmd in &cmds.add {
        match cmd {
            rar_common::database::structs::SCommand::Simple(cmd) => {
                if cmd.is_empty() {
                    warn!(
                        "Warning: Empty command in role '{}' task '{:?}' in add list",
                        role.as_ref().borrow().name,
                        task.as_ref().borrow().name
                    );
                }
            }
            rar_common::database::structs::SCommand::Complex(value) => {
                if value.as_object().is_none() {
                    warn!(
                        "Warning: Complex command is not an dictionnary in role '{}' task '{:?}' : '{:?}'",
                        role.as_ref().borrow().name,
                        task.as_ref().borrow().name,
                        value
                    );
                }
            }
        }
    }
    for cmd in &cmds.sub {
        match cmd {
            rar_common::database::structs::SCommand::Simple(cmd) => {
                if cmd.is_empty() {
                    warn!(
                        "Warning: Empty command in role '{}' task '{:?}' in sub list",
                        role.as_ref().borrow().name,
                        task.as_ref().borrow().name
                    );
                }
            }
            rar_common::database::structs::SCommand::Complex(value) => {
                if value.as_object().is_none() {
                    warn!(
                        "Warning: Complex command is not an dictionnary in role '{}' task '{:?}' : '{:?}'",
                        role.as_ref().borrow().name,
                        task.as_ref().borrow().name,
                        value
                    );
                }
            }
        }
    }
}

fn warn_cred(role: Rc<RefCell<SRole>>, task: Rc<RefCell<STask>>, cred: &SCredentials) {
    for key in cred._extra_fields.keys() {
        warn!(
            "Warning: Unknown cred field in role '{}' task '{:?}' : '{}'",
            role.as_ref().borrow().name,
            task.as_ref().borrow().name,
            key
        );
    }
    if let Some(id) = &cred.setuid {
        match id {
            rar_common::database::structs::SUserEither::MandatoryUser(suser_type) => {
                if suser_type.fetch_user().is_none() {
                    warn!(
                        "Warning: Unknown user in role '{}' task '{:?}' setuid: '{:?}'",
                        role.as_ref().borrow().name,
                        task.as_ref().borrow().name,
                        suser_type
                    );
                }
            }
            rar_common::database::structs::SUserEither::UserSelector(ssetuid_set) => {
                if let Some(default) = &ssetuid_set.fallback {
                    if default.fetch_user().is_none() {
                        warn!(
                            "Warning: Unknown user in role '{}' task '{:?}' setuid fallback: '{:?}'",
                            role.as_ref().borrow().name,
                            task.as_ref().borrow().name,
                            default
                        );
                    }
                }
                for add in &ssetuid_set.add {
                    if add.fetch_user().is_none() {
                        warn!(
                            "Warning: Unknown user in role '{}' task '{:?}' setuid add: '{:?}'",
                            role.as_ref().borrow().name,
                            task.as_ref().borrow().name,
                            add
                        );
                    }
                }
                for sub in &ssetuid_set.sub {
                    if sub.fetch_user().is_none() {
                        warn!(
                            "Warning: Unknown user in role '{}' task '{:?}' setuid sub: '{:?}'",
                            role.as_ref().borrow().name,
                            task.as_ref().borrow().name,
                            sub
                        );
                    }
                }
            }
        }
    }
    if let Some(sgroups_either) = &cred.setgid {
        match sgroups_either {
            SGroupsEither::MandatoryGroup(group) => {
                if group.fetch_group().is_none() {
                    warn!(
                        "Warning: Unknown group in role '{}' task '{:?}' setgid: '{:?}'",
                        role.as_ref().borrow().name,
                        task.as_ref().borrow().name,
                        group
                    );
                }
            }
            SGroupsEither::MandatoryGroups(sgroups) => {
                match sgroups {
                    SGroups::Single(sgroup_type) => {
                        if sgroup_type.fetch_group().is_none() {
                            warn!(
                                "Warning: Unknown group in role '{}' task '{:?}' setgid: '{:?}'",
                                role.as_ref().borrow().name,
                                task.as_ref().borrow().name,
                                sgroup_type
                            );
                        }
                    }
                    SGroups::Multiple(sgroup_types) => {
                        for sgroup_type in sgroup_types {
                            if sgroup_type.fetch_group().is_none() {
                                warn!("Warning: Unknown group in role '{}' task '{:?}' setgid: '{:?}'", role.as_ref().borrow().name, task.as_ref().borrow().name, sgroup_type);
                            }
                        }
                    }
                }
            }
            SGroupsEither::GroupSelector(chooser) => {
                match &chooser.fallback {
                    SGroups::Single(sgroup_type) => {
                        if sgroup_type.fetch_group().is_none() {
                            warn!(
                                "Warning: Unknown group in role '{}' task '{:?}' setgid fallback: '{:?}'",
                                role.as_ref().borrow().name,
                                task.as_ref().borrow().name,
                                sgroup_type
                            );
                        }
                    }
                    SGroups::Multiple(sgroup_types) => {
                        for sgroup_type in sgroup_types {
                            if sgroup_type.fetch_group().is_none() {
                                warn!("Warning: Unknown group in role '{}' task '{:?}' setgid fallback: '{:?}'", role.as_ref().borrow().name, task.as_ref().borrow().name, sgroup_type);
                            }
                        }
                    }
                }
                chooser.add.iter().for_each(|group| {
                    match group {
                        SGroups::Single(sgroup_type) => {
                            if sgroup_type.fetch_group().is_none() {
                                warn!(
                                    "Warning: Unknown group in role '{}' task '{:?}' setgid add: '{:?}'",
                                    role.as_ref().borrow().name,
                                    task.as_ref().borrow().name,
                                    sgroup_type
                                );
                            }
                        }
                        SGroups::Multiple(sgroup_types) => {
                            for sgroup_type in sgroup_types {
                                if sgroup_type.fetch_group().is_none() {
                                    warn!("Warning: Unknown group in role '{}' task '{:?}' setgid add: '{:?}'", role.as_ref().borrow().name, task.as_ref().borrow().name, sgroup_type);
                                }
                            }
                        }
                    }
                });
                chooser.sub.iter().for_each(|group| {
                    match group {
                        SGroups::Single(sgroup_type) => {
                            if sgroup_type.fetch_group().is_none() {
                                warn!(
                                    "Warning: Unknown group in role '{}' task '{:?}' setgid sub: '{:?}'",
                                    role.as_ref().borrow().name,
                                    task.as_ref().borrow().name,
                                    sgroup_type
                                );
                            }
                        }
                        SGroups::Multiple(sgroup_types) => {
                            for sgroup_type in sgroup_types {
                                if sgroup_type.fetch_group().is_none() {
                                    warn!("Warning: Unknown group in role '{}' task '{:?}' setgid sub: '{:?}'", role.as_ref().borrow().name, task.as_ref().borrow().name, sgroup_type);
                                }
                            }
                        }
                    }
                });
            }
        }
    }
}

fn warn_actors(role: &Rc<RefCell<rar_common::database::structs::SRole>>) {
    for actor in role.as_ref().borrow().actors.iter() {
        if actor.is_unknown() {
            warn!(
                "Warning: Unknown actor type in role '{}' : '{:?}'",
                role.as_ref().borrow().name,
                actor
            );
        } else if let SActor::User { id, _extra_fields } = actor {
            if let Some(id) = id {
                if id.fetch_user().is_none() {
                    warn!(
                        "Warning: Unknown user in role '{}' : '{}'",
                        role.as_ref().borrow().name,
                        id
                    );
                }
            }
            for key in _extra_fields.keys() {
                warn!(
                    "Warning: Unknown user field in role '{}' for user '{:?}' : '{}'",
                    role.as_ref().borrow().name,
                    id,
                    key
                );
            }
        } else if let SActor::Group {
            groups,
            _extra_fields,
        } = actor
        {
            for key in _extra_fields.keys() {
                warn!(
                    "Warning: Unknown group field in role '{}' for group '{:?}' : '{}'",
                    role.as_ref().borrow().name,
                    groups,
                    key
                );
            }
            if let Some(groups) = groups {
                match groups {
                    SGroups::Single(sgroup_type) => {
                        if sgroup_type.fetch_group().is_none() {
                            warn!(
                                "Warning: Unknown group in role '{}' : '{:?}'",
                                role.as_ref().borrow().name,
                                sgroup_type
                            );
                        }
                    }
                    SGroups::Multiple(sgroup_types) => {
                        for sgroup_type in sgroup_types {
                            if sgroup_type.fetch_group().is_none() {
                                warn!(
                                    "Warning: Unknown group in role '{}' : '{:?}'",
                                    role.as_ref().borrow().name,
                                    sgroup_type
                                );
                            }
                        }
                    }
                }
            } else {
                warn!(
                    "Warning: No group specified in role '{}' : '{:?}'",
                    role.as_ref().borrow().name,
                    groups
                );
            }
        }
    }
}

pub const SYSTEM_EDITOR: &str = env!("RAR_CHSR_EDITOR_PATH");

pub(crate) fn edit_config(
    folder: &PathBuf,
    config: Rc<RefCell<FullSettings>>,
) -> Result<bool, Box<dyn Error>> {
    let stdin = stdin();
    let mut input = stdin.lock();
    let mut stdout = std::io::stdout();
    edit_config_internal(folder, config, SYSTEM_EDITOR, &mut input, &mut stdout)
}

fn edit_config_internal<R, W>(
    folder: &PathBuf,
    config: Rc<RefCell<FullSettings>>,
    editor: &str,
    input: &mut R,
    output: &mut W,
) -> Result<bool, Box<dyn Error>>
where
    R: BufRead,
    W: Write,
{
    migrate_settings(&mut config.as_ref().borrow_mut())?;
    debug!("Using editor: {}", editor);

    debug!("Created temporary folder: {:?}", folder);
    let (fd, path) = nix::unistd::mkstemp(&folder.join("config_XXXXXX"))?;
    debug!("Created temporary file: {:?}", path);

    let mut file = unsafe { File::from_raw_fd(fd) };

    // Write current config to temp file
    serde_json::to_writer_pretty(&mut file, &Versioning::new(config.clone()))?;
    debug!("Wrote current config to temporary file");
    file.flush()?;
    debug!("Flushed temporary file");
    file.rewind()?;
    debug!("Rewound temporary file");

    loop {
        let mut cmd = Command::new(editor);
        if editor == SYSTEM_EDITOR {
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

        let status = cmd
            .arg(&path)
            .spawn()
            .map_err(|e| format!("Failed to launch editor: {}", e))?
            .wait_with_output()?;
        debug!("Editor exited with status: {:?}", status.status);
        if !status.status.success() {
            writeln!(output, "Editor exited with an error.")?;
            return Ok(false);
        }
        let seek_pos = file.stream_position()?;
        debug!("Current file position: {}", seek_pos);
        file.rewind()?;
        debug!("Rewound temporary file for reading");
        match serde_json::from_reader::<_, Versioning<FullSettings>>(&mut file) {
            Ok(new_config) => {
                warn_anomalies(&new_config);
                debug!("config: {:#?}", new_config);
                let after = serde_json::to_string_pretty(&new_config)?;
                writeln!(output, "Resulting confguration: {}", after)?;
                let after = serde_json::from_str::<Versioning<FullSettings>>(&after)?;
                debug!("re-serialised: {:#?}", after);
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
                } else {
                    *config.as_ref().borrow_mut() = new_config.data;
                    return Ok(true);
                }
            }
            Err(e) => {
                writeln!(output, "Your modifications are invalid:\n{}", e)?;
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
                } else {
                    // Replace the cursor position to the last position before reading
                    file.seek(std::io::SeekFrom::Start(seek_pos))?;
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rar_common::database::structs::{SCommand, SConfig, SetBehavior};
    use rar_common::{RemoteStorageSettings, SettingsContent, StorageMethod};

    use super::*;
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_edit_config_success() {
        // Setup a unique temp folder
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir_path = std::env::temp_dir().join(format!("rar_test_{}", timestamp));
        fs::create_dir_all(&temp_dir_path).unwrap();

        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });

        let config = Rc::new(RefCell::new(FullSettings::default()));

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
            serde_json::to_string_pretty(&Versioning::new(Rc::new(RefCell::new(
                FullSettings::builder()
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
                        SConfig::builder()
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
            ))))
            .unwrap()
        );
        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();

        // Inputs/Outputs
        let input_data = b"y\na\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = edit_config_internal(
            &temp_dir_path,
            config.clone(),
            mock_editor_path.to_str().unwrap(),
            &mut input,
            &mut output,
        );

        if let Err(e) = &result {
            println!("Error: {}", e);
            println!("Output: {}", String::from_utf8_lossy(&output));
        }

        let output_str = String::from_utf8(output.clone()).unwrap();
        assert!(
            result.unwrap_or(false),
            "Result failed (or was false). Output:\n{}",
            output_str
        );

        assert!(output_str.contains("Is this configuration valid?"));
    }

    #[test]
    fn test_edit_config_abort() {
        // Setup a unique temp folder
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir_path = std::env::temp_dir().join(format!("rar_test_abort_{}", timestamp));
        fs::create_dir_all(&temp_dir_path).unwrap();

        let temp_dir_path_clone = temp_dir_path.clone();
        let _defer = defer(move || {
            let _ = fs::remove_dir_all(&temp_dir_path_clone);
        });

        let config = Rc::new(RefCell::new(FullSettings::default()));

        let mock_editor_path = temp_dir_path.join("mock_editor.sh");
        let script = r#"#!/bin/sh
for last; do true; done
file="$last"
echo '{ "version": "1.0.0", "storage": { "method": "json" }, "config": null }' > "$file"
"#;
        fs::write(&mock_editor_path, script).unwrap();
        fs::set_permissions(&mock_editor_path, fs::Permissions::from_mode(0o755)).unwrap();

        let input_data = b"a\n";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = edit_config_internal(
            &temp_dir_path,
            config.clone(),
            mock_editor_path.to_str().unwrap(),
            &mut input,
            &mut output,
        );

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
