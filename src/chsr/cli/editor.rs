use std::{
    cell::RefCell,
    error::Error,
    io::{Seek, Write},
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
            .default_behavior
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
    migrate_settings(&mut *config.as_ref().borrow_mut())?;
    debug!("Using editor: {}", SYSTEM_EDITOR);

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
        let status = Command::new(SYSTEM_EDITOR)
            .arg("-u")
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
            .arg("--")
            .arg(&path)
            .spawn()
            .map_err(|e| format!("Failed to launch editor: {}", e))?
            .wait_with_output()?;
        debug!("Editor exited with status: {:?}", status.status);
        if !status.status.success() {
            eprintln!("Editor exited with an error.");
            return Ok(false);
        }
        let seek_pos = file.seek(std::io::SeekFrom::Current(0))?;
        debug!("Current file position: {}", seek_pos);
        file.rewind()?;
        debug!("Rewound temporary file for reading");
        match serde_json::from_reader::<_, Versioning<FullSettings>>(&mut file) {
            Ok(new_config) => {
                warn_anomalies(&new_config);
                debug!("config: {:#?}", new_config);
                let after = serde_json::to_string_pretty(&new_config)?;
                println!("Resulting confguration: {}", after);
                let after = serde_json::from_str::<Versioning<FullSettings>>(&after)?;
                debug!("re-serialised: {:#?}", after);
                // Yes == save, No and edit again == continue loop, abort == return false
                println!(
                    "Is this configuration valid? (the Deserializer might delete unknown fields)"
                );
                println!("  [Y]es to save and exit");
                println!("  [N]o to continue editing");
                println!("  [A]bort to exit without saving");
                eprint!("Your choice [Y/n/a]: ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                stdin().read_line(&mut input)?;
                let input = input.trim().to_lowercase();
                if input == "n" || input == "no" {
                    // Replace the cursor position to the last position before reading
                    file.seek(std::io::SeekFrom::Start(seek_pos))?;
                    continue;
                } else if input == "a" || input == "abort" {
                    return Ok(false);
                } else {
                    *config.as_ref().borrow_mut() = new_config.data;
                    return Ok(true);
                }
            }
            Err(e) => {
                eprintln!("Your modifications are invalid:\n{}", e);
                println!("Do you want to continue editing?");
                println!("  [Y]ontinue editing (Recommended)");
                println!("  [A]bort to exit without saving");
                eprint!("Your choice [Y/a]: ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                stdin().read_line(&mut input)?;
                let input = input.trim().to_lowercase();
                if input == "a" || input == "abort" {
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
