use crate::{
    SettingsContent,
    database::{
        actor::{SActor, SGroups},
        structs::{
            SCommand, SCommands, SCredentials, SGroupsEither, SPolicy, SRole, STask, SUserEither,
            SetBehavior,
        },
    },
    file::RootSettings,
};

#[allow(dead_code)]
pub trait Warn {
    fn warn_anomalies<F>(&self, warn: F)
    where
        F: FnMut(String);
}

impl Warn for RootSettings {
    fn warn_anomalies<F>(&self, mut warn: F)
    where
        F: FnMut(String),
    {
        self.storage.warn_anomalies(&mut warn);
        self.config.as_ref().borrow().warn_anomalies(&mut warn);
        if self.config.as_ref().borrow().is_empty()
            && self
                .storage
                .settings
                .as_ref()
                .is_none_or(|f| f.path.is_none())
        {
            warn("Warning: No configuration section found".to_string());
        }
    }
}

impl Warn for SPolicy {
    fn warn_anomalies<F>(&self, mut warn: F)
    where
        F: FnMut(String),
    {
        for key in self.extra_fields.keys() {
            warn(format!("Warning: Unknown configuration field '{key}'"));
        }
        if let Some(opt) = &self.options {
            for key in opt.as_ref().borrow().extra_fields.keys() {
                warn(format!(
                    "Warning: Unknown options field at {:?} level '{}'",
                    opt.as_ref().borrow().level,
                    key
                ));
            }
        }
        for role in &self.roles {
            role.as_ref().borrow().warn_anomalies(&mut warn);
        }
    }
}

impl Warn for SRole {
    #[allow(clippy::too_many_lines)]
    fn warn_anomalies<F>(&self, mut warn: F)
    where
        F: FnMut(String),
    {
        for key in self.extra_fields.keys() {
            warn(format!(
                "Warning: Unknown role field in role '{}' : '{}'",
                self.name, key
            ));
        }
        self.warn_actors(&mut warn);
        if let Some(opt) = &self.options {
            for key in opt.as_ref().borrow().extra_fields.keys() {
                warn(format!(
                    "Warning: Unknown options field at {:?} level in role '{}' : '{}'",
                    opt.as_ref().borrow().level,
                    self.name,
                    key
                ));
            }
        }
        for task in &self.tasks {
            for key in self.extra_fields.keys() {
                warn(format!(
                    "Warning: Unknown task field in role '{}' task '{:?}' : '{}'",
                    task.as_ref().borrow().name,
                    self.name,
                    key
                ));
            }
            warn_cred(
                self,
                &task.as_ref().borrow(),
                &task.as_ref().borrow().cred,
                &mut warn,
            );
            warn_cmds(
                self,
                &task.as_ref().borrow(),
                &task.as_ref().borrow().commands,
                &mut warn,
            );
            if let Some(opt) = &self.options {
                for key in opt.as_ref().borrow().extra_fields.keys() {
                    warn(format!(
                        "Warning: Unknown options field at {:?} level in role '{}' task '{:?}' : '{}'",
                        opt.as_ref().borrow().level,
                        self.name,
                        self.name,
                        key
                    ));
                }
            }
        }
    }
}

impl SRole {
    fn warn_actors<F>(&self, mut warn: F)
    where
        F: FnMut(String),
    {
        for actor in &self.actors {
            if actor.is_unknown() {
                warn(format!(
                    "Warning: Unknown actor type in role '{}' : '{:?}'",
                    self.name, actor
                ));
            } else if let SActor::User { id, extra_fields } = actor {
                if let Some(id) = id
                    && id.fetch_user().is_none()
                {
                    warn(format!(
                        "Warning: Unknown user in role '{}' : '{}'",
                        self.name, id
                    ));
                }
                for key in extra_fields.keys() {
                    warn(format!(
                        "Warning: Unknown user field in role '{}' for user '{:?}' : '{}'",
                        self.name, id, key
                    ));
                }
            } else if let SActor::Group {
                groups,
                extra_fields,
            } = actor
            {
                for key in extra_fields.keys() {
                    warn(format!(
                        "Warning: Unknown group field in role '{}' for group '{:?}' : '{}'",
                        self.name, groups, key
                    ));
                }
                if let Some(groups) = groups {
                    match groups {
                        SGroups::Single(sgroup_type) => {
                            if sgroup_type.fetch_group().is_none() {
                                warn(format!(
                                    "Warning: Unknown group in role '{}' : '{:?}'",
                                    self.name, sgroup_type
                                ));
                            }
                        }
                        SGroups::Multiple(sgroup_types) => {
                            for sgroup_type in sgroup_types {
                                if sgroup_type.fetch_group().is_none() {
                                    warn(format!(
                                        "Warning: Unknown group in role '{}' : '{:?}'",
                                        self.name, sgroup_type
                                    ));
                                }
                            }
                        }
                    }
                } else {
                    warn(format!(
                        "Warning: No group specified in role '{}' : '{:?}'",
                        self.name, groups
                    ));
                }
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn warn_cred<F>(role: &SRole, task: &STask, cred: &SCredentials, mut warn: F)
where
    F: FnMut(String),
{
    for key in cred.extra_fields.keys() {
        warn(format!(
            "Warning: Unknown cred field in role '{}' task '{:?}' : '{}'",
            role.name, task.name, key
        ));
    }
    if let Some(id) = &cred.setuid {
        match id {
            SUserEither::MandatoryUser(suser_type) => {
                if suser_type.fetch_user().is_none() {
                    warn(format!(
                        "Warning: Unknown user in role '{}' task '{:?}' setuid: '{:?}'",
                        role.name, task.name, suser_type
                    ));
                }
            }
            SUserEither::UserSelector(ssetuid_set) => {
                if let Some(default) = &ssetuid_set.fallback
                    && default.fetch_user().is_none()
                {
                    warn(format!(
                        "Warning: Unknown user in role '{}' task '{:?}' setuid fallback: '{:?}'",
                        role.name, task.name, default
                    ));
                }
                for add in &ssetuid_set.add {
                    if add.fetch_user().is_none() {
                        warn(format!(
                            "Warning: Unknown user in role '{}' task '{:?}' setuid add: '{:?}'",
                            role.name, task.name, add
                        ));
                    }
                }
                for sub in &ssetuid_set.sub {
                    if sub.fetch_user().is_none() {
                        warn(format!(
                            "Warning: Unknown user in role '{}' task '{:?}' setuid sub: '{:?}'",
                            role.name, task.name, sub
                        ));
                    }
                }
            }
        }
    }
    if let Some(sgroups_either) = &cred.setgid {
        match sgroups_either {
            SGroupsEither::MandatoryGroup(group) => {
                if group.fetch_group().is_none() {
                    warn(format!(
                        "Warning: Unknown group in role '{}' task '{:?}' setgid: '{:?}'",
                        role.name, task.name, group
                    ));
                }
            }
            SGroupsEither::MandatoryGroups(sgroups) => match sgroups {
                SGroups::Single(sgroup_type) => {
                    if sgroup_type.fetch_group().is_none() {
                        warn(format!(
                            "Warning: Unknown group in role '{}' task '{:?}' setgid: '{:?}'",
                            role.name, task.name, sgroup_type
                        ));
                    }
                }
                SGroups::Multiple(sgroup_types) => {
                    for sgroup_type in sgroup_types {
                        if sgroup_type.fetch_group().is_none() {
                            warn(format!(
                                "Warning: Unknown group in role '{}' task '{:?}' setgid: '{:?}'",
                                role.name, task.name, sgroup_type
                            ));
                        }
                    }
                }
            },
            SGroupsEither::GroupSelector(chooser) => {
                match &chooser.fallback {
                    SGroups::Single(sgroup_type) => {
                        if sgroup_type.fetch_group().is_none() {
                            warn(format!(
                                "Warning: Unknown group in role '{}' task '{:?}' setgid fallback: '{:?}'",
                                role.name, task.name, sgroup_type
                            ));
                        }
                    }
                    SGroups::Multiple(sgroup_types) => {
                        for sgroup_type in sgroup_types {
                            if sgroup_type.fetch_group().is_none() {
                                warn(format!(
                                    "Warning: Unknown group in role '{}' task '{:?}' setgid fallback: '{:?}'",
                                    role.name, task.name, sgroup_type
                                ));
                            }
                        }
                    }
                }
                chooser.add.iter().for_each(|group| {
                    match group {
                        SGroups::Single(sgroup_type) => {
                            if sgroup_type.fetch_group().is_none() {
                                warn(format!(
                                    "Warning: Unknown group in role '{}' task '{:?}' setgid add: '{:?}'",
                                    role.name,
                                    task.name,
                                    sgroup_type
                                ));
                            }
                        }
                        SGroups::Multiple(sgroup_types) => {
                            for sgroup_type in sgroup_types {
                                if sgroup_type.fetch_group().is_none() {
                                    warn(format!("Warning: Unknown group in role '{}' task '{:?}' setgid add: '{:?}'", role.name, task.name, sgroup_type));
                                }
                            }
                        }
                    }
                });
                chooser.sub.iter().for_each(|group| {
                    match group {
                        SGroups::Single(sgroup_type) => {
                            if sgroup_type.fetch_group().is_none() {
                                warn(format!(
                                    "Warning: Unknown group in role '{}' task '{:?}' setgid sub: '{:?}'",
                                    role.name,
                                    task.name,
                                    sgroup_type
                                ));
                            }
                        }
                        SGroups::Multiple(sgroup_types) => {
                            for sgroup_type in sgroup_types {
                                if sgroup_type.fetch_group().is_none() {
                                    warn(format!("Warning: Unknown group in role '{}' task '{:?}' setgid sub: '{:?}'", role.name, task.name, sgroup_type));
                                }
                            }
                        }
                    }
                });
            }
        }
    }
}

fn warn_cmds<F>(role: &SRole, task: &STask, cmds: &SCommands, warn: &mut F)
where
    F: FnMut(String),
{
    cmds.extra_fields.keys().for_each(|key| {
        warn(format!(
            "Warning: Unknown commands field in role '{}' task '{:?}' : '{}'",
            role.name, task.name, key
        ));
    });
    if cmds.add.is_empty()
        && !cmds
            .default
            .as_ref()
            .is_some_and(|b| *b == SetBehavior::All)
    {
        warn(format!(
            "Warning: No commands can be performed in role '{}' task '{:?}'",
            role.name, task.name
        ));
    }
    for cmd in &cmds.add {
        match cmd {
            SCommand::Simple(cmd) => {
                if cmd.is_empty() {
                    warn(format!(
                        "Warning: Empty command in role '{}' task '{:?}' in add list",
                        role.name, task.name
                    ));
                }
            }
            SCommand::Complex(value) => {
                if value.as_object().is_none() {
                    warn(format!(
                        "Warning: Complex command is not an dictionnary in role '{}' task '{:?}' : '{:?}'",
                        role.name, task.name, value
                    ));
                }
            }
        }
    }
    for cmd in &cmds.sub {
        match cmd {
            SCommand::Simple(cmd) => {
                if cmd.is_empty() {
                    warn(format!(
                        "Warning: Empty command in role '{}' task '{:?}' in sub list",
                        role.name, task.name
                    ));
                }
            }
            SCommand::Complex(value) => {
                if value.as_object().is_none() {
                    warn(format!(
                        "Warning: Complex command is not an dictionnary in role '{}' task '{:?}' : '{:?}'",
                        role.name, task.name, value
                    ));
                }
            }
        }
    }
}

impl Warn for SettingsContent {
    fn warn_anomalies<F>(&self, _warn: F)
    where
        F: FnMut(String),
    {
        // No anomalies possible for now.
    }
}
