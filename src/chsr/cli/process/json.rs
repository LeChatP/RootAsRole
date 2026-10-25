use rootasrole_core::println_ignore_io_error;
use std::{cell::RefCell, collections::HashMap, error::Error, num::NonZeroU8, rc::Rc};

use indexmap::IndexSet;
use jiff::SignedDuration;
use log::{debug, warn};

use crate::cli::data::{
    CommandChecks, EnvOverride, InputAction, PasswordOpt, RoleLink, RoleType, SetListType,
    TaskType, TimeoutOpt,
};
use serde_json::Value;

use rootasrole_core::database::{
    options::{
        EnvBehavior, EnvKey, Opt, OptStack, OptType, PathBehavior, SPassword, SPathOptions,
        STimeout, SUMask, SWorkdirEither, SWorkdirSet, WorkdirBehavior,
    },
    structs::{
        GroupsFrom, IdTask, RoleGetter, SCapabilities, SCommand, SGroupsEither, SRole, SSetgidSet,
        STask, SUserEither, SetBehavior,
    },
};

use super::perform_on_target_opt;

pub fn list_json(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options: bool,
    options_type: Option<OptType>,
    task_type: Option<TaskType>,
    role_type: Option<RoleType>,
) -> Result<(), Box<dyn Error>> {
    let Some(role_id) = role_id else {
        if options {
            let rcopt = OptStack::from_roles(rconfig)
                .to_opt()
                .map_err(std::io::Error::other)?;
            println_ignore_io_error!(
                "{}",
                options_to_show(&rcopt.as_ref().borrow(), options_type)?
            );
        } else {
            println_ignore_io_error!(
                "{}",
                serde_json::to_string_pretty(&*rconfig.as_ref().borrow())?
            );
        }
        return Ok(());
    };
    let role = rconfig.role(role_id).ok_or("Role not found")?;
    list_task(task_id, &role, options, options_type, task_type, role_type)
}

/// The options of a level, resolved with the upper levels, or only the one asked for.
fn options_to_show(opt: &Opt, options_type: Option<OptType>) -> serde_json::Result<String> {
    match options_type {
        None => serde_json::to_string_pretty(opt),
        Some(OptType::Path) => serde_json::to_string_pretty(&opt.path),
        Some(OptType::Env) => serde_json::to_string_pretty(&opt.env),
        Some(OptType::Root) => serde_json::to_string_pretty(&opt.root),
        Some(OptType::Bounding) => serde_json::to_string_pretty(&opt.bounding),
        Some(OptType::Timeout) => serde_json::to_string_pretty(&opt.timeout),
        Some(OptType::Password) => serde_json::to_string_pretty(&opt.password),
        Some(OptType::Authentication) => serde_json::to_string_pretty(&opt.authentication),
        Some(OptType::ExecInfo) => serde_json::to_string_pretty(&opt.execinfo),
        Some(OptType::UMask) => serde_json::to_string_pretty(&opt.umask),
        Some(OptType::Workdir) => serde_json::to_string_pretty(&opt.workdir),
    }
}

fn list_task(
    task_id: Option<IdTask>,
    role: &Rc<RefCell<rootasrole_core::database::structs::SRole>>,
    options: bool,
    options_type: Option<OptType>,
    task_type: Option<TaskType>,
    role_type: Option<RoleType>,
) -> Result<(), Box<dyn Error>> {
    if let Some(task_id) = task_id {
        let task = role
            .as_ref()
            .borrow()
            .task(&task_id)
            .cloned()
            .ok_or("Task not found")?;
        if options {
            debug!("task {task:?}");
            let rcopt = OptStack::from_task(&task)
                .to_opt()
                .map_err(std::io::Error::other)?;
            println_ignore_io_error!(
                "{}",
                options_to_show(&rcopt.as_ref().borrow(), options_type)?
            );
        } else {
            print_task(&task, task_type.unwrap_or(TaskType::All))?;
        }
    } else if options {
        let rcopt = OptStack::from_role(&role.clone())
            .to_opt()
            .map_err(std::io::Error::other)?;
        println_ignore_io_error!(
            "{}",
            options_to_show(&rcopt.as_ref().borrow(), options_type)?
        );
    } else {
        print_role(role, role_type.unwrap_or(RoleType::All))?;
    }
    Ok(())
}

fn print_task(
    task: &std::rc::Rc<std::cell::RefCell<rootasrole_core::database::structs::STask>>,
    task_type: TaskType,
) -> Result<(), Box<dyn std::error::Error>> {
    match task_type {
        TaskType::All => {
            println_ignore_io_error!("{}", serde_json::to_string_pretty(&task)?);
        }
        TaskType::Commands => {
            println_ignore_io_error!(
                "{}",
                serde_json::to_string_pretty(&task.as_ref().borrow().commands)?
            );
        }
        TaskType::Credentials => {
            println_ignore_io_error!(
                "{}",
                serde_json::to_string_pretty(&task.as_ref().borrow().cred)?
            );
        }
    }
    Ok(())
}

fn print_role(
    role: &std::rc::Rc<std::cell::RefCell<rootasrole_core::database::structs::SRole>>,
    role_type: RoleType,
) -> Result<(), Box<dyn std::error::Error>> {
    match role_type {
        RoleType::All => {
            println_ignore_io_error!("{}", serde_json::to_string_pretty(&role)?);
        }
        RoleType::Actors => {
            println_ignore_io_error!(
                "{}",
                serde_json::to_string_pretty(&role.as_ref().borrow().actors)?
            );
        }
        RoleType::Tasks => {
            println_ignore_io_error!(
                "{}",
                serde_json::to_string_pretty(&role.as_ref().borrow().tasks)?
            );
        }
    }
    Ok(())
}

pub fn role_add_del(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    action: InputAction,
    role_id: String,
    role_type: Option<RoleType>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 {action:?}");
    match action {
        InputAction::Add => {
            //verify if role exists
            if rconfig.role(&role_id).is_some() {
                return Err("Role already exists".into());
            }
            rconfig
                .as_ref()
                .borrow_mut()
                .roles
                .push(SRole::builder(role_id).build());
            Ok(true)
        }
        InputAction::Del => {
            if rconfig.role(&role_id).is_none() {
                return Err("Role do not exists".into());
            }
            rconfig
                .as_ref()
                .borrow_mut()
                .roles
                .retain(|r| r.as_ref().borrow().name != role_id);
            Ok(true)
        }
        InputAction::Purge => {
            if rconfig.role(&role_id).is_none() {
                return Err("Role do not exists".into());
            }
            let role = rconfig.role(&role_id).ok_or("Role not found")?;
            match role_type {
                Some(RoleType::Actors) => {
                    role.as_ref().borrow_mut().actors.clear();
                }
                Some(RoleType::Tasks) => {
                    role.as_ref().borrow_mut().tasks.clear();
                }
                None | Some(RoleType::All) => {
                    role.as_ref().borrow_mut().actors.clear();
                    role.as_ref().borrow_mut().tasks.clear();
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub fn task_add_del(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    action: InputAction,
    task_id: IdTask,
    task_type: Option<TaskType>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 add|del");
    let role = rconfig.role(role_id).ok_or("Role not found")?;
    match action {
        InputAction::Add => {
            //verify if task exists
            if role
                .as_ref()
                .borrow()
                .tasks
                .iter()
                .any(|t| t.as_ref().borrow().name == task_id)
            {
                return Err("Task already exists".into());
            }
            role.as_ref()
                .borrow_mut()
                .tasks
                .push(STask::builder(task_id).build());
            Ok(true)
        }
        InputAction::Del => {
            if role
                .as_ref()
                .borrow()
                .tasks
                .iter()
                .all(|t| t.as_ref().borrow().name != task_id)
            {
                return Err("Task do not exists".into());
            }
            role.as_ref()
                .borrow_mut()
                .tasks
                .retain(|t| t.as_ref().borrow().name != task_id);
            Ok(true)
        }
        InputAction::Purge => {
            let borrow = &role.as_ref().borrow();
            let task = borrow.task(&task_id).ok_or("Task not found")?;
            match task_type {
                Some(TaskType::Commands) => {
                    task.as_ref().borrow_mut().commands.add.clear();
                    task.as_ref().borrow_mut().commands.sub.clear();
                    task.as_ref().borrow_mut().commands.default = None;
                }
                Some(TaskType::Credentials) => {
                    task.as_ref().borrow_mut().cred.capabilities = None;
                    task.as_ref().borrow_mut().cred.setuid = None;
                    task.as_ref().borrow_mut().cred.setgid = None;
                }
                None | Some(TaskType::All) => {
                    task.as_ref().borrow_mut().commands.add.clear();
                    task.as_ref().borrow_mut().commands.sub.clear();
                    task.as_ref().borrow_mut().commands.default = None;
                    task.as_ref().borrow_mut().cred.capabilities = None;
                    task.as_ref().borrow_mut().cred.setuid = None;
                    task.as_ref().borrow_mut().cred.setgid = None;
                }
            }
            Ok(true)
        }
        _ => Err("Invalid action".into()),
    }
}

pub fn grant_revoke(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    action: InputAction,
    mut actors: Vec<rootasrole_core::database::actor::SActor>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 grant|revoke");
    let role = rconfig.role(role_id).ok_or("Role not found")?;
    match action {
        InputAction::Add => {
            //verify if actor is already in role
            //remove already existing actors
            actors.retain(|a| {
                if role.as_ref().borrow().actors.contains(a) {
                    println_ignore_io_error!("Actor {a} already in role");
                    false
                } else {
                    true
                }
            });
            role.as_ref().borrow_mut().actors.extend(actors);
            Ok(true)
        }
        InputAction::Del => {
            //if an actor is not in role, warns
            for actor in &actors {
                if !role.as_ref().borrow().actors.contains(actor) {
                    println_ignore_io_error!("Actor {actor} not in role");
                }
            }
            role.as_ref()
                .borrow_mut()
                .actors
                .retain(|a| !actors.contains(a));
            Ok(true)
        }
        _ => Err("Invalid action".into()),
    }
}

pub fn cred_set(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    task_id: IdTask,
    cred_caps: Option<capctl::CapSet>,
    cred_setuid: Option<rootasrole_core::database::actor::SUserType>,
    cred_setgid: Option<rootasrole_core::database::actor::SGroups>,
    groups_from: Option<GroupsFrom>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 cred");
    if groups_from.is_some() && cred_setgid.is_some() {
        return Err("--setgid-from only applies when --setgid does not force the groups".into());
    }
    match rconfig.task(role_id, task_id) {
        Ok(task) => {
            if let Some(caps) = cred_caps {
                task.as_ref().borrow_mut().cred.capabilities = Some(SCapabilities::from(caps));
            }
            if let Some(setuid) = cred_setuid {
                task.as_ref().borrow_mut().cred.setuid = Some(SUserEither::MandatoryUser(setuid));
            }
            if let Some(setgid) = cred_setgid {
                task.as_ref().borrow_mut().cred.setgid =
                    Some(SGroupsEither::MandatoryGroups(setgid));
            }
            if let Some(from) = groups_from {
                let mut task = task.as_ref().borrow_mut();
                if let Some(SGroupsEither::GroupSelector(selector)) = task.cred.setgid.as_mut() {
                    selector.from = Some(from);
                } else {
                    if task.cred.setgid.is_some() {
                        warn!("The groups that the task forced are replaced by --setgid-from");
                    }
                    task.cred.setgid = Some(SGroupsEither::GroupSelector(
                        SSetgidSet::builder(SetBehavior::None).from(from).build(),
                    ));
                }
            }
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

pub fn cred_unset(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    task_id: IdTask,
    cred_caps: Option<capctl::CapSet>,
    cred_setuid: Option<&rootasrole_core::database::actor::SUserType>,
    cred_setgid: Option<&rootasrole_core::database::actor::SGroups>,
    groups_from: bool,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 cred unset");
    match rconfig.task(role_id, task_id) {
        Ok(task) => {
            if let Some(caps) = cred_caps {
                if caps.is_empty() {
                    task.as_ref().borrow_mut().cred.capabilities = None;
                } else if let Some(ccaps) = task.as_ref().borrow_mut().cred.capabilities.as_mut() {
                    ccaps.add.drop_all(caps);
                } else {
                    return Err("No capabilities to remove".into());
                }
            }
            if cred_setuid.is_some() {
                task.as_ref().borrow_mut().cred.setuid = None;
            }
            if cred_setgid.is_some() {
                task.as_ref().borrow_mut().cred.setgid = None;
            }
            if groups_from {
                let mut task = task.as_ref().borrow_mut();
                let Some(SGroupsEither::GroupSelector(selector)) = task.cred.setgid.as_mut() else {
                    return Err("The task has no --setgid-from to unset".into());
                };
                selector.from = None;
                // a selector with nothing else is no setgid
                if selector.default_behavior.is_none()
                    && selector.fallback.is_none()
                    && selector.add.is_empty()
                    && selector.sub.is_empty()
                {
                    task.cred.setgid = None;
                }
            }
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

pub fn cred_caps(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    task_id: IdTask,
    setlist_type: SetListType,
    action: InputAction,
    cred_caps: capctl::CapSet,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 cred caps");
    let task = rconfig.task(role_id, task_id)?;
    match setlist_type {
        SetListType::White => match action {
            InputAction::Add => {
                let mut borrow = task.as_ref().borrow_mut();
                let caps = borrow.cred.capabilities.get_or_insert_default();

                caps.add = caps.add.union(cred_caps);
                debug!("caps.add: {:?}, cred_caps : {:?}", caps.add, cred_caps);
            }
            InputAction::Del => {
                task.as_ref()
                    .borrow_mut()
                    .cred
                    .capabilities
                    .as_mut()
                    .ok_or("No capabilities to remove from the add set")?
                    .add
                    .drop_all(cred_caps);
            }
            InputAction::Set => {
                task.as_ref()
                    .borrow_mut()
                    .cred
                    .capabilities
                    .get_or_insert_default()
                    .add = cred_caps;
            }
            _ => return Err(format!("Unknown action {action:?}").into()),
        },
        SetListType::Black => match action {
            InputAction::Add => {
                let mut borrow = task.as_ref().borrow_mut();
                let caps = borrow.cred.capabilities.get_or_insert_default();
                caps.sub = caps.sub.union(cred_caps);
            }
            InputAction::Del => {
                task.as_ref()
                    .borrow_mut()
                    .cred
                    .capabilities
                    .as_mut()
                    .ok_or("Cannot remove capabilities from an empty del")?
                    .sub
                    .drop_all(cred_caps);
            }
            InputAction::Set => {
                task.as_ref()
                    .borrow_mut()
                    .cred
                    .capabilities
                    .get_or_insert_default()
                    .sub = cred_caps;
            }
            _ => return Err(format!("Unknown action {action:?}").into()),
        },
        _ => return Err("Unknown list type".into()),
    }
    Ok(true)
}

pub fn cred_setpolicy(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    task_id: IdTask,
    cred_policy: rootasrole_core::database::structs::SetBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 cred setpolicy");
    let task = rconfig.task(role_id, task_id)?;
    if task.as_ref().borrow_mut().cred.capabilities.is_none() {
        task.as_ref()
            .borrow_mut()
            .cred
            .capabilities
            .replace(SCapabilities::default());
    }
    task.as_ref()
        .borrow_mut()
        .cred
        .capabilities
        .get_or_insert_default()
        .default_behavior = cred_policy;
    Ok(true)
}

pub fn cmd_whitelist_action(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    task_id: IdTask,
    line: &str,
    setlist_type: SetListType,
    action: InputAction,
    checks: &CommandChecks,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 command whitelist add c1");
    let task = rconfig.task(role_id, task_id)?;
    let mut task = task.as_ref().borrow_mut();
    let list = match setlist_type {
        SetListType::White => &mut task.commands.add,
        SetListType::Black => &mut task.commands.sub,
        _ => return Err("Unknown list type".into()),
    };
    let listed = |command: &SCommand| command_line(command) == Some(line);
    match action {
        InputAction::Add => {
            if list.iter().any(listed) {
                return Err("Command already exists".into());
            }
            list.push(command_entry(line.to_string(), checks));
        }
        InputAction::Del => {
            if !list.iter().any(listed) {
                println_ignore_io_error!("Command {line:?} not in task");
            }
            // in either form, with checks or not
            list.retain(|command| !listed(command));
        }
        _ => return Err(format!("Unknown action {action:?}").into()),
    }
    Ok(true)
}

/// The command line of an entry of a command list: the string, or the `command` of an entry
/// with the checks of the hashchecker plugin.
fn command_line(command: &SCommand) -> Option<&str> {
    match command {
        SCommand::Simple(line) => Some(line),
        SCommand::Complex(entry) => entry.get("command").and_then(Value::as_str),
    }
}

/// The entry of a command line: the string, or an object with the checks of the hashchecker
/// plugin.
fn command_entry(line: String, checks: &CommandChecks) -> SCommand {
    if *checks == CommandChecks::default() {
        return SCommand::Simple(line);
    }
    warn!(
        "The hashchecker plugin is deprecated and will be removed in RootAsRole 5.0: \
        use the IPE LSM to restrict which files can be executed"
    );
    let mut entry = serde_json::Map::new();
    entry.insert("command".into(), Value::from(line));
    if let Some((kind, hash)) = &checks.hash {
        entry.insert(kind.clone(), Value::from(hash.clone()));
    }
    if checks.read_only {
        entry.insert("read_only".into(), Value::Bool(true));
    }
    if checks.immutable {
        entry.insert("immutable".into(), Value::Bool(true));
    }
    SCommand::Complex(Value::Object(entry))
}

/// `chsr role R ssd|parents add|del|set R2,R3` and `... purge`: the roles that a member of R
/// must not hold (ssd), or whose tasks R gets (parents), kept as a list of names in R.
pub fn edit_role_links(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    link: RoleLink,
    action: InputAction,
    names: Vec<String>,
) -> Result<bool, Box<dyn Error>> {
    let key = link.key();
    debug!("chsr role r1 {key} {action:?}");
    let role = rconfig.role(role_id).ok_or("Role not found")?;
    if names.iter().any(|name| name == role_id) {
        return Err(format!("The {key} of {role_id} cannot name {role_id} itself").into());
    }
    if matches!(action, InputAction::Add | InputAction::Set) {
        for name in names.iter().filter(|name| rconfig.role(name).is_none()) {
            println_ignore_io_error!("Role {name} does not exist (yet)");
        }
    }
    let mut role = role.as_ref().borrow_mut();
    let mut current: Vec<String> = match role.extra_fields.get(key) {
        None => Vec::new(),
        Some(Value::String(name)) => vec![name.clone()],
        Some(Value::Array(linked)) => linked
            .iter()
            .map(|name| name.as_str().map(str::to_string))
            .collect::<Option<_>>()
            .ok_or_else(|| format!("The {key} of {role_id} holds something else than names"))?,
        Some(other) => {
            return Err(format!("The {key} of {role_id} is not a list of roles: {other}").into());
        }
    };
    match action {
        InputAction::Add | InputAction::Set => {
            if action == InputAction::Set {
                current.clear();
            }
            for name in names {
                if !current.contains(&name) {
                    current.push(name);
                }
            }
        }
        InputAction::Del => current.retain(|name| !names.contains(name)),
        InputAction::Purge => current.clear(),
        _ => return Err(format!("Unknown action {action:?}").into()),
    }
    if current.is_empty() {
        role.extra_fields.remove(key);
    } else {
        role.extra_fields
            .insert(key.to_string(), Value::from(current));
    }
    Ok(true)
}

/// `chsr role R task T purpose set <text>` and `... purpose unset`.
pub fn edit_task_purpose(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    task_id: IdTask,
    action: InputAction,
    purpose: Option<String>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 purpose {action:?}");
    let task = rconfig.task(role_id, task_id)?;
    task.as_ref().borrow_mut().purpose = match action {
        InputAction::Set => Some(purpose.ok_or("purpose set needs a text")?),
        InputAction::Del => None,
        _ => return Err(format!("Unknown action {action:?}").into()),
    };
    Ok(true)
}

/// `chsr o env override allow|deny|unset`: whether `dosr -E` may change the env behavior.
pub fn set_env_override(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    value: EnvOverride,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o env override {value:?}");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        match value {
            EnvOverride::Allow | EnvOverride::Deny => {
                binding.env.get_or_insert_default().override_behavior =
                    Some(value == EnvOverride::Allow);
            }
            EnvOverride::Unset => {
                if let Some(env) = binding.env.as_mut() {
                    env.override_behavior = None;
                }
            }
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn cmd_setpolicy(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: &str,
    task_id: IdTask,
    cmd_policy: rootasrole_core::database::structs::SetBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 command setpolicy");
    let task = rconfig.task(role_id, task_id)?;
    task.as_ref()
        .borrow_mut()
        .commands
        .default
        .replace(cmd_policy);
    Ok(true)
}

/// `chsr o env keep-only|delete-only`: the behavior and its list (keep in delete mode, delete
/// in keep mode); the other env fields of the level (check, set, override, unknown fields) stay.
pub fn env_set_policylist(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_env: &IndexSet<EnvKey>,
    options_env_policy: EnvBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o env set keep-only|delete-only {options_env:?}");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let env = binding.env.get_or_insert_default();
        env.default_behavior = options_env_policy;
        if options_env_policy.is_delete() {
            env.keep = Some(options_env.clone());
        } else if options_env_policy.is_keep() {
            env.delete = Some(options_env.clone());
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn set_privileged(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_root: Option<rootasrole_core::database::options::SPrivileged>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o root set privileged {options_root:?}");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().root = options_root;
        Ok(())
    })?;
    Ok(true)
}

pub fn set_bounding(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_bounding: Option<rootasrole_core::database::options::SBounding>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o bounding set {options_bounding:?}");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().bounding = options_bounding;
        Ok(())
    })?;
    Ok(true)
}

pub fn set_authentication(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_auth: Option<rootasrole_core::database::options::SAuthentication>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o auth set {options_auth:?}");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().authentication = options_auth;
        Ok(())
    })?;
    Ok(true)
}

pub fn set_execinfo(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_execinfo: Option<rootasrole_core::database::options::SInfo>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o execinfo set {options_execinfo:?}");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().execinfo = options_execinfo;
        Ok(())
    })?;
    Ok(true)
}

pub fn set_umask(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_umask: Option<SUMask>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o umask set {options_umask:?}");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().umask = options_umask;
        Ok(())
    })?;
    Ok(true)
}

pub fn path_set(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
    options_path: &str,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o path set");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let path = binding.path.get_or_insert_default();
        match setlist_type {
            Some(SetListType::White) => {
                path.add = Some(
                    options_path
                        .split(':')
                        .map(std::string::ToString::to_string)
                        .collect(),
                );
            }
            Some(SetListType::Black) => {
                path.sub = Some(
                    options_path
                        .split(':')
                        .map(std::string::ToString::to_string)
                        .collect(),
                );
            }
            None => {
                path.default_behavior = PathBehavior::Delete;
                path.add = Some(
                    options_path
                        .split(':')
                        .map(std::string::ToString::to_string)
                        .collect(),
                );
            }
            _ => return Err("Unknown list type".into()),
        }
        Ok(())
    })?;
    Ok(true)
}

/// `chsr o path (whitelist|blacklist) purge`: the level no longer defines the list, which is
/// inherited again, like the env lists. An explicit empty list would also remove the inherited
/// one: for the `sub` list, protections of the upper levels.
pub fn path_purge(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o path purge");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let Some(path) = binding.path.as_mut() else {
            return Ok(());
        };
        match setlist_type {
            Some(SetListType::White) => path.add = None,
            Some(SetListType::Black) => path.sub = None,
            _ => return Err("Unknown list type".into()),
        }
        Ok(())
    })?;
    Ok(true)
}

/// `chsr o workdir (whitelist|blacklist) purge`: the level no longer defines the list, see
/// [`path_purge`].
pub fn workdir_purge(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o workdir purge");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let Some(SWorkdirEither::Struct(workdir_set)) = binding.workdir.as_mut() else {
            // no list at this level: a bare path or nothing
            return Ok(());
        };
        match setlist_type {
            Some(SetListType::White) => workdir_set.add = None,
            Some(SetListType::Black) => workdir_set.sub = None,
            _ => return Err("Unknown list type".into()),
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn env_whitelist_set(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    setlist_type: Option<&SetListType>,
    options_env: &IndexSet<EnvKey>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o env whitelist set");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let env = binding.env.get_or_insert_default();
        match setlist_type {
            Some(SetListType::White) => {
                env.keep = Some(options_env.clone());
            }
            Some(SetListType::Black) => {
                env.delete = Some(options_env.clone());
            }
            Some(SetListType::Check) => {
                env.check = Some(options_env.clone());
            }
            None => {
                env.default_behavior = EnvBehavior::Delete;
                env.keep = Some(options_env.clone());
            }
            _ => return Err("Unknown list type".into()),
        }
        Ok(())
    })?;
    Ok(true)
}

/// `chsr o password set`: the fields given are changed, the others and the unknown fields of the
/// option are kept.
pub fn set_password(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    password_arg: [bool; 2],
    tries: Option<NonZeroU8>,
    delay: Option<SignedDuration>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o password set");
    if password_arg[PasswordOpt::Tries as usize] && tries.is_none() {
        return Err("--tries needs a number of tries".into());
    }
    if password_arg[PasswordOpt::Delay as usize] && delay.is_none() {
        return Err("--delay needs a duration".into());
    }
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut opt = opt.as_ref().borrow_mut();
        let password = opt.password.get_or_insert_with(SPassword::default);
        if let Some(tries) = tries {
            password.tries = Some(tries);
        }
        if let Some(delay) = delay {
            password.delay = Some(delay);
        }
        Ok(())
    })?;
    Ok(true)
}

/// `chsr o password unset`: the fields named are removed, then the option once nothing is left
/// in it.
pub fn unset_password(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    password_arg: [bool; 2],
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o password unset");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut opt = opt.as_ref().borrow_mut();
        if let Some(password) = opt.password.as_mut() {
            if password_arg[PasswordOpt::Tries as usize] {
                password.tries = None;
            }
            if password_arg[PasswordOpt::Delay as usize] {
                password.delay = None;
            }
            if password.tries.is_none()
                && password.delay.is_none()
                && password.extra_fields.is_empty()
            {
                opt.password = None;
            }
        }
        Ok(())
    })?;
    Ok(true)
}

/// `chsr o timeout unset`: the fields named are removed, then the option once nothing is left
/// in it.
pub fn unset_timeout(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    timeout_arg: [bool; 3],
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o timeout unset");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut opt = opt.as_ref().borrow_mut();
        if let Some(timeout) = opt.timeout.as_mut() {
            if timeout_arg[TimeoutOpt::Type as usize] {
                timeout.type_field = None;
            }
            if timeout_arg[TimeoutOpt::Duration as usize] {
                timeout.duration = None;
            }
            if timeout_arg[TimeoutOpt::MaxUsage as usize] {
                timeout.max_usage = None;
            }
            if timeout.type_field.is_none()
                && timeout.duration.is_none()
                && timeout.max_usage.is_none()
                && timeout.extra_fields.is_empty()
            {
                opt.timeout = None;
            }
        }
        Ok(())
    })?;
    Ok(true)
}

/// `chsr o timeout set`: the fields given are changed, the others and the unknown fields of the
/// option are kept.
pub fn set_timeout(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    timeout_arg: [bool; 3],
    timeout_type: Option<rootasrole_core::database::options::TimestampType>,
    timeout_duration: Option<SignedDuration>,
    timeout_max_usage: Option<u64>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o timeout set");
    if timeout_arg[TimeoutOpt::Type as usize] && timeout_type.is_none() {
        return Err("--type needs tty, ppid or uid".into());
    }
    if timeout_arg[TimeoutOpt::Duration as usize] && timeout_duration.is_none() {
        return Err("--duration needs a duration".into());
    }
    if timeout_arg[TimeoutOpt::MaxUsage as usize] && timeout_max_usage.is_none() {
        return Err("--max-usage needs a number".into());
    }
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut opt = opt.as_ref().borrow_mut();
        let timeout = opt.timeout.get_or_insert_with(STimeout::default);
        if let Some(timeout_type) = timeout_type {
            timeout.type_field = Some(timeout_type);
        }
        if let Some(duration) = timeout_duration {
            timeout.duration = Some(duration);
        }
        if let Some(max_usage) = timeout_max_usage {
            timeout.max_usage = Some(max_usage);
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn path_setlist2(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
    action: InputAction,
    options_path: &str,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o path set whitelist|blacklist add|del|set path1:path2:path3 22222222222");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        // removing from a list that the level does not define changes nothing
        if binding.path.is_none() && !matches!(action, InputAction::Add | InputAction::Set) {
            warn!("No path option at this level, nothing to remove");
            return Ok(());
        }
        let path = binding.path.get_or_insert_default();
        match setlist_type {
            Some(SetListType::White) => match action {
                InputAction::Add => {
                    path.add.get_or_insert_with(IndexSet::new).extend(
                        options_path
                            .split(':')
                            .map(std::string::ToString::to_string),
                    );
                }
                InputAction::Del => {
                    debug!("path.add del {:?}", path.add);
                    let hashset = options_path
                        .split(':')
                        .map(std::string::ToString::to_string)
                        .collect::<IndexSet<String>>();
                    if let Some(path) = &mut path.add {
                        *path = path
                            .difference(&hashset)
                            .cloned()
                            .collect::<IndexSet<String>>();
                    } else {
                        warn!("No path to remove from del list");
                    }
                }
                InputAction::Set => {
                    path.add = Some(
                        options_path
                            .split(':')
                            .map(std::string::ToString::to_string)
                            .collect(),
                    );
                }
                _ => return Err(format!("Unknown action {action:?}").into()),
            },
            Some(SetListType::Black) => match action {
                InputAction::Add => {
                    path.sub.get_or_insert_with(IndexSet::new).extend(
                        options_path
                            .split(':')
                            .map(std::string::ToString::to_string),
                    );
                }
                InputAction::Del => {
                    debug!("path.del del {:?}", path.sub);
                    let hashset = options_path
                        .split(':')
                        .map(std::string::ToString::to_string)
                        .collect::<IndexSet<String>>();
                    if let Some(path) = &mut path.sub {
                        *path = path
                            .difference(&hashset)
                            .cloned()
                            .collect::<IndexSet<String>>();
                    } else {
                        warn!("No path to remove from del list");
                    }
                }
                InputAction::Set => {
                    path.sub = Some(
                        options_path
                            .split(':')
                            .map(std::string::ToString::to_string)
                            .collect(),
                    );
                }
                _ => return Err(format!("Unknown action {action:?}").into()),
            },
            _ => return Err("Unknown list type".into()),
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn workdir_set_path(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_path: &str,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o workdir set path {options_path}");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().workdir = Some(SWorkdirEither::Path(options_path.to_string()));
        Ok(())
    })?;
    Ok(true)
}

pub fn workdir_setlist(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
    action: InputAction,
    options_path: &str,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o w set whitelist|blacklist add|del|set path1:path2:path3");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let workdir_current = binding.workdir.take();
        let mut workdir_set = match workdir_current {
            Some(SWorkdirEither::Struct(workdir_set)) => workdir_set,
            Some(SWorkdirEither::Path(path)) => SWorkdirSet {
                fallback: Some(path),
                ..Default::default()
            },
            None => SWorkdirSet::default(),
        };
        match setlist_type {
            Some(SetListType::White) => match action {
                InputAction::Add => {
                    workdir_set.add.get_or_insert_with(IndexSet::new).extend(
                        options_path
                            .split(':')
                            .map(std::string::ToString::to_string),
                    );
                }
                InputAction::Del => {
                    debug!("workdir.add del {:?}", workdir_set.add);
                    let hashset = options_path
                        .split(':')
                        .map(std::string::ToString::to_string)
                        .collect::<IndexSet<String>>();
                    if let Some(paths) = &mut workdir_set.add {
                        *paths = paths
                            .difference(&hashset)
                            .cloned()
                            .collect::<IndexSet<String>>();
                    } else {
                        warn!("No path to remove from del list");
                    }
                }
                InputAction::Set => {
                    workdir_set.add = Some(
                        options_path
                            .split(':')
                            .map(std::string::ToString::to_string)
                            .collect(),
                    );
                }
                _ => return Err(format!("Unknown action {action:?}").into()),
            },
            Some(SetListType::Black) => match action {
                InputAction::Add => {
                    workdir_set.sub.get_or_insert_with(IndexSet::new).extend(
                        options_path
                            .split(':')
                            .map(std::string::ToString::to_string),
                    );
                }
                InputAction::Del => {
                    debug!("workdir.del del {:?}", workdir_set.sub);
                    let hashset = options_path
                        .split(':')
                        .map(std::string::ToString::to_string)
                        .collect::<IndexSet<String>>();
                    if let Some(paths) = &mut workdir_set.sub {
                        *paths = paths
                            .difference(&hashset)
                            .cloned()
                            .collect::<IndexSet<String>>();
                    } else {
                        warn!("No path to remove from del list");
                    }
                }
                InputAction::Set => {
                    workdir_set.sub = Some(
                        options_path
                            .split(':')
                            .map(std::string::ToString::to_string)
                            .collect(),
                    );
                }
                _ => return Err(format!("Unknown action {action:?}").into()),
            },
            _ => return Err("Unknown list type".into()),
        }
        binding.workdir = Some(SWorkdirEither::Struct(workdir_set));
        Ok(())
    })?;
    Ok(true)
}

pub fn path_setpolicy(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_path_policy: PathBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o path setpolicy delete-all");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        if let Some(path) = &mut opt.as_ref().borrow_mut().path {
            path.default_behavior = options_path_policy;
        } else {
            opt.as_ref().borrow_mut().path = Some(SPathOptions {
                default_behavior: options_path_policy,
                ..Default::default()
            });
        }
        Ok(())
    })
    .map(|()| true)
}

pub fn workdir_setpolicy(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_workdir_policy: WorkdirBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o path setpolicy delete-all");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let workdir = opt.as_ref().borrow_mut().workdir.as_mut().map_or_else(
            || {
                SWorkdirEither::Struct(SWorkdirSet {
                    default_behavior: options_workdir_policy,
                    ..Default::default()
                })
            },
            |workdir| match workdir {
                SWorkdirEither::Path(p) => SWorkdirEither::Struct(SWorkdirSet {
                    default_behavior: options_workdir_policy,
                    fallback: Some(p.clone()),
                    ..Default::default()
                }),
                SWorkdirEither::Struct(sworkdir_set) => {
                    sworkdir_set.default_behavior = options_workdir_policy;
                    SWorkdirEither::Struct(sworkdir_set.clone())
                }
            },
        );
        opt.as_ref().borrow_mut().workdir = Some(workdir);
        Ok(())
    })
    .map(|()| true)
}

#[allow(clippy::too_many_lines)]
pub fn env_setlist_add(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
    action: InputAction,
    options_key_env: Option<IndexSet<EnvKey>>,
    options_env_values: Option<HashMap<String, String>>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o path {setlist_type:?} {action:?} path1 path2 path3");
    perform_on_target_opt(rconfig, role_id, task_id, move |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        // removing from a list that the level does not define changes nothing
        if binding.env.is_none() && !matches!(action, InputAction::Add | InputAction::Set) {
            warn!("No env option at this level, nothing to remove");
            return Ok(());
        }
        let env = binding.env.get_or_insert_default();

        match setlist_type {
            Some(SetListType::White) => match action {
                InputAction::Add => {
                    env.keep
                        .get_or_insert_with(IndexSet::new)
                        .extend(options_key_env.as_ref().ok_or("Empty list")?.clone());
                }
                InputAction::Del => {
                    if let Some(keep) = &mut env.keep {
                        *keep = keep
                            .difference(options_key_env.as_ref().ok_or("Empty list")?)
                            .cloned()
                            .collect::<IndexSet<EnvKey>>();
                    }
                }
                InputAction::Purge => {
                    env.keep = None;
                }
                InputAction::Set => {
                    env.keep
                        .replace(options_key_env.as_ref().ok_or("Empty list")?.clone());
                }
                _ => return Err(format!("Unknown action {action:?}").into()),
            },
            Some(SetListType::Black) => match action {
                InputAction::Add => {
                    env.delete
                        .get_or_insert_with(IndexSet::new)
                        .extend(options_key_env.as_ref().ok_or("Empty list")?.clone());
                }
                InputAction::Del => {
                    if let Some(delete) = &mut env.delete {
                        *delete = delete
                            .difference(options_key_env.as_ref().ok_or("Empty list")?)
                            .cloned()
                            .collect::<IndexSet<EnvKey>>();
                    }
                }
                InputAction::Purge => {
                    env.delete = None;
                }
                InputAction::Set => {
                    env.delete
                        .replace(options_key_env.as_ref().ok_or("Empty list")?.clone());
                }
                _ => return Err(format!("Unknown action {action:?}").into()),
            },
            Some(SetListType::Check) => match action {
                InputAction::Add => {
                    env.check
                        .get_or_insert_with(IndexSet::new)
                        .extend(options_key_env.as_ref().ok_or("Empty list")?.clone());
                }
                InputAction::Del => {
                    if let Some(check) = &mut env.check {
                        *check = check
                            .difference(options_key_env.as_ref().ok_or("Empty list")?)
                            .cloned()
                            .collect::<IndexSet<EnvKey>>();
                    }
                }
                InputAction::Set => {
                    env.check = Some(options_key_env.as_ref().ok_or("Empty list")?.clone());
                }
                InputAction::Purge => {
                    env.check = None;
                }
                _ => return Err(format!("Unknown action {action:?}").into()),
            },
            Some(SetListType::Set) => match action {
                InputAction::Add => {
                    debug!("options_env_values: {options_env_values:?}");
                    env.set
                        .get_or_insert_default()
                        .extend(options_env_values.as_ref().ok_or("Empty list")?.clone());
                }
                InputAction::Del => {
                    debug!("options_env_values: {options_env_values:?}");
                    options_key_env
                        .as_ref()
                        .ok_or("Empty list")?
                        .into_iter()
                        .for_each(|k| {
                            if let Some(env) = &mut env.set {
                                env.remove(&k.to_string());
                            }
                        });
                }
                InputAction::Purge => {
                    debug!("options_env_values: {options_env_values:?}");
                    env.set = None;
                }
                InputAction::Set => {
                    debug!("options_env_values: {options_env_values:?}");
                    env.set
                        .replace(options_env_values.as_ref().ok_or("Empty list")?.clone());
                }
                _ => return Err(format!("Unknown action {action:?}").into()),
            },
            None => match action {
                InputAction::Set => {
                    env.keep
                        .replace(options_key_env.as_ref().ok_or("Empty list")?.clone());
                }
                _ => return Err(format!("Unknown action {action:?}").into()),
            },
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn env_setpolicy(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    options_env_policy: EnvBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o env setpolicy delete-all {options_env_policy:?}");
    perform_on_target_opt(rconfig, role_id, task_id, move |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let env = binding.env.get_or_insert_default();
        env.default_behavior = options_env_policy;
        Ok(())
    })?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use rootasrole_core::database::options::{Level, Opt, OptType, SBounding, STimeout};

    use super::options_to_show;

    #[test]
    fn test_options_to_show_only_the_option_asked_for() {
        let opt = Opt::builder(Level::Role)
            .bounding(SBounding::Strict)
            .timeout(STimeout::default())
            .build();
        assert_eq!(
            options_to_show(&opt, Some(OptType::Bounding)).unwrap(),
            "\"strict\""
        );
        assert_eq!(options_to_show(&opt, Some(OptType::Root)).unwrap(), "null");
        let all: serde_json::Value =
            serde_json::from_str(&options_to_show(&opt, None).unwrap()).unwrap();
        assert_eq!(all["bounding"], "strict");
        assert!(all.get("timeout").is_some());
    }
}
