use std::{cell::RefCell, collections::HashMap, error::Error, ops::Deref, rc::Rc};

use linked_hash_set::LinkedHashSet;
use log::{debug, warn};

use crate::cli::data::{InputAction, RoleType, SetListType, TaskType, TimeoutOpt};

use rar_common::database::{
    options::{
        EnvBehavior, EnvKey, Opt, OptStack, OptType, PathBehavior, SEnvOptions, SPathOptions,
        STimeout, SUMask,
    },
    structs::{
        IdTask, RoleGetter, SCapabilities, SCommand, SGroupsEither, SRole, STask, SUserEither,
    },
};

use super::perform_on_target_opt;

pub fn list_json(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    options: bool,
    options_type: Option<OptType>,
    task_type: Option<TaskType>,
    role_type: Option<RoleType>,
) -> Result<(), Box<dyn Error>> {
    let config = rconfig.as_ref().borrow();
    if let Some(role_id) = role_id {
        if let Some(role) = rconfig.role(&role_id) {
            list_task(task_id, &role, options, options_type, task_type, role_type)
        } else {
            Err("Role not found".into())
        }
    } else {
        println!("{}", serde_json::to_string_pretty(config.deref()).unwrap());
        Ok(())
    }
}

fn list_task(
    task_id: Option<IdTask>,
    role: &Rc<RefCell<rar_common::database::structs::SRole>>,
    options: bool,
    options_type: Option<OptType>,
    task_type: Option<TaskType>,
    role_type: Option<RoleType>,
) -> Result<(), Box<dyn Error>> {
    if let Some(task_id) = task_id {
        if let Some(task) = role.as_ref().borrow().task(&task_id) {
            if options {
                debug!("task {:?}", task);
                let rcopt = OptStack::from_task(task.clone()).to_opt();
                let opt = rcopt.as_ref().borrow();
                if let Some(opttype) = options_type {
                    match opttype {
                        OptType::Env => {
                            println!("{}", serde_json::to_string_pretty(&opt.env).unwrap());
                        }
                        OptType::Path => {
                            println!("{}", serde_json::to_string_pretty(&opt.path).unwrap());
                        }
                        OptType::Root => {
                            println!("{}", serde_json::to_string_pretty(&opt.root).unwrap());
                        }
                        OptType::Bounding => {
                            println!("{}", serde_json::to_string_pretty(&opt.bounding).unwrap());
                        }
                        OptType::Timeout => {
                            println!("{}", serde_json::to_string_pretty(&opt.timeout).unwrap());
                        }
                        OptType::Authentication => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&opt.authentication).unwrap()
                            );
                        }
                        OptType::ExecInfo => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&opt.execinfo).unwrap()
                            );
                        }
                        OptType::UMask => {
                            println!("{}", serde_json::to_string_pretty(&opt.umask).unwrap());
                        }
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(&rcopt)?);
                }
            } else {
                print_task(task, task_type.unwrap_or(TaskType::All));
            }
        } else {
            return Err("Task not found".into());
        }
    } else if options {
        println!(
            "{}",
            serde_json::to_string_pretty(&OptStack::from_role(role.clone()).to_opt())?
        );
    } else {
        print_role(role, &role_type.unwrap_or(RoleType::All));
    }
    Ok(())
}

fn print_task(
    task: &std::rc::Rc<std::cell::RefCell<rar_common::database::structs::STask>>,
    task_type: TaskType,
) {
    match task_type {
        TaskType::All => {
            println!("{}", serde_json::to_string_pretty(&task).unwrap());
        }
        TaskType::Commands => {
            println!(
                "{}",
                serde_json::to_string_pretty(&task.as_ref().borrow().commands).unwrap()
            );
        }
        TaskType::Credentials => {
            println!(
                "{}",
                serde_json::to_string_pretty(&task.as_ref().borrow().cred).unwrap()
            );
        }
    }
}

fn print_role(
    role: &std::rc::Rc<std::cell::RefCell<rar_common::database::structs::SRole>>,
    role_type: &RoleType,
) {
    match role_type {
        RoleType::All => {
            println!("{}", serde_json::to_string_pretty(&role).unwrap());
        }
        RoleType::Actors => {
            println!(
                "{}",
                serde_json::to_string_pretty(&role.as_ref().borrow().actors).unwrap()
            );
        }
        RoleType::Tasks => {
            println!(
                "{}",
                serde_json::to_string_pretty(&role.as_ref().borrow().tasks).unwrap()
            );
        }
    }
}

pub fn role_add_del(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    action: InputAction,
    role_id: String,
    role_type: Option<RoleType>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 {:?}", action);
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
            let role = rconfig.role(&role_id).unwrap();
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
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: String,
    action: InputAction,
    task_id: IdTask,
    task_type: Option<TaskType>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 add|del");
    let role = rconfig.role(&role_id).ok_or("Role not found")?;
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
            let task = borrow.task(&task_id).expect("Task do not exists");
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
        _ => unreachable!("Invalid action"),
    }
}

pub fn grant_revoke(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: String,
    action: InputAction,
    mut actors: Vec<rar_common::database::actor::SActor>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 grant|revoke");
    let role = rconfig.role(&role_id).ok_or("Role not found")?;
    match action {
        InputAction::Add => {
            //verify if actor is already in role
            //remove already existing actors
            actors.retain(|a| {
                if role.as_ref().borrow().actors.contains(a) {
                    println!("Actor {} already in role", a);
                    false
                } else {
                    true
                }
            });
            role.as_ref().borrow_mut().actors.extend(actors);
            Ok(true)
        }
        InputAction::Del => {
            //if actor is not in role, warns
            if !role.as_ref().borrow().actors.contains(&actors[0]) {
                println!("Actor {} not in role", actors[0]);
            }
            role.as_ref()
                .borrow_mut()
                .actors
                .retain(|a| !actors.contains(a));
            Ok(true)
        }
        _ => unreachable!("Invalid action"),
    }
}

pub fn cred_set(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: String,
    task_id: IdTask,
    cred_caps: Option<capctl::CapSet>,
    cred_setuid: Option<rar_common::database::actor::SUserType>,
    cred_setgid: Option<rar_common::database::actor::SGroups>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 cred");
    match rconfig.task(&role_id, task_id) {
        Ok(task) => {
            if let Some(caps) = cred_caps {
                task.as_ref().borrow_mut().cred.capabilities = Some(SCapabilities::from(caps));
            }
            if let Some(setuid) = cred_setuid {
                task.as_ref().borrow_mut().cred.setuid = Some(SUserEither::MandatoryUser(setuid));
            }
            if let Some(setgid) = cred_setgid {
                task.as_ref().borrow_mut().cred.setgid =
                    Some(SGroupsEither::MandatoryGroups(setgid.clone()));
            }
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

pub fn cred_unset(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: String,
    task_id: IdTask,
    cred_caps: Option<capctl::CapSet>,
    cred_setuid: Option<rar_common::database::actor::SUserType>,
    cred_setgid: Option<rar_common::database::actor::SGroups>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 cred unset");
    match rconfig.task(&role_id, task_id) {
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
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

pub fn cred_caps(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: String,
    task_id: IdTask,
    setlist_type: SetListType,
    action: InputAction,
    cred_caps: capctl::CapSet,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 cred caps");
    let task = rconfig.task(&role_id, task_id)?;
    match setlist_type {
        SetListType::White => match action {
            InputAction::Add => {
                if task.as_ref().borrow().cred.capabilities.is_none() {
                    task.as_ref()
                        .borrow_mut()
                        .cred
                        .capabilities
                        .replace(SCapabilities::default());
                }
                let mut borrow = task.as_ref().borrow_mut();
                let caps = borrow.cred.capabilities.as_mut().unwrap();

                caps.add = caps.add.union(cred_caps);
                debug!("caps.add: {:?}, cred_caps : {:?}", caps.add, cred_caps);
            }
            InputAction::Del => {
                task.as_ref()
                    .borrow_mut()
                    .cred
                    .capabilities
                    .as_mut()
                    .unwrap()
                    .add
                    .drop_all(cred_caps);
            }
            InputAction::Set => {
                task.as_ref()
                    .borrow_mut()
                    .cred
                    .capabilities
                    .as_mut()
                    .unwrap()
                    .add = cred_caps;
            }
            _ => unreachable!("Unknown action {:?}", action),
        },
        SetListType::Black => match action {
            InputAction::Add => {
                let caps = &mut task.as_ref().borrow_mut().cred.capabilities;

                caps.as_mut().unwrap().sub = caps.as_ref().unwrap().sub.union(cred_caps)
            }
            InputAction::Del => {
                task.as_ref()
                    .borrow_mut()
                    .cred
                    .capabilities
                    .as_mut()
                    .unwrap()
                    .sub
                    .drop_all(cred_caps);
            }
            InputAction::Set => {
                task.as_ref()
                    .borrow_mut()
                    .cred
                    .capabilities
                    .as_mut()
                    .unwrap()
                    .sub = cred_caps;
            }
            _ => unreachable!("Unknown action {:?}", action),
        },
        _ => unreachable!("Unknown setlist type"),
    }
    Ok(true)
}

pub fn cred_setpolicy(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: String,
    task_id: IdTask,
    cred_policy: rar_common::database::structs::SetBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 cred setpolicy");
    let task = rconfig.task(&role_id, task_id)?;
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
        .as_mut()
        .unwrap()
        .default_behavior = cred_policy;
    Ok(true)
}

pub fn cmd_whitelist_action(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: String,
    task_id: IdTask,
    cmd_id: Vec<String>,
    setlist_type: SetListType,
    action: InputAction,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 command whitelist add c1");
    let task = rconfig.task(&role_id, task_id)?;
    let cmd = SCommand::Simple(shell_words::join(cmd_id.iter()));
    match setlist_type {
        SetListType::White => match action {
            InputAction::Add => {
                //verify if command exists
                if task.as_ref().borrow().commands.add.contains(&cmd) {
                    return Err("Command already exists".into());
                }
                task.as_ref().borrow_mut().commands.add.push(cmd);
            }
            InputAction::Del => {
                //if command is not in task, warns
                if !task.as_ref().borrow().commands.add.contains(&cmd) {
                    println!("Command {:?} not in task", cmd);
                }
                task.as_ref().borrow_mut().commands.add.retain(|c| {
                    debug!("'{:?}' != '{:?}' : {}", c, &cmd, *c != cmd);
                    *c != cmd
                });
            }
            _ => unreachable!("Unknown action {:?}", action),
        },
        SetListType::Black => match action {
            InputAction::Add => {
                //verify if command exists
                if task.as_ref().borrow().commands.sub.contains(&cmd) {
                    return Err("Command already exists".into());
                }
                task.as_ref().borrow_mut().commands.sub.push(cmd);
            }
            InputAction::Del => {
                //if command is not in task, warns
                if !task.as_ref().borrow().commands.sub.contains(&cmd) {
                    println!("Command {:?} not in task", cmd);
                }
                task.as_ref()
                    .borrow_mut()
                    .commands
                    .sub
                    .retain(|c| c != &cmd);
            }
            _ => unreachable!("Unknown action {:?}", action),
        },
        _ => unreachable!("Unknown setlist type"),
    }
    Ok(true)
}

pub fn cmd_setpolicy(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: String,
    task_id: IdTask,
    cmd_policy: rar_common::database::structs::SetBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr role r1 task t1 command setpolicy");
    let task = rconfig.task(&role_id, task_id)?;
    task.as_ref()
        .borrow_mut()
        .commands
        .default
        .replace(cmd_policy);
    Ok(true)
}

pub fn env_set_policylist(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    options_env: LinkedHashSet<EnvKey>,
    options_env_policy: EnvBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o env set keep-only|delete-only {:?}", options_env);
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().env = Some(SEnvOptions {
            default_behavior: options_env_policy,
            keep: if options_env_policy.is_delete() {
                Some(options_env.clone())
            } else {
                None
            },
            delete: if options_env_policy.is_keep() {
                Some(options_env.clone())
            } else {
                None
            },
            ..Default::default()
        });
        Ok(())
    })?;
    Ok(true)
}

pub fn set_privileged(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    options_root: Option<rar_common::database::options::SPrivileged>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o root set privileged");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().root = options_root;
        Ok(())
    })?;
    Ok(true)
}

pub fn set_bounding(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    options_bounding: Option<rar_common::database::options::SBounding>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o bounding set");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().bounding = options_bounding;
        Ok(())
    })?;
    Ok(true)
}

pub fn set_authentication(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    options_auth: Option<rar_common::database::options::SAuthentication>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o auth set");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().authentication = options_auth;
        Ok(())
    })?;
    Ok(true)
}

pub fn set_execinfo(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    options_execinfo: Option<rar_common::database::options::SInfo>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o execinfo set");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().execinfo = options_execinfo;
        Ok(())
    })?;
    Ok(true)
}

pub fn set_umask(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    options_umask: Option<SUMask>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o umask set");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        opt.as_ref().borrow_mut().umask = options_umask;
        Ok(())
    })?;
    Ok(true)
}

pub fn path_set(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
    options_path: String,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o path set");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let path = binding.path.get_or_insert(SPathOptions::default());
        match setlist_type {
            Some(SetListType::White) => {
                path.add = Some(options_path.split(':').map(|s| s.to_string()).collect());
            }
            Some(SetListType::Black) => {
                path.sub = Some(options_path.split(':').map(|s| s.to_string()).collect());
            }
            None => {
                path.default_behavior = PathBehavior::Delete;
                path.add = Some(options_path.split(':').map(|s| s.to_string()).collect());
            }
            _ => unreachable!("Unknown setlist type"),
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn path_purge(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o path purge");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let path = binding.path.get_or_insert(SPathOptions::default());
        match setlist_type {
            Some(SetListType::White) => {
                if let Some(add) = &mut path.add {
                    add.clear();
                }
            }
            Some(SetListType::Black) => {
                if let Some(sub) = &mut path.sub {
                    sub.clear();
                }
            }
            _ => unreachable!("Unknown setlist type"),
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn env_whitelist_set(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
    options_env: LinkedHashSet<EnvKey>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o env whitelist set");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut binding = opt.as_ref().borrow_mut();
        let env = binding.env.get_or_insert(SEnvOptions::default());
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
            _ => unreachable!("Unknown setlist type"),
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn unset_timeout(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    timeout_arg: [bool; 3],
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o timeout unset");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut timeout = STimeout::default();
        if timeout_arg[TimeoutOpt::Type as usize] {
            timeout.type_field = None;
        }
        if timeout_arg[TimeoutOpt::Duration as usize] {
            timeout.duration = None;
        }
        if timeout_arg[TimeoutOpt::MaxUsage as usize] {
            timeout.max_usage = None;
        }
        if timeout_arg.iter().all(|b| *b) {
            opt.as_ref().borrow_mut().timeout = None;
        } else {
            opt.as_ref().borrow_mut().timeout = Some(timeout);
        }

        Ok(())
    })?;
    Ok(true)
}

pub fn set_timeout(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    timeout_type: Option<rar_common::database::options::TimestampType>,
    timeout_duration: Option<chrono::TimeDelta>,
    timeout_max_usage: Option<u64>,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o timeout set");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut timeout = STimeout::default();
        if let Some(timeout_type) = timeout_type {
            timeout.type_field = Some(timeout_type);
        }
        if let Some(duration) = timeout_duration {
            timeout.duration = Some(duration);
        }
        if let Some(max_usage) = timeout_max_usage {
            timeout.max_usage = Some(max_usage);
        }
        opt.as_ref().borrow_mut().timeout = Some(timeout);
        Ok(())
    })?;
    Ok(true)
}

pub fn path_setlist2(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
    action: InputAction,
    options_path: String,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o path set whitelist|blacklist add|del|set path1:path2:path3 22222222222");
    perform_on_target_opt(rconfig, role_id, task_id, |opt: Rc<RefCell<Opt>>| {
        let mut default_path = SPathOptions::default();
        let mut binding = opt.as_ref().borrow_mut();
        let path = binding.path.as_mut().unwrap_or(&mut default_path);
        match setlist_type {
            Some(SetListType::White) => match action {
                InputAction::Add => {
                    path.add
                        .get_or_insert(LinkedHashSet::new())
                        .extend(options_path.split(':').map(|s| s.to_string()));
                }
                InputAction::Del => {
                    debug!("path.add del {:?}", path.add);
                    let hashset = options_path
                        .split(':')
                        .map(|s| s.to_string())
                        .collect::<LinkedHashSet<String>>();
                    if let Some(path) = &mut path.add {
                        *path = path
                            .difference(&hashset)
                            .cloned()
                            .collect::<LinkedHashSet<String>>();
                    } else {
                        warn!("No path to remove from del list");
                    }
                }
                InputAction::Set => {
                    path.add = Some(options_path.split(':').map(|s| s.to_string()).collect());
                }
                _ => unreachable!("Unknown action {:?}", action),
            },
            Some(SetListType::Black) => match action {
                InputAction::Add => {
                    path.sub
                        .get_or_insert(LinkedHashSet::new())
                        .extend(options_path.split(':').map(|s| s.to_string()));
                }
                InputAction::Del => {
                    debug!("path.del del {:?}", path.sub);
                    let hashset = options_path
                        .split(':')
                        .map(|s| s.to_string())
                        .collect::<LinkedHashSet<String>>();
                    if let Some(path) = &mut path.sub {
                        *path = path
                            .difference(&hashset)
                            .cloned()
                            .collect::<LinkedHashSet<String>>();
                    } else {
                        warn!("No path to remove from del list");
                    }
                }
                InputAction::Set => {
                    path.sub = Some(options_path.split(':').map(|s| s.to_string()).collect());
                }
                _ => unreachable!("Unknown action {:?}", action),
            },
            _ => unreachable!("Unknown setlist type"),
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn path_setpolicy(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
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
    .map(|_| true)
}

pub fn env_setlist_add(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    setlist_type: Option<SetListType>,
    action: InputAction,
    options_key_env: Option<LinkedHashSet<EnvKey>>,
    options_env_values: Option<HashMap<String, String>>,
) -> Result<bool, Box<dyn Error>> {
    debug!(
        "chsr o path {:?} {:?} path1 path2 path3",
        setlist_type, action
    );
    perform_on_target_opt(rconfig, role_id, task_id, move |opt: Rc<RefCell<Opt>>| {
        let mut default_env = SEnvOptions::default();
        let mut binding = opt.as_ref().borrow_mut();
        let env = binding.env.as_mut().unwrap_or(&mut default_env);

        match setlist_type {
            Some(SetListType::White) => match action {
                InputAction::Add => {
                    if options_key_env.is_none() {
                        return Err("Empty list".into());
                    }
                    env.keep
                        .get_or_insert(LinkedHashSet::new())
                        .extend(options_key_env.as_ref().unwrap().clone());
                }
                InputAction::Del => {
                    if options_key_env.is_none() {
                        return Err("Empty list".into());
                    }
                    if let Some(keep) = &mut env.keep {
                        *keep = keep
                            .difference(options_key_env.as_ref().unwrap())
                            .cloned()
                            .collect::<LinkedHashSet<EnvKey>>();
                    }
                }
                InputAction::Purge => {
                    env.keep = None;
                }
                InputAction::Set => {
                    env.keep = Some(options_key_env.as_ref().unwrap().clone());
                }
                _ => unreachable!("Unknown action {:?}", action),
            },
            Some(SetListType::Black) => match action {
                InputAction::Add => {
                    if options_key_env.is_none() {
                        return Err("Empty list".into());
                    }
                    env.delete
                        .get_or_insert(LinkedHashSet::new())
                        .extend(options_key_env.as_ref().unwrap().clone());
                }
                InputAction::Del => {
                    if options_key_env.is_none() {
                        return Err("Empty list".into());
                    }
                    if let Some(delete) = &mut env.delete {
                        *delete = delete
                            .difference(options_key_env.as_ref().unwrap())
                            .cloned()
                            .collect::<LinkedHashSet<EnvKey>>();
                    }
                }
                InputAction::Purge => {
                    env.delete = None;
                }
                InputAction::Set => {
                    env.delete = Some(options_key_env.as_ref().unwrap().clone());
                }
                _ => unreachable!("Unknown action {:?}", action),
            },
            Some(SetListType::Check) => match action {
                InputAction::Add => {
                    if options_key_env.is_none() {
                        return Err("Empty list".into());
                    }
                    env.check
                        .get_or_insert(LinkedHashSet::new())
                        .extend(options_key_env.as_ref().unwrap().clone());
                }
                InputAction::Del => {
                    if options_key_env.is_none() {
                        return Err("Empty list".into());
                    }
                    if let Some(check) = &mut env.check {
                        *check = check
                            .difference(options_key_env.as_ref().unwrap())
                            .cloned()
                            .collect::<LinkedHashSet<EnvKey>>();
                    }
                }
                InputAction::Set => {
                    env.check = Some(options_key_env.as_ref().unwrap().clone());
                }
                InputAction::Purge => {
                    env.check = None;
                }
                _ => unreachable!("Unknown action {:?}", action),
            },
            Some(SetListType::Set) => match action {
                InputAction::Add => {
                    debug!("options_env_values: {:?}", options_env_values);
                    env.set
                        .get_or_insert_default()
                        .extend(options_env_values.as_ref().unwrap().clone());
                }
                InputAction::Del => {
                    debug!("options_env_values: {:?}", options_env_values);
                    options_key_env.as_ref().unwrap().into_iter().for_each(|k| {
                        if let Some(env) = &mut env.set {
                            env.remove(&k.to_string());
                        }
                    });
                }
                InputAction::Purge => {
                    debug!("options_env_values: {:?}", options_env_values);
                    env.set = None;
                }
                InputAction::Set => {
                    debug!("options_env_values: {:?}", options_env_values);
                    env.set
                        .replace(options_env_values.as_ref().unwrap().clone());
                }
                _ => unreachable!("Unknown action {:?}", action),
            },
            None => match action {
                InputAction::Set => {
                    env.keep = Some(options_key_env.as_ref().unwrap().clone());
                }
                _ => unreachable!("Unknown action {:?}", action),
            },
        }
        Ok(())
    })?;
    Ok(true)
}

pub fn env_setpolicy(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    options_env_policy: EnvBehavior,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr o env setpolicy delete-all");
    perform_on_target_opt(rconfig, role_id, task_id, move |opt: Rc<RefCell<Opt>>| {
        let mut default_env = SEnvOptions::default();
        let mut binding = opt.as_ref().borrow_mut();
        let env = binding.env.as_mut().unwrap_or(&mut default_env);
        env.default_behavior = options_env_policy;
        Ok(())
    })?;
    Ok(true)
}
