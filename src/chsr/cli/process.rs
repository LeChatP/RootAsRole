mod convert;
mod json;
mod upgrade;

use std::{cell::RefCell, error::Error, ffi::OsStr, path::Path, rc::Rc};

use json::{
    cmd_setpolicy, cmd_whitelist_action, cred_caps, cred_set, cred_setpolicy, cred_unset,
    edit_role_links, edit_task_purpose, env_set_policylist, env_setlist_add, env_setpolicy,
    env_whitelist_set, grant_revoke, path_purge, path_set, path_setlist2, path_setpolicy,
    role_add_del, set_authentication, set_bounding, set_env_override, set_execinfo, set_password,
    set_privileged, set_timeout, set_umask, task_add_del, unset_password, unset_timeout,
};

use log::debug;

use rootasrole_core::{
    database::{
        options::{Level, Opt, OptType},
        structs::{IdTask, RoleGetter, SPolicy},
    },
    file::FileSettings,
    println_ignore_io_error,
    util::DEFAULT_POLICY_FILE,
};

use crate::cli::process::json::{
    workdir_purge, workdir_set_path, workdir_setlist, workdir_setpolicy,
};

use super::{
    data::{InputAction, Inputs},
    usage,
};

#[allow(clippy::too_many_lines)]
pub fn process_input(storage: &mut FileSettings, inputs: Inputs) -> Result<bool, Box<dyn Error>> {
    if inputs.action == InputAction::Convert {
        debug!("chsr convert");
        return convert::convert(
            storage,
            inputs.convertion.ok_or("convert needs a destination")?,
            inputs.convert_reconfigure,
        );
    }
    if inputs.action == InputAction::Upgrade {
        debug!("chsr upgrade");
        return upgrade::upgrade(storage, inputs.upgrade_check);
    }
    if inputs.action == InputAction::List && inputs.policy && inputs.policy_path.is_none() {
        // chsr file list: the files of the policy, the root file last
        for file in storage.get_files() {
            println_ignore_io_error!("{file}");
        }
        return Ok(false);
    }
    if inputs.action == InputAction::List
        && inputs.policy_path.is_none()
        && inputs.role_id.is_none()
        && !inputs.options
        && storage.policy_files().next().is_some()
    {
        // chsr list: every policy file, by path
        let mut files = serde_json::Map::new();
        for (path, policy) in storage.policy_files() {
            files.insert(
                path.display().to_string(),
                serde_json::to_value(&*policy.as_ref().borrow())?,
            );
        }
        println_ignore_io_error!("{}", serde_json::to_string_pretty(&files)?);
        return Ok(false);
    }
    let rconfig = &target_policy(storage, inputs.policy_path.as_deref())?;
    match inputs {
        Inputs {
            action: InputAction::Help,
            ..
        } => {
            usage::help();
            Ok(false)
        }
        Inputs {
            action: InputAction::List,
            options, // show options ?
            role_id,
            role_type,
            task_id,
            task_type,    // what to show
            options_type, // in json
            ..
        } => {
            debug!("chsr list");
            match json::list_json(
                rconfig,
                role_id.as_ref(),
                task_id,
                options,
                options_type,
                task_type,
                role_type,
            ) {
                Ok(()) => {
                    debug!("chsr list ok");
                    Ok(false)
                }
                Err(e) => {
                    debug!("chsr list err {e:?}");
                    Err(e)
                }
            }
        }
        // before the role and task deletions below, which use the same keywords
        Inputs {
            // chsr role r1 ssd|parents add|del|set r2,r3, chsr role r1 ssd|parents purge
            action,
            role_id: Some(role_id),
            role_link: Some(link),
            role_links,
            ..
        } => edit_role_links(
            rconfig,
            &role_id,
            link,
            action,
            role_links.unwrap_or_default(),
        ),
        Inputs {
            // chsr role r1 task t1 purpose set <text>, chsr role r1 task t1 purpose unset
            action,
            role_id: Some(role_id),
            task_id: Some(task_id),
            purpose: true,
            task_purpose,
            ..
        } => edit_task_purpose(rconfig, &role_id, task_id, action, task_purpose),
        Inputs {
            // chsr o env override allow|deny|unset
            role_id,
            task_id,
            options_env_override: Some(value),
            ..
        } => set_env_override(rconfig, role_id.as_ref(), task_id, value),

        Inputs {
            // chsr role r1 add|del
            action,
            role_id: Some(role_id),
            task_id: None,
            setlist_type: None,
            options: false,
            actors: None,
            role_type,
            ..
        } => role_add_del(rconfig, action, role_id, role_type),

        Inputs {
            // chsr role r1 grant|revoke -u u1 -u u2 -g g1,g2
            action,
            role_id: Some(role_id),
            actors: Some(actors),
            options: false,
            ..
        } => grant_revoke(rconfig, &role_id, action, actors),

        Inputs {
            // chsr role r1 task t1 add|del
            action,
            role_id: Some(role_id),
            task_id: Some(task_id),
            setlist_type: None,
            options: false,
            cmd_id: None,
            cred_caps: None,
            cred_setuid: None,
            cred_setgid: None,
            task_type,
            cmd_policy: None,
            cred_policy: None,
            ..
        } => task_add_del(rconfig, &role_id, action, task_id, task_type),

        Inputs {
            //chsr role r1 task t1 cred set --caps "cap_net_raw,cap_sys_admin"
            action: InputAction::Set,
            role_id: Some(role_id),
            task_id: Some(task_id),
            cred_caps,
            cred_setuid,
            cred_setgid,
            cmd_id: None,
            cmd_policy: None,
            cred_policy: None,
            options: false,
            ..
        } => cred_set(
            rconfig,
            &role_id,
            task_id,
            cred_caps,
            cred_setuid,
            cred_setgid,
        ),

        Inputs {
            //chsr role r1 task t1 cred unset --caps "cap_net_raw,cap_sys_admin"
            action: InputAction::Del,
            role_id: Some(role_id),
            task_id: Some(task_id),
            cred_caps,
            cred_setuid,
            cred_setgid,
            cmd_id: None,
            cmd_policy: None,
            options: false,
            setlist_type: None,
            ..
        } => cred_unset(
            rconfig,
            &role_id,
            task_id,
            cred_caps,
            cred_setuid.as_ref(),
            cred_setgid.as_ref(),
        ),

        Inputs {
            action,
            role_id: Some(role_id),
            task_id: Some(task_id),
            setlist_type: Some(setlist_type),
            cred_caps: Some(pcred_caps),
            cmd_policy: None,
            options: false,
            ..
        } => cred_caps(rconfig, &role_id, task_id, setlist_type, action, pcred_caps),
        Inputs {
            role_id: Some(role_id),
            task_id: Some(task_id),
            cred_policy: Some(cred_policy),
            options: false,
            ..
        } => cred_setpolicy(rconfig, &role_id, task_id, cred_policy),

        Inputs {
            // chsr role r1 task t1 command whitelist add c1
            action,
            role_id: Some(role_id),
            task_id: Some(task_id),
            cmd_id: Some(cmd_id),
            setlist_type: Some(setlist_type),
            cmd_checks,
            ..
        } => cmd_whitelist_action(
            rconfig,
            &role_id,
            task_id,
            cmd_id,
            setlist_type,
            action,
            &cmd_checks,
        ),
        Inputs {
            role_id: Some(role_id),
            task_id: Some(task_id),
            cmd_policy: Some(cmd_policy),
            ..
        } => cmd_setpolicy(rconfig, &role_id, task_id, cmd_policy),

        // Set options
        Inputs {
            // chsr o env set A,B,C
            action: InputAction::Set,
            role_id,
            task_id,
            options_type: Some(OptType::Env),
            options_env_policy: Some(options_env_policy),
            options_key_env: Some(options_env),
            ..
        } => env_set_policylist(
            rconfig,
            role_id.as_ref(),
            task_id,
            &options_env,
            options_env_policy,
        ),
        Inputs {
            // chsr o root set privileged
            action: InputAction::Set,
            role_id,
            task_id,
            options_root: Some(options_root),
            ..
        } => set_privileged(rconfig, role_id.as_ref(), task_id, Some(options_root)),

        Inputs {
            // chsr o root del
            action: InputAction::Del,
            role_id,
            task_id,
            options_root: Some(_),
            ..
        } => set_privileged(rconfig, role_id.as_ref(), task_id, None),

        Inputs {
            // chsr o bounding set strict
            action: InputAction::Set,
            role_id,
            task_id,
            options_bounding: Some(options_bounding),
            ..
        } => set_bounding(rconfig, role_id.as_ref(), task_id, Some(options_bounding)),

        Inputs {
            // chsr o bounding del
            action: InputAction::Del,
            role_id,
            task_id,
            options_bounding: Some(_),
            ..
        } => set_bounding(rconfig, role_id.as_ref(), task_id, None),

        Inputs {
            // chsr o authentication perform
            action: InputAction::Set,
            role_id,
            task_id,
            options_auth: Some(options_auth),
            ..
        } => set_authentication(rconfig, role_id.as_ref(), task_id, Some(options_auth)),

        Inputs {
            // chsr o authentication del
            action: InputAction::Del,
            role_id,
            task_id,
            options_auth: Some(_),
            ..
        } => set_authentication(rconfig, role_id.as_ref(), task_id, None),

        Inputs {
            // chsr o execinfo hide|show
            action: InputAction::Set,
            role_id,
            task_id,
            options_execinfo: Some(options_execinfo),
            ..
        } => set_execinfo(rconfig, role_id.as_ref(), task_id, Some(options_execinfo)),

        Inputs {
            // chsr o execinfo del
            action: InputAction::Del,
            role_id,
            task_id,
            options_execinfo: Some(_),
            ..
        } => set_execinfo(rconfig, role_id.as_ref(), task_id, None),

        Inputs {
            action: InputAction::Set,
            role_id,
            task_id,
            options_umask: Some(options_umask),
            ..
        } => set_umask(rconfig, role_id.as_ref(), task_id, Some(options_umask)),

        Inputs {
            action: InputAction::Del,
            role_id,
            task_id,
            options_umask: Some(_),
            ..
        } => set_umask(rconfig, role_id.as_ref(), task_id, None),

        Inputs {
            // chsr o path whitelist set a:b:c
            action: InputAction::Set,
            role_id,
            task_id,
            options_path: Some(options_path),
            options_type: Some(OptType::Path),
            setlist_type,
            ..
        } => path_set(
            rconfig,
            role_id.as_ref(),
            task_id,
            setlist_type,
            &options_path,
        ),
        Inputs {
            // chsr o path whitelist set a:b:c
            action: InputAction::Purge,
            role_id,
            task_id,
            options_path: None,
            options_type: Some(OptType::Path),
            setlist_type,
            ..
        } => path_purge(rconfig, role_id.as_ref(), task_id, setlist_type),

        Inputs {
            // chsr o path whitelist set a:b:c
            action: InputAction::Purge,
            role_id,
            task_id,
            options_path: None,
            options_type: Some(OptType::Workdir),
            setlist_type,
            ..
        } => workdir_purge(rconfig, role_id.as_ref(), task_id, setlist_type),

        Inputs {
            // chsr o env whitelist set A,B,C
            action: InputAction::Set,
            role_id,
            task_id,
            options_key_env: Some(options_env),
            options_type: Some(OptType::Env),
            setlist_type,
            options_env_values: None,
            options_env_policy: None,
            ..
        } => env_whitelist_set(
            rconfig,
            role_id.as_ref(),
            task_id,
            setlist_type.as_ref(),
            &options_env,
        ),
        Inputs {
            // chsr o password unset --tries --delay
            action: InputAction::Del,
            role_id,
            task_id,
            options: true,
            password_arg: Some(password_arg),
            setlist_type: None,
            ..
        } => unset_password(rconfig, role_id.as_ref(), task_id, password_arg),

        Inputs {
            // chsr o password set --tries 3 --delay 00:00:05
            action: InputAction::Set,
            role_id,
            task_id,
            options: true,
            password_arg: Some(password_arg),
            password_tries,
            password_delay,
            ..
        } => set_password(
            rconfig,
            role_id.as_ref(),
            task_id,
            password_arg,
            password_tries,
            password_delay,
        ),

        Inputs {
            // chsr o timeout unset --type  --duration  --max-usage
            action: InputAction::Del,
            role_id,
            task_id,
            options: true,
            timeout_arg: Some(timeout_arg),
            setlist_type: None,
            ..
        } => unset_timeout(rconfig, role_id.as_ref(), task_id, timeout_arg),

        Inputs {
            // chsr o timeout set --type tty --duration 00:00:00 --max-usage 1
            action: InputAction::Set,
            role_id,
            task_id,
            options: true,
            timeout_arg: Some(timeout_arg),
            timeout_type,
            timeout_duration,
            timeout_max_usage,
            ..
        } => set_timeout(
            rconfig,
            role_id.as_ref(),
            task_id,
            timeout_arg,
            timeout_type,
            timeout_duration,
            timeout_max_usage,
        ),

        Inputs {
            // chsr o path setpolicy delete-all
            action: InputAction::Set,
            role_id,
            task_id,
            options_type: Some(OptType::Path),
            options_path_policy: Some(options_path_policy),
            ..
        } => path_setpolicy(rconfig, role_id.as_ref(), task_id, options_path_policy),
        Inputs {
            // chsr o workdir setpolicy none
            action: InputAction::Set,
            role_id,
            task_id,
            options_type: Some(OptType::Workdir),
            options_workdir_policy: Some(options_workdir_policy),
            ..
        } => workdir_setpolicy(rconfig, role_id.as_ref(), task_id, options_workdir_policy),

        Inputs {
            // chsr o env whitelist add A
            action,
            role_id,
            task_id,
            options_key_env,
            options_env_values,
            options_type: Some(OptType::Env),
            setlist_type,
            options_env_policy: None,
            ..
        } => env_setlist_add(
            rconfig,
            role_id.as_ref(),
            task_id,
            setlist_type,
            action,
            options_key_env,
            options_env_values,
        ),

        Inputs {
            // chsr o path whitelist add path1:path2:path3
            action,
            role_id,
            task_id,
            options_path: Some(options_path),
            options_type: Some(OptType::Path),
            setlist_type,
            ..
        } => path_setlist2(
            rconfig,
            role_id.as_ref(),
            task_id,
            setlist_type,
            action,
            &options_path,
        ),

        Inputs {
            // chsr o workdir set /home/user
            action: InputAction::Set,
            role_id,
            task_id,
            options_path: Some(options_path),
            options_type: Some(OptType::Workdir),
            setlist_type: None,
            ..
        } => workdir_set_path(rconfig, role_id.as_ref(), task_id, options_path.as_str()),

        Inputs {
            // chsr o workdir whitelist add /home/user
            action,
            role_id,
            task_id,
            options_path: Some(options_path),
            options_type: Some(OptType::Workdir),
            setlist_type,
            ..
        } => workdir_setlist(
            rconfig,
            role_id.as_ref(),
            task_id,
            setlist_type,
            action,
            &options_path,
        ),

        Inputs {
            // chsr o env setpolicy delete-all
            role_id,
            task_id,
            options_type: Some(OptType::Env),
            options_env_policy: Some(options_env_policy),
            options_key_env: None,
            ..
        } => env_setpolicy(rconfig, role_id.as_ref(), task_id, options_env_policy),
        _ => Err("Unknown Input".into()),
    }
}
/// The policy that a command edits: the file named with `chsr file <path>` (its path, or its
/// name in the policy directory), else `default.json` of the policy directory, the only policy
/// file, or the policy of the root file when there is no other file.
fn target_policy(
    storage: &FileSettings,
    policy_path: Option<&str>,
) -> Result<Rc<RefCell<SPolicy>>, Box<dyn Error>> {
    let files: Vec<_> = storage.policy_files().collect();
    let names = || {
        files
            .iter()
            .map(|(path, _)| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(name) = policy_path {
        let wanted = Path::new(name);
        if let Some(policy) = storage.get(wanted) {
            return Ok(policy.clone());
        }
        return files
            .iter()
            .find(|(path, _)| {
                wanted.components().count() == 1 && path.file_name() == Some(wanted.as_os_str())
            })
            .map(|(_, policy)| Rc::clone(policy))
            .ok_or_else(|| format!("{name} is not a file of the policy: {}", names()).into());
    }
    match files.as_slice() {
        [] => Ok(storage.get_root().config.clone()),
        [(_, policy)] => Ok(Rc::clone(policy)),
        _ => files
            .iter()
            .find(|(path, _)| path.file_name() == Some(OsStr::new(DEFAULT_POLICY_FILE)))
            .map(|(_, policy)| Rc::clone(policy))
            .ok_or_else(|| {
                format!(
                    "The policy has several files and no {DEFAULT_POLICY_FILE}, choose one with chsr file <path>: {}",
                    names()
                )
                .into()
            }),
    }
}

pub fn perform_on_target_opt(
    rconfig: &Rc<RefCell<rootasrole_core::database::structs::SPolicy>>,
    role_id: Option<&String>,
    task_id: Option<IdTask>,
    exec_on_opt: impl Fn(Rc<RefCell<Opt>>) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    /// Execute on the options of the level, created empty when the level has none: only what
    /// the command sets is written, the other options stay inherited. `Opt::default()` would
    /// write every built-in default at that level, which replaces the lists of the upper levels.
    fn execute_or_create_option(
        exec_on_opt: impl Fn(Rc<RefCell<Opt>>) -> Result<(), Box<dyn Error>>,
        options: &mut Option<Rc<RefCell<Opt>>>,
        level: Level,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(opt) = options {
            exec_on_opt(opt.clone())
        } else {
            let new_opt = Rc::new(RefCell::new(Opt::builder(level).build()));
            let result = exec_on_opt(new_opt.clone());
            // a command that removes from options that the level does not have changes nothing
            if *new_opt.as_ref().borrow() != Opt::builder(level).build() {
                *options = Some(new_opt);
            }
            result
        }
    }

    // If role_id is provided, find the role
    if let Some(role_id) = role_id {
        let role = rconfig.role(role_id).ok_or("Role not found")?;
        let mut role_borrowed = role.as_ref().borrow_mut();

        // If task_id is provided, find the task
        if let Some(task_id) = task_id {
            let task = role_borrowed.task(&task_id).ok_or("Task not found")?;
            return execute_or_create_option(
                exec_on_opt,
                &mut task.as_ref().borrow_mut().options,
                Level::Task,
            );
        }
        // No task_id, use role options
        return execute_or_create_option(exec_on_opt, &mut role_borrowed.options, Level::Role);
    }

    // No role_id, use global config options
    execute_or_create_option(
        exec_on_opt,
        &mut rconfig.as_ref().borrow_mut().options,
        Level::Global,
    )
}
