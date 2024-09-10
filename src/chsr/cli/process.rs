mod json;

use std::{cell::RefCell, error::Error, rc::Rc};

use json::*;

use tracing::debug;

use rar_common::{
    database::{
        options::{Opt, OptType},
        structs::IdTask,
    },
    Storage,
};

use super::{
    data::{InputAction, Inputs},
    usage,
};

pub fn process_input(storage: &Storage, inputs: Inputs) -> Result<bool, Box<dyn Error>> {
    match inputs {
        Inputs {
            action: InputAction::Help,
            ..
        } => usage::help(),
        Inputs {
            action: InputAction::List,
            options, // show options ?
            role_id,
            role_type,
            task_id,
            task_type,    // what to show
            options_type, // in json
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                debug!("chsr list");
                match json::list_json(
                    rconfig,
                    role_id,
                    task_id,
                    options,
                    options_type,
                    task_type,
                    role_type,
                ) {
                    Ok(_) => {
                        debug!("chsr list ok");
                        Ok(false)
                    }
                    Err(e) => {
                        debug!("chsr list err {:?}", e);
                        Err(e)
                    }
                }
            }
        },
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
        } => match storage {
            Storage::JSON(rconfig) => role_add_del(rconfig, action, role_id, role_type),
        },
        Inputs {
            // chsr role r1 grant|revoke -u u1 -u u2 -g g1,g2
            action,
            role_id: Some(role_id),
            actors: Some(actors),
            options: false,
            ..
        } => match storage {
            Storage::JSON(rconfig) => grant_revoke(rconfig, role_id, action, actors),
        },

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
        } => match storage {
            Storage::JSON(rconfig) => task_add_del(rconfig, role_id, action, task_id, task_type),
        },
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
        } => match storage {
            Storage::JSON(rconfig) => cred_set(
                rconfig,
                role_id,
                task_id,
                cred_caps,
                cred_setuid,
                cred_setgid,
            ),
        },
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
        } => match storage {
            Storage::JSON(rconfig) => cred_unset(
                rconfig,
                role_id,
                task_id,
                cred_caps,
                cred_setuid,
                cred_setgid,
            ),
        },
        Inputs {
            action,
            role_id: Some(role_id),
            task_id: Some(task_id),
            setlist_type: Some(setlist_type),
            cred_caps: Some(pcred_caps),
            cmd_policy: None,
            options: false,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                cred_caps(rconfig, role_id, task_id, setlist_type, action, pcred_caps)
            }
        },
        Inputs {
            role_id: Some(role_id),
            task_id: Some(task_id),
            cred_policy: Some(cred_policy),
            options: false,
            ..
        } => match storage {
            Storage::JSON(rconfig) => cred_setpolicy(rconfig, role_id, task_id, cred_policy),
        },
        Inputs {
            // chsr role r1 task t1 command whitelist add c1
            action,
            role_id: Some(role_id),
            task_id: Some(task_id),
            cmd_id: Some(cmd_id),
            setlist_type: Some(setlist_type),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                cmd_whitelist_action(rconfig, role_id, task_id, cmd_id, setlist_type, action)
            }
        },
        Inputs {
            role_id: Some(role_id),
            task_id: Some(task_id),
            cmd_policy: Some(cmd_policy),
            ..
        } => match storage {
            Storage::JSON(rconfig) => cmd_setpolicy(rconfig, role_id, task_id, cmd_policy),
        },
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
        } => match storage {
            Storage::JSON(rconfig) => {
                env_set_policylist(rconfig, role_id, task_id, options_env, options_env_policy)
            }
        },
        Inputs {
            // chsr o root set privileged
            action: InputAction::Set,
            role_id,
            task_id,
            options_root: Some(options_root),
            ..
        } => match storage {
            Storage::JSON(rconfig) => set_privileged(rconfig, role_id, task_id, options_root),
        },
        Inputs {
            // chsr o bounding set strict
            action: InputAction::Set,
            role_id,
            task_id,
            options_bounding: Some(options_bounding),
            ..
        } => match storage {
            Storage::JSON(rconfig) => set_bounding(rconfig, role_id, task_id, options_bounding),
        },
        Inputs {
            // chsr o bounding set strict
            action: InputAction::Set,
            role_id,
            task_id,
            options_auth: Some(options_auth),
            ..
        } => match storage {
            Storage::JSON(rconfig) => set_authentication(rconfig, role_id, task_id, options_auth),
        },
        Inputs {
            // chsr o wildcard-denied set ";&*$"
            action,
            role_id,
            task_id,
            options: true,
            options_wildcard: Some(options_wildcard),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                json_wildcard(rconfig, role_id, task_id, action, options_wildcard)
            }
        },
        Inputs {
            // chsr o path whitelist set a:b:c
            action: InputAction::Set,
            role_id,
            task_id,
            options_path: Some(options_path),
            options_type: Some(OptType::Path),
            setlist_type,
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                path_set(rconfig, role_id, task_id, setlist_type, options_path)
            }
        },
        Inputs {
            // chsr o path whitelist set a:b:c
            action: InputAction::Purge,
            role_id,
            task_id,
            options_path: None,
            options_type: Some(OptType::Path),
            setlist_type,
            ..
        } => match storage {
            Storage::JSON(rconfig) => path_purge(rconfig, role_id, task_id, setlist_type),
        },
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
        } => match storage {
            Storage::JSON(rconfig) => {
                env_whitelist_set(rconfig, role_id, task_id, setlist_type, options_env)
            }
        },
        Inputs {
            // chsr o timeout unset --type  --duration  --max-usage
            action: InputAction::Del,
            role_id,
            task_id,
            options: true,
            timeout_arg: Some(timeout_arg),
            setlist_type: None,
            ..
        } => match storage {
            Storage::JSON(rconfig) => unset_timeout(rconfig, role_id, task_id, timeout_arg),
        },
        Inputs {
            // chsr o timeout set --type tty --duration 00:00:00 --max-usage 1
            action: InputAction::Set,
            role_id,
            task_id,
            options: true,
            timeout_arg: Some(_),
            timeout_type,
            timeout_duration,
            timeout_max_usage,
            ..
        } => match storage {
            Storage::JSON(rconfig) => set_timeout(
                rconfig,
                role_id,
                task_id,
                timeout_type,
                timeout_duration,
                timeout_max_usage,
            ),
        },

        Inputs {
            // chsr o path setpolicy delete-all
            action: InputAction::Set,
            role_id,
            task_id,
            options_type: Some(OptType::Path),
            options_path_policy: Some(options_path_policy),
            ..
        } => match storage {
            Storage::JSON(rconfig) => {
                path_setpolicy(rconfig, role_id, task_id, options_path_policy)
            }
        },
        Inputs {
            // chsr o path whitelist add path1:path2:path3
            action,
            role_id,
            task_id,
            options_key_env,
            options_env_values,
            options_type: Some(OptType::Env),
            setlist_type,
            options_env_policy: None,
            ..
        } => match storage {
            Storage::JSON(rconfig) => env_setlist_add(
                rconfig,
                role_id,
                task_id,
                setlist_type,
                action,
                options_key_env,
                options_env_values,
            ),
        },
        Inputs {
            // chsr o path whitelist add path1:path2:path3
            action,
            role_id,
            task_id,
            options_path: Some(options_path),
            options_type: Some(OptType::Path),
            setlist_type,
            ..
        } => match storage {
            Storage::JSON(rconfig) => path_setlist2(
                rconfig,
                role_id,
                task_id,
                setlist_type,
                action,
                options_path,
            ),
        },
        Inputs {
            // chsr o env setpolicy delete-all
            role_id,
            task_id,
            options_type: Some(OptType::Env),
            options_env_policy: Some(options_env_policy),
            options_key_env: None,
            ..
        } => match storage {
            Storage::JSON(rconfig) => env_setpolicy(rconfig, role_id, task_id, options_env_policy),
        },

        _ => Err("Unknown Input".into()),
    }
}

pub fn perform_on_target_opt(
    rconfig: &Rc<RefCell<rar_common::database::structs::SConfig>>,
    role_id: Option<String>,
    task_id: Option<IdTask>,
    exec_on_opt: impl Fn(Rc<RefCell<Opt>>) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let config = rconfig.as_ref().borrow_mut();
    if let Some(role_id) = role_id {
        if let Some(role) = config.role(&role_id) {
            if let Some(task_id) = task_id {
                if let Some(task) = role.as_ref().borrow().task(&task_id) {
                    if let Some(options) = &task.as_ref().borrow_mut().options {
                        exec_on_opt(options.clone())
                    } else {
                        let options = Rc::new(RefCell::new(Opt::default()));
                        let ret = exec_on_opt(options.clone());
                        task.as_ref().borrow_mut().options = Some(options);
                        ret
                    }
                } else {
                    Err("Task not found".into())
                }
            } else if let Some(options) = &role.as_ref().borrow_mut().options {
                exec_on_opt(options.clone())
            } else {
                let options = Rc::new(RefCell::new(Opt::default()));
                let ret = exec_on_opt(options.clone());
                role.as_ref().borrow_mut().options = Some(options);
                ret
            }
        } else {
            Err("Role not found".into())
        }
    } else {
        return exec_on_opt(config.options.as_ref().unwrap().clone());
    }
}
