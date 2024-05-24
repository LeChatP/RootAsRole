pub(crate) mod data;
pub(crate) mod pair;
pub(crate) mod process;
pub(crate) mod usage;

use std::error::Error;

use data::{Cli, Inputs, Rule};

use pair::recurse_pair;
use pest::Parser;
use process::process_input;
use tracing::debug;
use usage::print_usage;

use crate::common::{config::Storage, util::escape_parser_string_vec};

pub fn main<I, S>(storage: &Storage, args: I) -> Result<bool, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = escape_parser_string_vec(args);
    let args = Cli::parse(Rule::cli, &args);
    let args = match args {
        Ok(v) => v,
        Err(e) => {
            return print_usage(e);
        }
    };
    let mut inputs = Inputs::default();
    for pair in args {
        recurse_pair(pair, &mut inputs)?;
    }
    debug!("Inputs : {:?}", inputs);
    process_input(storage, inputs)
}

#[cfg(test)]
mod tests {
    use std::{ffi::CString, io::Write, rc::Rc};

    use crate::common::{
        config,
        database::{read_json_config, structs::SCredentials},
        remove_with_privileges,
    };

    use super::super::common::{
        config::{RemoteStorageSettings, SettingsFile, Storage, ROOTASROLE},
        database::{options::*, structs::*, version::Versioning},
    };

    use super::*;
    use crate::rc_refcell;
    use capctl::Cap;
    use chrono::TimeDelta;
    use tracing::error;
    use tracing_subscriber::util::SubscriberInitExt;

    fn setup(name: &str) {
        use std::io;
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_file(true)
            .with_line_number(true)
            .with_writer(io::stdout)
            .finish()
            .try_init();
        //Write json test json file
        let path = format!("{}.{}",ROOTASROLE,name);
        let mut file = std::fs::File::create(path.clone()).unwrap();
        let mut settings = SettingsFile::default();
        settings.storage.method = config::StorageMethod::JSON;
        settings.storage.settings = Some(RemoteStorageSettings::default());
        settings.storage.settings.as_mut().unwrap().path = Some(path.into());
        settings.storage.settings.as_mut().unwrap().immutable = Some(false);

        let mut opt = Opt::default();

        opt.timeout = Some(STimeout::default());
        opt.timeout.as_mut().unwrap().type_field = Some(TimestampType::PPID);
        opt.timeout.as_mut().unwrap().duration = Some(
            TimeDelta::hours(15)
                .checked_add(&TimeDelta::minutes(30))
                .unwrap()
                .checked_add(&TimeDelta::seconds(30))
                .unwrap(),
        );
        opt.timeout.as_mut().unwrap().max_usage = Some(1);

        opt.path = Some(SPathOptions::default());
        opt.path.as_mut().unwrap().default_behavior = PathBehavior::Delete;
        opt.path.as_mut().unwrap().add = vec!["path1".to_string(), "path2".to_string()]
            .into_iter()
            .collect();
        opt.path.as_mut().unwrap().sub = vec!["path3".to_string(), "path4".to_string()]
            .into_iter()
            .collect();

        opt.env = Some(SEnvOptions::default());
        opt.env.as_mut().unwrap().default_behavior = EnvBehavior::Delete;
        opt.env.as_mut().unwrap().keep = vec!["env1".into(), "env2".into()].into_iter().collect();
        opt.env.as_mut().unwrap().check = vec!["env3".into(), "env4".into()].into_iter().collect();
        opt.env.as_mut().unwrap().delete = vec!["env5".into(), "env6".into()].into_iter().collect();

        opt.root = Some(SPrivileged::Privileged);
        opt.bounding = Some(SBounding::Ignore);
        opt.wildcard_denied = Some("*".to_string());

        settings.config.as_ref().borrow_mut().options = Some(rc_refcell!(opt.clone()));

        settings.config.as_ref().borrow_mut().roles = vec![];

        let mut role = SRole::default();
        role.name = "complete".to_string();
        role.actors = vec![
            SActor::from_user_id(0),
            SActor::from_group_id(0),
            SActor::from_group_vec_string(vec!["groupA", "groupB"]),
        ];
        role.options = Some(rc_refcell!(opt.clone()));
        let role = rc_refcell!(role);

        let mut task = STask::new(IdTask::Name("t_complete".to_string()), Rc::downgrade(&role));
        task.purpose = Some("complete".to_string());
        task.commands = SCommands::default();
        task.commands.default_behavior = Some(SetBehavior::All);
        task.commands.add.push(SCommand::Simple("ls".to_string()));
        task.commands.add.push(SCommand::Simple("echo".to_string()));
        task.commands.sub.push(SCommand::Simple("cat".to_string()));
        task.commands.sub.push(SCommand::Simple("grep".to_string()));

        task.cred = SCredentials::default();
        task.cred.setuid = Some(SActorType::Name("user1".to_string()));
        task.cred.setgid = Some(SGroups::Multiple(vec![
            SActorType::Name("group1".to_string()),
            SActorType::Name("group2".to_string()),
        ]));
        task.cred.capabilities = Some(SCapabilities::default());
        task.cred.capabilities.as_mut().unwrap().default_behavior = SetBehavior::All;
        task.cred
            .capabilities
            .as_mut()
            .unwrap()
            .add
            .add(Cap::LINUX_IMMUTABLE);
        task.cred
            .capabilities
            .as_mut()
            .unwrap()
            .add
            .add(Cap::NET_BIND_SERVICE);
        task.cred
            .capabilities
            .as_mut()
            .unwrap()
            .sub
            .add(Cap::SYS_ADMIN);
        task.cred
            .capabilities
            .as_mut()
            .unwrap()
            .sub
            .add(Cap::SYS_BOOT);

        task.options = Some(rc_refcell!(opt.clone()));

        role.as_ref().borrow_mut().tasks.push(rc_refcell!(task));
        settings.config.as_ref().borrow_mut().roles.push(role);

        let versionned = Versioning::new(settings.clone());

        file.write_all(
            serde_json::to_string_pretty(&versionned)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();

        file.flush().unwrap();
    }

    fn teardown(name: &str) {
        //Remove json test file
        let path = format!("{}.{}",ROOTASROLE,name);
        remove_with_privileges(path).unwrap();
    }
    // we need to test every commands
    // chsr r r1 create
    // chsr r r1 delete
    // chsr r r1 show (actors|tasks|all)
    // chsr r r1 purge (actors|tasks|all)
    // chsr r r1 grant -u user1 -g group1 group2&group3
    // chsr r r1 revoke -u user1 -g group1 group2&group3
    // chsr r r1 task t1 show (all|cmd|cred)
    // chsr r r1 task t1 purge (all|cmd|cred)
    // chsr r r1 t t1 add
    // chsr r r1 t t1 del
    // chsr r r1 t t1 commands show
    // chsr r r1 t t1 cmd setpolicy (deny-all|allow-all)
    // chsr r r1 t t1 cmd (whitelist|blacklist) (add|del) super command with spaces
    // chsr r r1 t t1 credentials show
    // chsr r r1 t t1 cred (unset|set) --caps capA,capB,capC --setuid user1 --setgid group1,group2
    // chsr r r1 t t1 cred caps setpolicy (deny-all|allow-all)
    // chsr r r1 t t1 cred caps (whitelist|blacklist) (add|del) capA capB capC
    // chsr (r r1) (t t1) options show (all|path|env|root|bounding|wildcard-denied)
    // chsr o path set /usr/bin:/bin this regroups setpolicy delete and whitelist set
    // chsr o path setpolicy (delete-all|keep-all|inherit)
    // chsr o path (whitelist|blacklist) (add|del|set|purge) /usr/bin:/bin

    // chsr o env set MYVAR=1 VAR2=2 //this regroups setpolicy delete and whitelist set
    // chsr o env setpolicy (delete-all|keep-all|inherit)
    // chsr o env (whitelist|blacklist|checklist) (add|del|set|purge) MYVAR=1

    // chsr o root (privileged|user|inherit)
    // chsr o bounding (strict|ignore|inherit)
    // chsr o wildcard-denied (set|add|del) *

    // chsr o timeout set --type tty --duration 5:00 --max_usage 1
    // chsr o t unset --type --duration --max_usage

    #[test]
    fn test_all_main() {
        setup("all_main");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"all_main")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), vec!["--help"],)
            .inspect_err(|e| {
                error!("{}", e);
            })
            .inspect(|e| {
                debug!("{}", e);
            })
            .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r r1 create".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete delete".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        teardown("all_main");
    }
    #[test]
    fn test_r_complete_show_actors() {
        setup("r_complete_show_actors");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_show_actors")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete show actors".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete show tasks".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete show all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete purge actors".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        teardown("r_complete_show_actors");
    }
    #[test]
    fn test_purge_tasks() {
        setup("purge_tasks");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"purge_tasks")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete purge tasks".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        teardown("purge_tasks");
    }
    #[test]
    fn test_r_complete_purge_all() {
        setup("r_complete_purge_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_purge_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete purge all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        teardown("r_complete_purge_all");
    }
    #[test]
    fn test_r_complete_grant_u_user1_g_group1_g_group2_group3() {
        setup("r_complete_grant_u_user1_g_group1_g_group2_group3");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_grant_u_user1_g_group1_g_group2_group3")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete grant -u user1 -g group1 -g group2&group3".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::from_user_string("user1")));
        assert!(config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::from_group_string("group1")));
        assert!(config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::from_group_vec_string(vec!["group2", "group3"])));
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete revoke -u user1 -g group1 -g group2&group3".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(!config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::from_user_string("user1")));
        assert!(!config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::from_group_string("group1")));
        assert!(!config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::from_group_vec_string(vec!["group2", "group3"])));
        teardown("r_complete_grant_u_user1_g_group1_g_group2_group3");
    }
    #[test]
    fn test_r_complete_task_t_complete_show_all() {
        setup("r_complete_task_t_complete_show_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_task_t_complete_show_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete task t_complete show all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete task t_complete show cmd".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete task t_complete show cred".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete task t_complete purge all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        teardown("r_complete_task_t_complete_show_all");
    }
    #[test]
    fn test_r_complete_task_t_complete_purge_cmd() {
        setup("r_complete_task_t_complete_purge_cmd");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_task_t_complete_purge_cmd")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete task t_complete purge cmd".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        teardown("r_complete_task_t_complete_purge_cmd");
    }
    #[test]
    fn test_r_complete_task_t_complete_purge_cred() {
        setup("r_complete_task_t_complete_purge_cred");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_task_t_complete_purge_cred")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete task t_complete purge cred".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        debug!("=====");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_task_t_complete_purge_cred")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        let task_count = config.as_ref().borrow()[0].as_ref().borrow().tasks.len();
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t1 add".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks.len(),
            task_count + 1
        );
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t1 del".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks.len(),
            task_count
        );
        teardown("r_complete_task_t_complete_purge_cred");
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_setpolicy_deny_all() {
        setup("r_complete_t_t_complete_cmd_setpolicy_deny_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cmd_setpolicy_deny_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete cmd setpolicy deny-all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .commands
                .default_behavior,
            Some(SetBehavior::None)
        );
        teardown("r_complete_t_t_complete_cmd_setpolicy_deny_all");
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_setpolicy_allow_all() {
        setup("r_complete_t_t_complete_cmd_setpolicy_allow_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cmd_setpolicy_allow_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete cmd setpolicy allow-all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .commands
                .default_behavior,
            Some(SetBehavior::All)
        );
        teardown("r_complete_t_t_complete_cmd_setpolicy_allow_all");
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_whitelist_add_super_command_with_spaces() {
        setup("r_complete_t_t_complete_cmd_whitelist_add_super_command_with_spaces");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cmd_whitelist_add_super_command_with_spaces")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete cmd whitelist add super command with spaces".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .commands
            .add
            .contains(&SCommand::Simple("super command with spaces".to_string())));
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete cmd blacklist add super command with spaces".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .commands
            .sub
            .contains(&SCommand::Simple("super command with spaces".to_string())));
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete cmd whitelist del super command with spaces".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .commands
            .add
            .contains(&SCommand::Simple("super command with spaces".to_string())));
        teardown("r_complete_t_t_complete_cmd_whitelist_add_super_command_with_spaces");
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_blacklist_del_super_command_with_spaces() {
        setup("r_complete_t_t_complete_cmd_blacklist_del_super_command_with_spaces");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cmd_blacklist_del_super_command_with_spaces")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), vec![
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "blacklist",
                "del",
                "super",
                "command",
                "with",
                "spaces"
            ])
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .commands
            .sub
            .contains(&SCommand::Simple("super command with spaces".to_string())));
        teardown("r_complete_t_t_complete_cmd_blacklist_del_super_command_with_spaces");
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2() {
        setup("r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete cred set --caps cap_dac_override,cap_sys_admin,cap_sys_boot --setuid user1 --setgid group1,group2".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .default_behavior
            .is_none());
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .has(Cap::DAC_OVERRIDE));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .has(Cap::SYS_ADMIN));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .has(Cap::SYS_BOOT));
        assert!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .cred
                .capabilities
                .as_ref()
                .unwrap()
                .sub
                .size()
                == 0
        );
        assert!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .cred
                .capabilities
                .as_ref()
                .unwrap()
                .add
                .size()
                == 3
        );
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete cred unset --caps cap_dac_override,cap_sys_admin,cap_sys_boot --setuid user1 --setgid group1,group2".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .is_empty());
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .setuid
            .is_none());
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .setgid
            .is_none());
        teardown("r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2");
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_setpolicy_deny_all() {
        setup("r_complete_t_t_complete_cred_caps_setpolicy_deny_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cred_caps_setpolicy_deny_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete cred caps setpolicy deny-all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .cred
                .capabilities
                .as_ref()
                .unwrap()
                .default_behavior,
            SetBehavior::None
        );
        teardown("r_complete_t_t_complete_cred_caps_setpolicy_deny_all");
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_setpolicy_allow_all() {
        setup("r_complete_t_t_complete_cred_caps_setpolicy_allow_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cred_caps_setpolicy_allow_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete cred caps setpolicy allow-all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .cred
                .capabilities
                .as_ref()
                .unwrap()
                .default_behavior,
            SetBehavior::All
        );
        teardown("r_complete_t_t_complete_cred_caps_setpolicy_allow_all");
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot() {
        setup("r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete cred caps whitelist add cap_dac_override cap_sys_admin cap_sys_boot".split(" "))
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .has(Cap::DAC_OVERRIDE));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .has(Cap::SYS_ADMIN));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .has(Cap::SYS_BOOT));
        teardown("r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot() {
        setup("r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete cred caps blacklist add cap_dac_override cap_sys_admin cap_sys_boot".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .sub
            .has(Cap::DAC_OVERRIDE));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .sub
            .has(Cap::SYS_ADMIN));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .sub
            .has(Cap::SYS_BOOT));
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete cred caps whitelist del cap_dac_override cap_sys_admin cap_sys_boot".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .has(Cap::DAC_OVERRIDE));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .has(Cap::SYS_ADMIN));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .add
            .has(Cap::SYS_BOOT));
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete cred caps blacklist del cap_dac_override cap_sys_admin cap_sys_boot".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .sub
            .has(Cap::DAC_OVERRIDE));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .sub
            .has(Cap::SYS_ADMIN));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .cred
            .capabilities
            .as_ref()
            .unwrap()
            .sub
            .has(Cap::SYS_BOOT));
        teardown("r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");
    }
    #[test]
    fn test_options_show_all() {
        setup("options_show_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"options_show_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "options show all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete options show path".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete options show bounding".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        teardown("options_show_all");
    }
    #[test]
    fn test_r_complete_t_t_complete_options_show_env() {
        setup("r_complete_t_t_complete_options_show_env");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_options_show_env")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete options show env".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete t t_complete options show root".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete t t_complete options show bounding".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete t t_complete options show wildcard-denied".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete t t_complete o path set /usr/bin:/bin".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        teardown("r_complete_t_t_complete_options_show_env");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_setpolicy_delete_all() {
        setup("r_complete_t_t_complete_o_path_setpolicy_delete_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_path_setpolicy_delete_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o path setpolicy delete-all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .default_behavior
            .is_delete());
        teardown("r_complete_t_t_complete_o_path_setpolicy_delete_all");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_setpolicy_keep_unsafe() {
        setup("r_complete_t_t_complete_o_path_setpolicy_keep_unsafe");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_path_setpolicy_keep_unsafe")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o path setpolicy keep-unsafe".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .default_behavior
            .is_keep_unsafe());
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o path setpolicy keep-safe".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .default_behavior
            .is_keep_safe());
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o path setpolicy inherit".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .default_behavior
            .is_inherit());
        teardown("r_complete_t_t_complete_o_path_setpolicy_keep_unsafe");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_whitelist_add() {
        setup("r_complete_t_t_complete_o_path_whitelist_add");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_path_whitelist_add")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o path whitelist add /usr/bin:/bin".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .add
            .contains(&"/usr/bin".to_string()));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .add
            .contains(&"/bin".to_string()));
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o path whitelist del /usr/bin:/bin".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .add
            .contains(&"/usr/bin".to_string()));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .add
            .contains(&"/bin".to_string()));
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o path whitelist purge".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .add
            .is_empty());
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o path whitelist set /usr/bin:/bin".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .add
            .contains(&"/usr/bin".to_string()));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .add
            .contains(&"/bin".to_string()));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .path
                .as_ref()
                .unwrap()
                .add
                .len(),
            2
        );
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o path blacklist set /usr/bin:/bin".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o path blacklist add /tmp".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .sub
            .contains(&"/tmp".to_string()));
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o path blacklist del /usr/bin:/bin".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        debug!(
            "add : {:?}",
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .path
                .as_ref()
                .unwrap()
                .sub
        );
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .path
                .as_ref()
                .unwrap()
                .sub
                .len(),
            1
        );
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .sub
            .contains(&"/tmp".to_string()));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .sub
            .contains(&"/usr/bin".to_string()));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .path
            .as_ref()
            .unwrap()
            .sub
            .contains(&"/bin".to_string()));
        teardown("r_complete_t_t_complete_o_path_whitelist_add");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_blacklist_purge() {
        setup("r_complete_t_t_complete_o_path_blacklist_purge");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_path_blacklist_purge")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o path blacklist purge".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        teardown("r_complete_t_t_complete_o_path_blacklist_purge");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_keep_only_myvar_var2() {
        setup("r_complete_t_t_complete_o_env_keep_only_MYVAR_VAR2");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_keep_only_MYVAR_VAR2")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env keep-only MYVAR,VAR2".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .default_behavior
            .is_delete());
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .keep
            .contains(&"MYVAR".to_string().into()));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .keep
            .contains(&"VAR2".to_string().into()));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .env
                .as_ref()
                .unwrap()
                .keep
                .len(),
            2
        );
        teardown("r_complete_t_t_complete_o_env_keep_only_MYVAR_VAR2");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_delete_only_myvar_var2() {
        setup("r_complete_t_t_complete_o_env_delete_only_MYVAR_VAR2");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_delete_only_MYVAR_VAR2")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env delete-only MYVAR,VAR2".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .default_behavior
            .is_keep());
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .delete
            .contains(&"MYVAR".to_string().into()));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .delete
            .contains(&"VAR2".to_string().into()));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .env
                .as_ref()
                .unwrap()
                .delete
                .len(),
            2
        );
        teardown("r_complete_t_t_complete_o_env_delete_only_MYVAR_VAR2");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_delete_all() {
        setup("r_complete_t_t_complete_o_env_setpolicy_delete_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_setpolicy_delete_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env setpolicy delete-all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .env
                .as_ref()
                .unwrap()
                .default_behavior,
            EnvBehavior::Delete
        );
        teardown("r_complete_t_t_complete_o_env_setpolicy_delete_all");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_keep_all() {
        setup("r_complete_t_t_complete_o_env_setpolicy_keep_all");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_setpolicy_keep_all")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env setpolicy keep-all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .env
                .as_ref()
                .unwrap()
                .default_behavior,
            EnvBehavior::Keep
        );
        teardown("r_complete_t_t_complete_o_env_setpolicy_keep_all");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_inherit() {
        setup("r_complete_t_t_complete_o_env_setpolicy_inherit");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_setpolicy_inherit")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env setpolicy inherit".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .env
                .as_ref()
                .unwrap()
                .default_behavior,
            EnvBehavior::Inherit
        );
        teardown("r_complete_t_t_complete_o_env_setpolicy_inherit");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_whitelist_add_MYVAR() {
        setup("r_complete_t_t_complete_o_env_whitelist_add_MYVAR");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_whitelist_add_MYVAR")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env whitelist add MYVAR".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .keep
            .contains(&"MYVAR".to_string().into()));
        assert!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .env
                .as_ref()
                .unwrap()
                .keep
                .len()
                > 1
        );
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o env whitelist del MYVAR".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .keep
            .contains(&"MYVAR".to_string().into()));
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o env whitelist set MYVAR".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .keep
            .contains(&"MYVAR".to_string().into()));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .env
                .as_ref()
                .unwrap()
                .keep
                .len(),
            1
        );
        teardown("r_complete_t_t_complete_o_env_whitelist_add_MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_whitelist_purge() {
        setup("r_complete_t_t_complete_o_env_whitelist_purge");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_whitelist_purge")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env whitelist purge".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .keep
            .is_empty());
        teardown("r_complete_t_t_complete_o_env_whitelist_purge");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_add_myvar() {
        setup("r_complete_t_t_complete_o_env_blacklist_add_MYVAR");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_blacklist_add_MYVAR")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env blacklist add MYVAR".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .delete
            .contains(&"MYVAR".to_string().into()));
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o env blacklist del MYVAR".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .delete
            .contains(&"MYVAR".to_string().into()));
        teardown("r_complete_t_t_complete_o_env_blacklist_add_MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_set_myvar() {
        setup("r_complete_t_t_complete_o_env_blacklist_set_MYVAR");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_blacklist_set_MYVAR")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env blacklist set MYVAR".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .delete
            .contains(&"MYVAR".to_string().into()));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .env
                .as_ref()
                .unwrap()
                .delete
                .len(),
            1
        );
        teardown("r_complete_t_t_complete_o_env_blacklist_set_MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_purge() {
        setup("r_complete_t_t_complete_o_env_blacklist_purge");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_blacklist_purge")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env blacklist purge".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .delete
            .is_empty());
        teardown("r_complete_t_t_complete_o_env_blacklist_purge");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_checklist_add_MYVAR() {
        setup("r_complete_t_t_complete_o_env_checklist_add_MYVAR");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_env_checklist_add_MYVAR")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o env checklist add MYVAR".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .check
            .contains(&"MYVAR".to_string().into()));
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o env checklist del MYVAR".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(!config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .check
            .contains(&"MYVAR".to_string().into()));
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o env checklist set MYVAR".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .check
            .contains(&"MYVAR".to_string().into()));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .env
                .as_ref()
                .unwrap()
                .check
                .len(),
            1
        );
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o env checklist purge".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
            .as_ref()
            .borrow()
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .env
            .as_ref()
            .unwrap()
            .check
            .is_empty());
        teardown("r_complete_t_t_complete_o_env_checklist_add_MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_root_privileged() {
        setup("r_complete_t_t_complete_o_root_privileged");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_root_privileged")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o root privileged".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .root
                .as_ref()
                .unwrap(),
            &SPrivileged::Privileged
        );
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o root user".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .root
                .as_ref()
                .unwrap(),
            &SPrivileged::User
        );
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o root inherit".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .root
                .as_ref()
                .unwrap(),
            &SPrivileged::Inherit
        );
        teardown("r_complete_t_t_complete_o_root_privileged");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_bounding_strict() {
        setup("r_complete_t_t_complete_o_bounding_strict");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_bounding_strict")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o bounding strict".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .bounding
                .as_ref()
                .unwrap(),
            &SBounding::Strict
        );
        teardown("r_complete_t_t_complete_o_bounding_strict");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_bounding_ignore() {
        setup("r_complete_t_t_complete_o_bounding_ignore");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_bounding_ignore")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o bounding ignore".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .bounding
                .as_ref()
                .unwrap(),
            &SBounding::Ignore
        );
        teardown("r_complete_t_t_complete_o_bounding_ignore");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_bounding_inherit() {
        setup("r_complete_t_t_complete_o_bounding_inherit");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_bounding_inherit")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o bounding inherit".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .bounding
                .as_ref()
                .unwrap(),
            &SBounding::Inherit
        );
        teardown("r_complete_t_t_complete_o_bounding_inherit");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_auth_skip() {
        setup("r_complete_t_t_complete_o_auth_skip");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_auth_skip")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o auth skip".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .authentication
                .as_ref()
                .unwrap(),
            &SAuthentication::Skip
        );
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o auth perform".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .authentication
                .as_ref()
                .unwrap(),
            &SAuthentication::Perform
        );
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o auth inherit".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .authentication
                .as_ref()
                .unwrap(),
            &SAuthentication::Inherit
        );
        teardown("r_complete_t_t_complete_o_auth_skip");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_wildcard_denied_set() {
        setup("r_complete_t_t_complete_o_wildcard_denied_set");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_wildcard_denied_set")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(&Storage::JSON(config.clone()), "r complete t t_complete o wildcard-denied set *".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .wildcard_denied
                .as_ref()
                .unwrap(),
            "*"
        );
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o wildcard-denied add ~".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .wildcard_denied
                .as_ref()
                .unwrap(),
            "*~"
        );
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o wildcard-denied del *".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert_eq!(
            config.as_ref().borrow()[0].as_ref().borrow().tasks[0]
                .as_ref()
                .borrow()
                .options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .wildcard_denied
                .as_ref()
                .unwrap(),
            "~"
        );
        debug!("=====");
        let settings = config::get_settings(&format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_o_wildcard_denied_set")).expect("Failed to get settings");
        let config = read_json_config(settings.clone()).expect("Failed to read json");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o timeout set --type uid --duration 15:05:10 --max-usage 7"
                .split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        {
            let binding = config.as_ref().borrow();
            let bindingrole = binding[0].as_ref().borrow();
            let bindingtask = bindingrole.tasks[0].as_ref().borrow();
            let bindingopt = bindingtask.options.as_ref().unwrap().as_ref().borrow();
            let timeout = bindingopt.timeout.as_ref().unwrap();
            assert_eq!(timeout.duration, Some(chrono::Duration::seconds(54310)));
            assert_eq!(timeout.max_usage, Some(7));
            assert_eq!(timeout.type_field, Some(TimestampType::UID));
        }
        debug!("=====");
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o timeout unset --type --max-usage".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        {
            let binding = config.as_ref().borrow();
            let bindingrole = binding[0].as_ref().borrow();
            let bindingtask = bindingrole.tasks[0].as_ref().borrow();
            let bindingopt = bindingtask.options.as_ref().unwrap().as_ref().borrow();
            let timeout = bindingopt.timeout.as_ref().unwrap();
            assert_eq!(timeout.max_usage, None);
            assert_eq!(timeout.type_field, None);
        }
        assert!(main(
            &Storage::JSON(config.clone()),
            "r complete t t_complete o timeout unset --type --duration --max-usage".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        {
            let binding = config.as_ref().borrow();
            let bindingrole = binding[0].as_ref().borrow();
            let bindingtask = bindingrole.tasks[0].as_ref().borrow();
            let bindingopt = bindingtask.options.as_ref().unwrap().as_ref().borrow();
            assert!(bindingopt.timeout.as_ref().is_none());
        }
        assert!(main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            "r complete tosk".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_err());
        teardown("r_complete_t_t_complete_o_wildcard_denied_set");
    }
}
