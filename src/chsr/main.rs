//extern crate sudoers_reader;

use common::subsribe;
use common::{
    config::{self, Storage},
    database::{read_json_config, save_json},
    drop_effective,
    plugin::register_plugins,
    read_effective,
};
use tracing::{debug, error};

mod cli;
#[path = "../mod.rs"]
mod common;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    subsribe("chsr");
    drop_effective()?;
    register_plugins();
    let settings = config::get_settings().expect("Error on config read");
    let config = match settings.clone().as_ref().borrow().storage.method {
        config::StorageMethod::JSON => Storage::JSON(read_json_config(settings.clone())?),
        _ => {
            error!("Unsupported storage method");
            std::process::exit(1);
        }
    };
    read_effective(false).expect("Operation not permitted");

    if cli::main(&config, std::env::args()).is_ok_and(|b| b) {
        match config {
            Storage::JSON(config) => {
                debug!("Saving configuration");
                save_json(settings, config)?;
                Ok(())
            }
        }
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write, rc::Rc};

    use self::common::{
        config::{RemoteStorageSettings, SettingsFile, ROOTASROLE},
        database::{options::*, structs::*, version::Versioning},
    };

    use super::*;
    use capctl::Cap;
    use chrono::TimeDelta;
    use common::config::Storage;

    fn setup() {
        //Write json test json file
        let mut file = std::fs::File::create(ROOTASROLE).unwrap();
        let mut settings = SettingsFile::default();
        settings.storage.method = config::StorageMethod::JSON;
        settings.storage.settings = Some(RemoteStorageSettings::default());
        settings.storage.settings.as_mut().unwrap().path = Some(ROOTASROLE.into());
        settings.storage.settings.as_mut().unwrap().immutable = Some(false);

        let mut opt = Opt::default();

        opt.timeout = Some(STimeout::default());
        opt.timeout.as_mut().unwrap().type_field = TimestampType::PPID;
        opt.timeout.as_mut().unwrap().duration = TimeDelta::hours(15)
            .checked_add(&TimeDelta::minutes(30))
            .unwrap()
            .checked_add(&TimeDelta::seconds(30))
            .unwrap();
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

    fn teardown() {
        //Remove json test file
        std::fs::remove_file(ROOTASROLE).unwrap();
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

    //TODO: verify values
    #[test]
    fn test_main_1() {
        setup();

        // lets test every commands
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "r1", "create"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "r1", "delete"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "show", "actors"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "show", "tasks"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "show", "all"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "purge", "actors"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "purge", "tasks"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "purge", "all"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "grant",
                "-u",
                "user1",
                "-g",
                "group1",
                "-g",
                "group2&group3"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "revoke",
                "-u",
                "user1",
                "-g",
                "group1",
                "-g",
                "group2&group3"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "task", "t_complete", "show", "all"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "task", "t_complete", "show", "cmd"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "task",
                "t_complete",
                "show",
                "cred"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "task",
                "t_complete",
                "purge",
                "all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "task",
                "t_complete",
                "purge",
                "cmd"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "task",
                "t_complete",
                "purge",
                "cred"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "t", "t1", "add"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "t", "t1", "del"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "setpolicy",
                "deny-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "setpolicy",
                "allow-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "whitelist",
                "add",
                "super command with spaces"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "blacklist",
                "add",
                "super",
                "command",
                "with",
                "spaces"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "whitelist",
                "del",
                "super command with spaces"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cmd",
                "blacklist",
                "del",
                "super command with spaces"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        // let settings = config::get_settings().expect("Failed to get settings");
        // assert!(cli::main(
        //     &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
        //     vec!["chsr", "r", "complete", "t", "t_complete", "credentials", "show"],
        // )
        // .inspect_err(|e| {
        //     error!("{}", e);
        // })
        // .inspect(|e| {
        //     debug!("{}",e);
        // })
        // .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "unset",
                "--caps",
                "capA,capB,capC",
                "--setuid",
                "user1",
                "--setgid",
                "group1,group2"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "set",
                "--caps",
                "capA,capB,capC",
                "--setuid",
                "user1",
                "--setgid",
                "group1,group2"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "setpolicy",
                "deny-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "setpolicy",
                "allow-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "whitelist",
                "add",
                "capA",
                "capB",
                "capC"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "blacklist",
                "add",
                "capA",
                "capB",
                "capC"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "whitelist",
                "del",
                "capA",
                "capB",
                "capC"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "cred",
                "caps",
                "blacklist",
                "del",
                "capA",
                "capB",
                "capC"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "options", "show", "all"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "options", "show", "path"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec!["chsr", "r", "complete", "options", "show", "bounding"],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "options",
                "show",
                "env"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "options",
                "show",
                "root"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "options",
                "show",
                "bounding"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "options",
                "show",
                "wildcard-denied"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "set",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "setpolicy",
                "delete-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "setpolicy",
                "keep-unsafe"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "setpolicy",
                "inherit"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "whitelist",
                "add",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "whitelist",
                "del",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "whitelist",
                "set",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "whitelist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "blacklist",
                "add",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "blacklist",
                "del",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "blacklist",
                "set",
                "/usr/bin:/bin"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "path",
                "blacklist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "set",
                "MYVAR,VAR2"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "setpolicy",
                "delete-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "setpolicy",
                "keep-all"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "setpolicy",
                "inherit"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "whitelist",
                "add",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "whitelist",
                "del",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "whitelist",
                "set",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "whitelist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "blacklist",
                "add",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "blacklist",
                "del",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "blacklist",
                "set",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "blacklist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "checklist",
                "add",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "checklist",
                "del",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "checklist",
                "set",
                "MYVAR"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "env",
                "checklist",
                "purge"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "root",
                "privileged"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "root",
                "user"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "root",
                "inherit"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "bounding",
                "strict"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "bounding",
                "ignore"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "bounding",
                "inherit"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "wildcard-denied",
                "set",
                "*"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "wildcard-denied",
                "add",
                "*"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "wildcard-denied",
                "del",
                "*"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "timeout",
                "set",
                "--type",
                "tty",
                "--duration",
                "5:00",
                "--max-usage",
                "1"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = config::get_settings().expect("Failed to get settings");
        assert!(cli::main(
            &Storage::JSON(read_json_config(settings.clone()).expect("Failed to read json")),
            vec![
                "chsr",
                "r",
                "complete",
                "t",
                "t_complete",
                "o",
                "t",
                "unset",
                "--type",
                "--duration",
                "--max-usage"
            ],
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        teardown();
    }
}
