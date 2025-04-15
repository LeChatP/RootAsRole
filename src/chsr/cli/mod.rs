pub(crate) mod data;
pub(crate) mod pair;
pub(crate) mod process;
pub(crate) mod usage;

use std::error::Error;

use data::{Cli, Inputs, Rule};

use log::debug;
use pair::recurse_pair;
use pest::Parser;
use process::process_input;
use usage::print_usage;

use crate::util::escape_parser_string_vec;
use rar_common::Storage;

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
    use std::{env::current_dir, io::Write};

    use linked_hash_set::LinkedHashSet;
    use rar_common::{
        database::{
            actor::SActor,
            actor::SGroups,
            options::*,
            structs::{SCredentials, *},
            versionning::Versioning,
        },
        get_full_settings,
        util::remove_with_privileges,
        RemoteStorageSettings, Settings, FullSettingsFile, Storage, StorageMethod,
    };

    use crate::ROOTASROLE;

    use super::*;
    use capctl::Cap;
    use chrono::TimeDelta;
    use log::error;
    use test_log::test;

    fn setup(name: &str) {
        let file_path = format!("{}.{}", ROOTASROLE, name);
        let versionned = Versioning::new(
            FullSettingsFile::builder()
                .storage(
                    Settings::builder()
                        .method(StorageMethod::JSON)
                        .settings(
                            RemoteStorageSettings::builder()
                                .path(file_path.clone())
                                .not_immutable()
                                .build(),
                        )
                        .build(),
                )
                .config(
                    SConfig::builder()
                        .options(|opt| {
                            opt.timeout(
                                STimeout::builder()
                                    .type_field(TimestampType::PPID)
                                    .duration(
                                        TimeDelta::hours(15)
                                            .checked_add(&TimeDelta::minutes(30))
                                            .unwrap()
                                            .checked_add(&TimeDelta::seconds(30))
                                            .unwrap(),
                                    )
                                    .max_usage(1)
                                    .build(),
                            )
                            .path(
                                SPathOptions::builder(PathBehavior::Delete)
                                    .add(["path1", "path2"])
                                    .sub(["path3", "path4"])
                                    .build(),
                            )
                            .env(
                                SEnvOptions::builder(EnvBehavior::Delete)
                                    .keep(["env1", "env2"])
                                    .unwrap()
                                    .check(["env3", "env4"])
                                    .unwrap()
                                    .delete(["env5", "env6"])
                                    .unwrap()
                                    .set([("env7", "val7"), ("env8", "val8")])
                                    .build(),
                            )
                            .root(SPrivileged::Privileged)
                            .bounding(SBounding::Ignore)
                            .wildcard_denied("*")
                            .build()
                        })
                        .role(
                            SRole::builder("complete")
                                .options(|opt| {
                                    opt.timeout(
                                        STimeout::builder()
                                            .type_field(TimestampType::PPID)
                                            .duration(
                                                TimeDelta::hours(15)
                                                    .checked_add(&TimeDelta::minutes(30))
                                                    .unwrap()
                                                    .checked_add(&TimeDelta::seconds(30))
                                                    .unwrap(),
                                            )
                                            .max_usage(1)
                                            .build(),
                                    )
                                    .path(
                                        SPathOptions::builder(PathBehavior::Delete)
                                            .add(["path1", "path2"])
                                            .sub(["path3", "path4"])
                                            .build(),
                                    )
                                    .env(
                                        SEnvOptions::builder(EnvBehavior::Delete)
                                            .keep(["env1", "env2"])
                                            .unwrap()
                                            .check(["env3", "env4"])
                                            .unwrap()
                                            .delete(["env5", "env6"])
                                            .unwrap()
                                            .set([("env7", "val7"), ("env8", "val8")])
                                            .build(),
                                    )
                                    .root(SPrivileged::Privileged)
                                    .bounding(SBounding::Ignore)
                                    .wildcard_denied("*")
                                    .build()
                                })
                                .actor(SActor::user(0).build())
                                .actor(SActor::group(0).build())
                                .actor(SActor::group(["groupA", "groupB"]).build())
                                .task(
                                    STask::builder("t_complete")
                                        .options(|opt| {
                                            opt.timeout(
                                                STimeout::builder()
                                                    .type_field(TimestampType::PPID)
                                                    .duration(
                                                        TimeDelta::hours(15)
                                                            .checked_add(&TimeDelta::minutes(30))
                                                            .unwrap()
                                                            .checked_add(&TimeDelta::seconds(30))
                                                            .unwrap(),
                                                    )
                                                    .max_usage(1)
                                                    .build(),
                                            )
                                            .path(
                                                SPathOptions::builder(PathBehavior::Delete)
                                                    .add(["path1", "path2"])
                                                    .sub(["path3", "path4"])
                                                    .build(),
                                            )
                                            .env(
                                                SEnvOptions::builder(EnvBehavior::Delete)
                                                    .keep(["env1", "env2"])
                                                    .unwrap()
                                                    .check(["env3", "env4"])
                                                    .unwrap()
                                                    .delete(["env5", "env6"])
                                                    .unwrap()
                                                    .set([("env7", "val7"), ("env8", "val8")])
                                                    .build(),
                                            )
                                            .root(SPrivileged::Privileged)
                                            .bounding(SBounding::Ignore)
                                            .wildcard_denied("*")
                                            .build()
                                        })
                                        .commands(
                                            SCommands::builder(SetBehavior::All)
                                                .add(["ls".into(), "echo".into()])
                                                .sub(["cat".into(), "grep".into()])
                                                .build(),
                                        )
                                        .cred(
                                            SCredentials::builder()
                                                .setuid("user1")
                                                .setgid(SGroupschooser::Group(SGroups::from([
                                                    "setgid1", "setgid2",
                                                ])))
                                                .capabilities(
                                                    SCapabilities::builder(SetBehavior::All)
                                                        .add_cap(Cap::LINUX_IMMUTABLE)
                                                        .add_cap(Cap::NET_BIND_SERVICE)
                                                        .sub_cap(Cap::SYS_ADMIN)
                                                        .sub_cap(Cap::SYS_BOOT)
                                                        .build(),
                                                )
                                                .build(),
                                        )
                                        .build(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .build(),
        );
        let mut file = std::fs::File::create(file_path.clone()).unwrap_or_else(|_| {
            panic!(
                "Failed to create {:?}/{:?} file at",
                current_dir().unwrap(),
                file_path
            )
        });
        let jsonstr = serde_json::to_string_pretty(&versionned).unwrap();
        file.write_all(jsonstr.as_bytes()).unwrap();
        file.flush().unwrap();
    }

    fn teardown(name: &str) {
        //Remove json test file
        let path = format!("{}.{}", ROOTASROLE, name);
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
        let path = format!("{}.{}", ROOTASROLE, "all_main");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(&Storage::SConfig(config.clone()), vec!["--help"],)
            .inspect_err(|e| {
                error!("{}", e);
            })
            .inspect(|e| {
                debug!("{}", e);
            })
            .is_ok_and(|b| !b));
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r r1 create".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
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
        let path = format!("{}.{}", ROOTASROLE, "r_complete_show_actors");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete show actors".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete show tasks".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete show all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
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
        let path = format!("{}.{}", ROOTASROLE, "purge_tasks");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete purge tasks".split(" "),
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
        let path = format!("{}.{}", ROOTASROLE, "r_complete_purge_all");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete purge all".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_grant_u_user1_g_group1_g_group2_group3"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete grant -u user1 -g group1 -g group2&group3".split(" "),
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
            .contains(&SActor::user("user1").build()));
        assert!(config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::group("group1").build()));
        assert!(config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::group(["group2", "group3"]).build()));
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .contains(&SActor::user("user1").build()));
        assert!(!config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::group("group1").build()));
        assert!(!config.as_ref().borrow()[0]
            .as_ref()
            .borrow()
            .actors
            .contains(&SActor::group(["group2", "group3"]).build()));
        teardown("r_complete_grant_u_user1_g_group1_g_group2_group3");
    }
    #[test]
    fn test_r_complete_task_t_complete_show_all() {
        setup("r_complete_task_t_complete_show_all");
        let path = format!("{}.{}", ROOTASROLE, "r_complete_task_t_complete_show_all");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete task t_complete show all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
    let settings = get_full_settings(&path).expect("Failed to get settings");
    let binding = settings.as_ref().borrow();
    let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete task t_complete show cmd".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
    let settings = get_full_settings(&path).expect("Failed to get settings");
    let binding = settings.as_ref().borrow();
    let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete task t_complete show cred".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
    let settings = get_full_settings(&path).expect("Failed to get settings");
    let binding = settings.as_ref().borrow();
    let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
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
        let path = format!("{}.{}", ROOTASROLE, "r_complete_task_t_complete_purge_cmd");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete task t_complete purge cmd".split(" "),
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
        let path = format!("{}.{}", ROOTASROLE, "r_complete_task_t_complete_purge_cred");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete task t_complete purge cred".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        debug!("=====");
        let path = format!("{}.{}", ROOTASROLE, "r_complete_task_t_complete_purge_cred");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        let task_count = config.as_ref().borrow()[0].as_ref().borrow().tasks.len();
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_cmd_setpolicy_deny_all"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete cmd setpolicy deny-all".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_cmd_setpolicy_allow_all"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete cmd setpolicy allow-all".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_cmd_whitelist_add_super_command_with_spaces"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete cmd whitelist add super command with spaces".split(" "),
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
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_cmd_blacklist_del_super_command_with_spaces"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            vec![
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
            ]
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
            .sub
            .contains(&SCommand::Simple("super command with spaces".to_string())));
        teardown("r_complete_t_t_complete_cmd_blacklist_del_super_command_with_spaces");
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2(
    ) {
        setup("r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2");
        let path = format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(&Storage::SConfig(config.clone()), "r complete t t_complete cred set --caps cap_dac_override,cap_sys_admin,cap_sys_boot --setuid user1 --setgid group1,group2".split(" "),
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
            &Storage::SConfig(config.clone()),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_cred_caps_setpolicy_deny_all"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete cred caps setpolicy deny-all".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_cred_caps_setpolicy_allow_all"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete cred caps setpolicy allow-all".split(" "),
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
    fn test_r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot(
    ) {
        setup("r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");
        let path = format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(&Storage::SConfig(config.clone()), "r complete t t_complete cred caps whitelist add cap_dac_override cap_sys_admin cap_sys_boot".split(" "))
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
    fn test_r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot(
    ) {
        setup("r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");
        let path = format!("{}.{}",ROOTASROLE,"r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(&Storage::SConfig(config.clone()), "r complete t t_complete cred caps blacklist add cap_dac_override cap_sys_admin cap_sys_boot".split(" "),
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
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
        let path = format!("{}.{}", ROOTASROLE, "options_show_all");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "options show all".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
    let settings = get_full_settings(&path).expect("Failed to get settings");
    let binding = settings.as_ref().borrow();
    let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete options show path".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
    let settings = get_full_settings(&path).expect("Failed to get settings");
    let binding = settings.as_ref().borrow();
    let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_options_show_env"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete options show env".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
    let settings = get_full_settings(&path).expect("Failed to get settings");
    let binding = settings.as_ref().borrow();
    let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete options show root".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
    let settings = get_full_settings(&path).expect("Failed to get settings");
    let binding = settings.as_ref().borrow();
    let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete options show bounding".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
    let settings = get_full_settings(&path).expect("Failed to get settings");
    let binding = settings.as_ref().borrow();
    let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete options show wildcard-denied".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| !b));
    let settings = get_full_settings(&path).expect("Failed to get settings");
    let binding = settings.as_ref().borrow();
    let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_path_setpolicy_delete_all"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o path setpolicy delete-all".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_path_setpolicy_keep_unsafe"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o path setpolicy keep-unsafe".split(" "),
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
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_path_whitelist_add"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o path whitelist add /usr/bin:/bin".split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        let default = LinkedHashSet::new();
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
            .as_ref()
            .unwrap_or(&default)
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
            .as_ref()
            .unwrap_or(&default)
            .contains(&"/bin".to_string()));
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .as_ref()
            .unwrap_or(&default)
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
            .as_ref()
            .unwrap_or(&default)
            .contains(&"/bin".to_string()));
        debug!("=====");
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .as_ref()
            .unwrap_or(&default)
            .is_empty());
        debug!("=====");
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .as_ref()
            .unwrap_or(&default)
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
            .as_ref()
            .unwrap_or(&default)
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
                .as_ref()
                .unwrap_or(&default)
                .len(),
            2
        );
        debug!("=====");
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
            .as_ref()
            .unwrap_or(&default)
            .contains(&"/tmp".to_string()));
        assert!(main(
            &Storage::SConfig(config.clone()),
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
                .as_ref()
                .unwrap_or(&default)
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
            .as_ref()
            .unwrap_or(&default)
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
            .as_ref()
            .unwrap_or(&default)
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
            .as_ref()
            .unwrap_or(&default)
            .contains(&"/bin".to_string()));
        teardown("r_complete_t_t_complete_o_path_whitelist_add");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_blacklist_purge() {
        setup("r_complete_t_t_complete_o_path_blacklist_purge");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_path_blacklist_purge"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o path blacklist purge".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_keep_only_MYVAR_VAR2"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env keep-only MYVAR,VAR2".split(" "),
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
            .as_ref()
            .unwrap()
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
            .as_ref()
            .unwrap()
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
                .as_ref()
                .unwrap()
                .len(),
            2
        );
        teardown("r_complete_t_t_complete_o_env_keep_only_MYVAR_VAR2");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_delete_only_myvar_var2() {
        setup("r_complete_t_t_complete_o_env_delete_only_MYVAR_VAR2");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_delete_only_MYVAR_VAR2"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env delete-only MYVAR,VAR2".split(" "),
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
            .as_ref()
            .unwrap()
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
            .as_ref()
            .unwrap()
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
                .as_ref()
                .unwrap()
                .len(),
            2
        );
        teardown("r_complete_t_t_complete_o_env_delete_only_MYVAR_VAR2");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_set_myvar_value_var2_value2() {
        setup("r_complete_t_t_complete_o_env_set_MYVAR_value_VAR2_value2");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_set_MYVAR_value_VAR2_value2"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            r#"r complete t t_complete o env set MYVAR=value,VAR2="value2""#.split(" "),
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
                .set
                .as_ref()
                .unwrap()
                .get_key_value("MYVAR")
                .unwrap(),
            (&"MYVAR".to_string(), &"value".to_string())
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
                .env
                .as_ref()
                .unwrap()
                .set
                .as_ref()
                .unwrap()
                .get_key_value("VAR2")
                .unwrap(),
            (&"VAR2".to_string(), &"value2".to_string())
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
                .env
                .as_ref()
                .unwrap()
                .set
                .as_ref()
                .unwrap()
                .len(),
            2
        );
        teardown("r_complete_t_t_complete_o_env_set_MYVAR_value_VAR2_value2");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_add_myvar_value_var2_value2() {
        setup("r_complete_t_t_complete_o_env_add_MYVAR_value_VAR2_value2");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_add_MYVAR_value_VAR2_value2"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            r#"r complete t t_complete o env setlist set VAR3=value3"#.split(" "),
        )
        .inspect_err(|e| {
            error!("{}", e);
        })
        .inspect(|e| {
            debug!("{}", e);
        })
        .is_ok_and(|b| b));
        assert!(main(
            &Storage::SConfig(config.clone()),
            r#"r complete t t_complete o env setlist add MYVAR=value,VAR2="value2""#.split(" "),
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
                .set
                .as_ref()
                .unwrap()
                .get_key_value("MYVAR")
                .unwrap(),
            (&"MYVAR".to_string(), &"value".to_string())
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
                .env
                .as_ref()
                .unwrap()
                .set
                .as_ref()
                .unwrap()
                .get_key_value("VAR2")
                .unwrap(),
            (&"VAR2".to_string(), &"value2".to_string())
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
                .env
                .as_ref()
                .unwrap()
                .set
                .as_ref()
                .unwrap()
                .get_key_value("VAR3")
                .unwrap(),
            (&"VAR3".to_string(), &"value3".to_string())
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
                .env
                .as_ref()
                .unwrap()
                .set
                .as_ref()
                .unwrap()
                .len(),
            3
        );
        assert!(main(
            &Storage::SConfig(config.clone()),
            r#"r complete t t_complete o env setlist del MYVAR,VAR2"#.split(" "),
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
                .set
                .as_ref()
                .unwrap()
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
            .env
            .as_ref()
            .unwrap()
            .set
            .as_ref()
            .unwrap()
            .get_key_value("MYVAR")
            .is_none());
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
            .set
            .as_ref()
            .unwrap()
            .get_key_value("VAR2")
            .is_none());
        assert!(main(
            &Storage::SConfig(config.clone()),
            r#"r complete t t_complete o env setlist purge"#.split(" "),
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
            .set
            .is_none());
        teardown("r_complete_t_t_complete_o_env_add_MYVAR_value_VAR2_value2");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_delete_all() {
        setup("r_complete_t_t_complete_o_env_setpolicy_delete_all");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_setpolicy_delete_all"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env setpolicy delete-all".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_setpolicy_keep_all"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env setpolicy keep-all".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_setpolicy_inherit"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env setpolicy inherit".split(" "),
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
    fn test_r_complete_t_t_complete_o_env_whitelist_add_myvar() {
        setup("r_complete_t_t_complete_o_env_whitelist_add_MYVAR");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_whitelist_add_MYVAR"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env whitelist add MYVAR".split(" "),
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
            .as_ref()
            .unwrap()
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
                .as_ref()
                .unwrap()
                .len()
                > 1
        );
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .as_ref()
            .unwrap()
            .contains(&"MYVAR".to_string().into()));
        debug!("=====");
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .as_ref()
            .unwrap()
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
                .as_ref()
                .unwrap()
                .len(),
            1
        );
        teardown("r_complete_t_t_complete_o_env_whitelist_add_MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_whitelist_purge() {
        setup("r_complete_t_t_complete_o_env_whitelist_purge");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_whitelist_purge"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env whitelist purge".split(" "),
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
            .is_none());
        teardown("r_complete_t_t_complete_o_env_whitelist_purge");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_add_myvar() {
        setup("r_complete_t_t_complete_o_env_blacklist_add_MYVAR");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_blacklist_add_MYVAR"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env blacklist add MYVAR".split(" "),
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
            .as_ref()
            .unwrap()
            .contains(&"MYVAR".to_string().into()));
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .as_ref()
            .unwrap()
            .contains(&"MYVAR".to_string().into()));
        teardown("r_complete_t_t_complete_o_env_blacklist_add_MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_set_myvar() {
        setup("r_complete_t_t_complete_o_env_blacklist_set_MYVAR");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_blacklist_set_MYVAR"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env blacklist set MYVAR".split(" "),
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
            .as_ref()
            .unwrap()
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
                .as_ref()
                .unwrap()
                .len(),
            1
        );
        teardown("r_complete_t_t_complete_o_env_blacklist_set_MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_purge() {
        setup("r_complete_t_t_complete_o_env_blacklist_purge");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_blacklist_purge"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env blacklist purge".split(" "),
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
            .is_none());
        teardown("r_complete_t_t_complete_o_env_blacklist_purge");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_checklist_add_myvar() {
        setup("r_complete_t_t_complete_o_env_checklist_add_MYVAR");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_env_checklist_add_MYVAR"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o env checklist add MYVAR".split(" "),
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
            .as_ref()
            .unwrap()
            .contains(&"MYVAR".to_string().into()));
        debug!("=====");
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .as_ref()
            .unwrap()
            .contains(&"MYVAR".to_string().into()));
        debug!("=====");
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .as_ref()
            .unwrap()
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
                .as_ref()
                .unwrap()
                .len(),
            1
        );
        debug!("=====");
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            .is_none());
        teardown("r_complete_t_t_complete_o_env_checklist_add_MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_root_privileged() {
        setup("r_complete_t_t_complete_o_root_privileged");
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_root_privileged"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o root privileged".split(" "),
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
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_bounding_strict"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o bounding strict".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_bounding_ignore"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o bounding ignore".split(" "),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_bounding_inherit"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o bounding inherit".split(" "),
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
        let path = format!("{}.{}", ROOTASROLE, "r_complete_t_t_complete_o_auth_skip");
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o auth skip".split(" "),
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
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_wildcard_denied_set"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
            "r complete t t_complete o wildcard-denied set *".split(" "),
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
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
        let path = format!(
            "{}.{}",
            ROOTASROLE, "r_complete_t_t_complete_o_wildcard_denied_set"
        );
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
            &Storage::SConfig(config.clone()),
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
        let settings = get_full_settings(&path).expect("Failed to get settings");
        let binding = settings.as_ref().borrow();
        let config = binding.config.as_ref().unwrap();
        assert!(main(
            &Storage::SConfig(config.clone()),
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
