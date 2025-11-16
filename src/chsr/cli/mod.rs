pub(crate) mod data;
#[cfg(not(tarpaulin_include))]
#[cfg(feature = "editor")]
pub(crate) mod editor;
pub(crate) mod pair;
pub(crate) mod process;
//TODO: UI miri tests
#[cfg(not(tarpaulin_include))]
pub(crate) mod usage;

use std::{cell::RefCell, error::Error, path::PathBuf, rc::Rc};

use bon::builder;
use data::{Cli, Inputs, Rule};

use landlock::RulesetStatus;
use log::debug;
use pair::recurse_pair;
use pest::Parser;
use process::process_input;
use rar_common::FullSettings;
use usage::print_usage;

use crate::{cli::editor::edit_config, util::escape_parser_string_vec};

#[builder]
pub fn main<I, S>(
    #[builder(start_fn)] storage: Rc<RefCell<FullSettings>>,
    #[builder(start_fn)] args: I,
    #[builder(default = RulesetStatus::NotEnforced)] ruleset: RulesetStatus,
    folder: Option<&PathBuf>,
) -> Result<bool, Box<dyn Error>>
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
    if inputs.editor {
        if ruleset == RulesetStatus::NotEnforced {
            return Err("Editor mode requires landlock to be enforced.".into());
        }
        return edit_config(folder.unwrap(), storage.clone());
    }
    process_input(&storage, inputs)
}

#[cfg(test)]
mod tests {
    use std::{env::current_dir, fs, io::Write};

    use linked_hash_set::LinkedHashSet;
    use rar_common::{
        database::{
            actor::SActor,
            actor::SGroups,
            options::*,
            structs::{SCredentials, *},
            versionning::Versioning,
        },
        read_full_settings,
        util::remove_with_privileges,
        FullSettings, RemoteStorageSettings, SettingsContent, StorageMethod,
    };
    use serde_json::{Map, Value};

    use crate::ROOTASROLE;

    use super::*;
    use capctl::Cap;
    use chrono::TimeDelta;
    use log::error;
    use test_log::test;

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

    // Test helper functions
    struct TestContext {
        settings: Rc<RefCell<FullSettings>>,
        role_index: usize,
        task_index: usize,
    }

    impl TestContext {
        fn new(name: &str) -> (Self, Defer<impl FnOnce()>) {
            let defer = setup(name);
            let path = format!("{}.{}", ROOTASROLE, name);
            let settings = read_full_settings(&path).expect("Failed to get settings");
            (
                Self {
                    settings,
                    role_index: 0,
                    task_index: 0,
                },
                defer,
            )
        }

        fn run_command(&self, command: &str) -> Result<bool, Box<dyn Error>> {
            main(self.settings.clone(), command.split(" "))
                .call()
                .inspect_err(|e| error!("{}", e))
                .inspect(|e| debug!("{}", e))
        }

        fn assert_command_success(&self, command: &str) {
            assert!(self.run_command(command).expect("Command should not fail"));
        }

        fn assert_command_no_change(&self, command: &str) {
            assert!(!self.run_command(command).expect("Command should not fail"));
        }

        fn opt(&self, level: Level) -> Rc<RefCell<Opt>> {
            match level {
                Level::Task => {
                    let task = self.task();
                    let task_ref = task.as_ref().borrow();
                    task_ref.options.as_ref().unwrap().clone()
                }
                Level::Role => {
                    let role = self.role();
                    let role_ref = role.as_ref().borrow();
                    role_ref.options.as_ref().unwrap().clone()
                }
                Level::Global => {
                    let settings_ref = self.settings.as_ref().borrow();
                    let config_ref = settings_ref.config.as_ref().unwrap().as_ref().borrow();
                    config_ref.options.as_ref().unwrap().clone()
                }
                _ => panic!("Invalid level"),
            }
        }

        fn get_role(&self, role_index: usize) -> Rc<RefCell<SRole>> {
            let settings_ref = self.settings.as_ref().borrow();
            let config_ref = settings_ref.config.as_ref().unwrap().as_ref().borrow();
            config_ref[role_index].clone()
        }

        fn get_task(&self, role_index: usize, task_index: usize) -> Rc<RefCell<STask>> {
            let settings_ref = self.get_role(role_index);
            let role_ref = settings_ref.as_ref().borrow();
            role_ref.tasks[task_index].clone()
        }

        fn role(&self) -> Rc<RefCell<SRole>> {
            self.get_role(self.role_index)
        }

        fn task(&self) -> Rc<RefCell<STask>> {
            self.get_task(self.role_index, self.task_index)
        }

        fn with_role_actors<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&Vec<SActor>) -> R,
        {
            let settings_ref = self.role();
            let role_ref = settings_ref.as_ref().borrow();
            f(&role_ref.actors)
        }

        fn assert_actor_exists(&self, actor: &SActor) {
            self.with_role_actors(|actors| {
                assert!(actors.contains(actor));
            })
        }

        fn assert_actor_not_exists(&self, actor: &SActor) {
            self.with_role_actors(|actors| {
                assert!(!actors.contains(actor));
            })
        }

        fn task_count(&self) -> usize {
            self.role().as_ref().borrow().tasks.len()
        }

        fn with_task_commands<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&SCommands) -> R,
        {
            let settings_ref = self.task();
            let task_ref = settings_ref.as_ref().borrow();
            f(&task_ref.commands)
        }

        fn with_task_capabilities<F, R>(&self, f: F) -> R
        where
            F: FnOnce(Option<&SCapabilities>) -> R,
        {
            let settings_ref = self.task();
            let task_ref = settings_ref.as_ref().borrow();
            f(task_ref.cred.capabilities.as_ref())
        }

        fn assert_command_default_behavior(&self, expected: Option<SetBehavior>) {
            self.with_task_commands(|commands| {
                assert_eq!(commands.default, expected);
            })
        }

        fn assert_command_contains(&self, command: &SCommand) {
            self.with_task_commands(|commands| {
                assert!(commands.add.contains(command));
            })
        }

        fn assert_command_not_contains(&self, command: &SCommand) {
            self.with_task_commands(|commands| {
                assert!(!commands.add.contains(command));
            })
        }

        fn assert_command_blacklist_contains(&self, command: &SCommand) {
            self.with_task_commands(|commands| {
                assert!(commands.sub.contains(command));
            })
        }

        fn assert_command_blacklist_not_contains(&self, command: &SCommand) {
            self.with_task_commands(|commands| {
                assert!(!commands.sub.contains(command));
            })
        }

        fn run_command_vec(&self, args: Vec<&str>) -> Result<bool, Box<dyn Error>> {
            main(self.settings.clone(), args)
                .call()
                .inspect_err(|e| error!("{}", e))
                .inspect(|e| debug!("{}", e))
        }

        fn assert_command_vec_success(&self, args: Vec<&str>) {
            assert!(self.run_command_vec(args).expect("Command should not fail"));
        }

        fn assert_capability_default_behavior_is_none(&self) {
            self.with_task_capabilities(|caps| {
                assert!(caps.unwrap().default_behavior.is_none());
            })
        }

        fn assert_capability_has(&self, cap: Cap) {
            self.with_task_capabilities(|caps| {
                assert!(caps.unwrap().add.has(cap));
            })
        }

        fn assert_capability_sub_size(&self, expected: usize) {
            self.with_task_capabilities(|caps| {
                assert_eq!(caps.unwrap().sub.size(), expected);
            })
        }

        fn assert_capability_add_size(&self, expected: usize) {
            self.with_task_capabilities(|caps| {
                assert_eq!(caps.unwrap().add.size(), expected);
            })
        }

        fn assert_capability_add_is_empty(&self) {
            self.with_task_capabilities(|caps| {
                assert!(caps.unwrap().add.is_empty());
            })
        }

        fn assert_setuid_is_none(&self) {
            let settings_ref = self.task();
            let task_ref = settings_ref.as_ref().borrow();
            assert!(task_ref.cred.setuid.is_none());
        }

        fn assert_setgid_is_none(&self) {
            let settings_ref = self.task();
            let task_ref = settings_ref.as_ref().borrow();
            assert!(task_ref.cred.setgid.is_none());
        }

        fn assert_capability_default_behavior(&self, expected: SetBehavior) {
            self.with_task_capabilities(|caps| {
                assert_eq!(caps.unwrap().default_behavior, expected);
            })
        }

        fn assert_capability_sub_has(&self, cap: Cap) {
            self.with_task_capabilities(|caps| {
                assert!(caps.unwrap().sub.has(cap));
            })
        }

        fn assert_capability_add_not_has(&self, cap: Cap) {
            self.with_task_capabilities(|caps| {
                assert!(!caps.unwrap().add.has(cap));
            })
        }

        fn assert_capability_sub_not_has(&self, cap: Cap) {
            self.with_task_capabilities(|caps| {
                assert!(!caps.unwrap().sub.has(cap));
            })
        }

        fn with_path_options<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&SPathOptions) -> R,
        {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            f(&task_ref.path.as_ref().unwrap())
        }

        fn assert_path_default_behavior(&self, expected: PathBehavior) {
            self.with_path_options(|path_options| {
                assert_eq!(path_options.default_behavior, expected);
            });
        }

        fn assert_path_whitelist_contains(&self, path: &str) {
            self.with_path_options(|path_options| {
                let default = LinkedHashSet::new();
                assert!(path_options
                    .add
                    .as_ref()
                    .unwrap_or(&default)
                    .contains(&path.to_string()));
            });
        }

        fn assert_path_whitelist_not_contains(&self, path: &str) {
            self.with_path_options(|path_options| {
                let default = LinkedHashSet::new();
                assert!(!path_options
                    .add
                    .as_ref()
                    .unwrap_or(&default)
                    .contains(&path.to_string()));
            });
        }

        fn assert_path_blacklist_contains(&self, path: &str) {
            self.with_path_options(|path_options| {
                let default = LinkedHashSet::new();
                assert!(path_options
                    .sub
                    .as_ref()
                    .unwrap_or(&default)
                    .contains(&path.to_string()));
            });
        }

        fn assert_path_blacklist_not_contains(&self, path: &str) {
            self.with_path_options(|path_options| {
                let default = LinkedHashSet::new();
                assert!(!path_options
                    .sub
                    .as_ref()
                    .unwrap_or(&default)
                    .contains(&path.to_string()));
            });
        }

        fn assert_path_whitelist_is_empty(&self) {
            self.assert_path_whitelist_len(0);
        }

        fn assert_path_whitelist_len(&self, expected: usize) {
            self.with_path_options(|path_options| {
                let default = LinkedHashSet::new();
                assert_eq!(
                    path_options.add.as_ref().unwrap_or(&default).len(),
                    expected
                );
            });
        }

        fn assert_path_blacklist_len(&self, expected: usize) {
            self.with_path_options(|path_options| {
                let default = LinkedHashSet::new();
                assert_eq!(
                    path_options.sub.as_ref().unwrap_or(&default).len(),
                    expected
                );
            });
        }

        fn with_env_options<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&SEnvOptions) -> R,
        {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            f(&task_ref.env.as_ref().unwrap())
        }

        fn assert_env_default_behavior_is_delete(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.default_behavior.is_delete());
            })
        }

        fn assert_env_default_behavior_is_keep(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.default_behavior.is_keep());
            })
        }

        fn assert_env_default_behavior(&self, expected: EnvBehavior) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.default_behavior, expected);
            })
        }

        fn assert_env_keep_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(env_options
                    .keep
                    .as_ref()
                    .unwrap()
                    .contains(&var.to_string().into()));
            })
        }

        fn assert_env_keep_len(&self, expected: usize) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.keep.as_ref().unwrap().len(), expected);
            })
        }

        fn assert_env_delete_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(env_options
                    .delete
                    .as_ref()
                    .unwrap()
                    .contains(&var.to_string().into()));
            })
        }

        fn assert_env_delete_len(&self, expected: usize) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.delete.as_ref().unwrap().len(), expected);
            })
        }

        fn assert_env_set_key_value(&self, key: &str, value: &str) {
            self.with_env_options(|env_options| {
                assert_eq!(
                    env_options
                        .set
                        .as_ref()
                        .unwrap()
                        .get_key_value(key)
                        .unwrap(),
                    (&key.to_string(), &value.to_string())
                );
            })
        }

        fn assert_env_set_len(&self, expected: usize) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.set.as_ref().unwrap().len(), expected);
            })
        }

        fn assert_env_set_is_none(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.set.is_none());
            })
        }

        fn assert_env_set_key_not_exists(&self, key: &str) {
            self.with_env_options(|env_options| {
                assert!(env_options
                    .set
                    .as_ref()
                    .unwrap()
                    .get_key_value(key)
                    .is_none());
            })
        }

        fn assert_env_keep_not_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(!env_options
                    .keep
                    .as_ref()
                    .unwrap()
                    .contains(&var.to_string().into()));
            })
        }

        fn assert_env_keep_is_none(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.keep.is_none());
            })
        }

        fn assert_env_delete_not_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(!env_options
                    .delete
                    .as_ref()
                    .unwrap()
                    .contains(&var.to_string().into()));
            })
        }

        fn assert_env_delete_is_none(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.delete.is_none());
            })
        }

        fn assert_env_check_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(env_options
                    .check
                    .as_ref()
                    .unwrap()
                    .contains(&var.to_string().into()));
            })
        }

        fn assert_env_check_not_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(!env_options
                    .check
                    .as_ref()
                    .unwrap()
                    .contains(&var.to_string().into()));
            })
        }

        fn assert_env_check_len(&self, expected: usize) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.check.as_ref().unwrap().len(), expected);
            })
        }

        fn assert_env_check_is_none(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.check.is_none());
            })
        }

        // Root option helpers
        fn assert_root_option(&self, expected: &Option<SPrivileged>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.root, *expected);
        }

        // Bounding option helpers
        fn assert_bounding_option(&self, expected: &Option<SBounding>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.bounding, *expected);
        }

        // Authentication option helpers
        fn assert_authentication_option(&self, expected: &Option<SAuthentication>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.authentication, *expected);
        }

        // Execinfo option helpers
        fn assert_execinfo_option(&self, expected: &Option<SInfo>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.execinfo, *expected);
        }

        // SUMask option helpers
        fn assert_umask_option(&self, expected: &Option<SUMask>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.umask, *expected);
        }
    }

    fn setup(name: &str) -> Defer<impl FnOnce()> {
        let file_path = format!("{}.{}", ROOTASROLE, name);
        let versionned = Versioning::new(
            FullSettings::builder()
                .storage(
                    SettingsContent::builder()
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
                                                .setgid(SGroupsEither::MandatoryGroups(
                                                    SGroups::from(["setgid1", "setgid2"]),
                                                ))
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
        defer(move || {
            remove_with_privileges(file_path).unwrap();
        })
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
    // chsr (r r1) (t t1) options show (all|path|env|root|bounding)
    // chsr o path set /usr/bin:/bin this regroups setpolicy delete and whitelist set
    // chsr o path setpolicy (delete-all|keep-all|inherit)
    // chsr o path (whitelist|blacklist) (add|del|set|purge) /usr/bin:/bin

    // chsr o env set MYVAR=1 VAR2=2 //this regroups setpolicy delete and whitelist set
    // chsr o env setpolicy (delete-all|keep-all|inherit)
    // chsr o env (whitelist|blacklist|checklist) (add|del|set|purge) MYVAR=1

    // chsr o root (privileged|user|inherit)
    // chsr o bounding (strict|ignore|inherit)

    // chsr o timeout set --type tty --duration 5:00 --max_usage 1
    // chsr o t unset --type --duration --max_usage

    #[test]
    fn test_all_main() {
        let (ctx, _defer) = TestContext::new("all_main");

        // Test --help command (should not change anything)
        ctx.assert_command_no_change("--help");

        // Test role creation
        ctx.assert_command_success("r r1 create");

        // Test role deletion
        ctx.assert_command_success("r complete delete");
    }
    #[test]
    fn test_r_complete_show_actors() {
        let (ctx, _defer) = TestContext::new("r_complete_show_actors");

        // Test show commands (should not change anything)
        ctx.assert_command_no_change("r complete show actors");
        ctx.assert_command_no_change("r complete show tasks");
        ctx.assert_command_no_change("r complete show all");

        // Test purge actors command (should make changes)
        ctx.assert_command_success("r complete purge actors");
    }
    #[test]
    fn test_purge_tasks() {
        let (ctx, _defer) = TestContext::new("purge_tasks");

        // Test purge tasks command (should make changes)
        ctx.assert_command_success("r complete purge tasks");
    }
    #[test]
    fn test_r_complete_purge_all() {
        let (ctx, _defer) = TestContext::new("r_complete_purge_all");

        // Test purge all command (should make changes)
        ctx.assert_command_success("r complete purge all");
    }
    #[test]
    fn test_r_complete_grant_u_user1_g_group1_g_group2_group3() {
        let (ctx, _defer) = TestContext::new("r_complete_grant_u_user1_g_group1_g_group2_group3");

        // Test grant command (should make changes)
        ctx.assert_command_success("r complete grant -u user1 -g group1 -g group2&group3");

        // Verify actors were added
        ctx.assert_actor_exists(&SActor::user("user1").build());
        ctx.assert_actor_exists(&SActor::group("group1").build());
        ctx.assert_actor_exists(&SActor::group(["group2", "group3"]).build());

        // Test revoke command (should make changes)
        ctx.assert_command_success("r complete revoke -u user1 -g group1 -g group2&group3");

        // Verify actors were removed
        ctx.assert_actor_not_exists(&SActor::user("user1").build());
        ctx.assert_actor_not_exists(&SActor::group("group1").build());
        ctx.assert_actor_not_exists(&SActor::group(["group2", "group3"]).build());
    }
    #[test]
    fn test_r_complete_task_t_complete_show_all() {
        let (ctx, _defer) = TestContext::new("r_complete_task_t_complete_show_all");

        // Test show commands (should not change anything)
        ctx.assert_command_no_change("r complete task t_complete show all");
        ctx.assert_command_no_change("r complete task t_complete show cmd");
        ctx.assert_command_no_change("r complete task t_complete show cred");

        // Test purge all command (should make changes)
        ctx.assert_command_success("r complete task t_complete purge all");
    }
    #[test]
    fn test_r_complete_task_t_complete_purge_cmd() {
        let (ctx, _defer) = TestContext::new("r_complete_task_t_complete_purge_cmd");

        // Test purge cmd command (should make changes)
        ctx.assert_command_success("r complete task t_complete purge cmd");
    }
    #[test]
    fn test_r_complete_task_t_complete_purge_cred() {
        let (ctx, _defer) = TestContext::new("r_complete_task_t_complete_purge_cred");

        // Test purge cred command (should make changes)
        ctx.assert_command_success("r complete task t_complete purge cred");

        debug!("=====");
        let task_count = ctx.task_count();
        ctx.assert_command_success("r complete t t1 add");
        assert_eq!(ctx.task_count(), task_count + 1);

        ctx.assert_command_success("r complete t t1 del");
        assert_eq!(ctx.task_count(), task_count);
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_setpolicy_deny_all() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_cmd_setpolicy_deny_all");

        ctx.assert_command_success("r complete t t_complete cmd setpolicy deny-all");
        ctx.assert_command_default_behavior(Some(SetBehavior::None));
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_setpolicy_allow_all() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_cmd_setpolicy_allow_all");

        ctx.assert_command_success("r complete t t_complete cmd setpolicy allow-all");
        ctx.assert_command_default_behavior(Some(SetBehavior::All));
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_whitelist_add_super_command_with_spaces() {
        let (ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_cmd_whitelist_add_super_command_with_spaces");

        let command = SCommand::Simple("super command with spaces".to_string());

        // Test whitelist add
        ctx.assert_command_success(
            "r complete t t_complete cmd whitelist add super command with spaces",
        );
        ctx.assert_command_contains(&command);

        // Test blacklist add
        ctx.assert_command_success(
            "r complete t t_complete cmd blacklist add super command with spaces",
        );
        ctx.assert_command_blacklist_contains(&command);

        // Test whitelist del
        ctx.assert_command_success(
            "r complete t t_complete cmd whitelist del super command with spaces",
        );
        ctx.assert_command_not_contains(&command);
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_blacklist_del_super_command_with_spaces() {
        let (ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_cmd_blacklist_del_super_command_with_spaces");

        let command = SCommand::Simple("super command with spaces".to_string());
        let args = vec![
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
            "spaces",
        ];

        ctx.assert_command_vec_success(args);
        ctx.assert_command_blacklist_not_contains(&command);
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2(
    ) {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2");

        // Test cred set command
        ctx.assert_command_success("r complete t t_complete cred set --caps cap_dac_override,cap_sys_admin,cap_sys_boot --setuid user1 --setgid group1,group2");

        // Verify capabilities
        ctx.assert_capability_default_behavior_is_none();
        ctx.assert_capability_has(Cap::DAC_OVERRIDE);
        ctx.assert_capability_has(Cap::SYS_ADMIN);
        ctx.assert_capability_has(Cap::SYS_BOOT);
        ctx.assert_capability_sub_size(0);
        ctx.assert_capability_add_size(3);

        // Test cred unset command
        ctx.assert_command_success("r complete t t_complete cred unset --caps cap_dac_override,cap_sys_admin,cap_sys_boot --setuid user1 --setgid group1,group2");

        // Verify everything is cleared
        ctx.assert_capability_add_is_empty();
        ctx.assert_setuid_is_none();
        ctx.assert_setgid_is_none();
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_setpolicy_deny_all() {
        let (ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_cred_caps_setpolicy_deny_all");

        ctx.assert_command_success("r complete t t_complete cred caps setpolicy deny-all");
        ctx.assert_capability_default_behavior(SetBehavior::None);
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_setpolicy_allow_all() {
        let (ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_cred_caps_setpolicy_allow_all");

        ctx.assert_command_success("r complete t t_complete cred caps setpolicy allow-all");
        ctx.assert_capability_default_behavior(SetBehavior::All);
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot(
    ) {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");

        ctx.assert_command_success("r complete t t_complete cred caps whitelist add cap_dac_override cap_sys_admin cap_sys_boot");
        ctx.assert_capability_has(Cap::DAC_OVERRIDE);
        ctx.assert_capability_has(Cap::SYS_ADMIN);
        ctx.assert_capability_has(Cap::SYS_BOOT);
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot(
    ) {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot");

        // Test blacklist add
        ctx.assert_command_success("r complete t t_complete cred caps blacklist add cap_dac_override cap_sys_admin cap_sys_boot");
        ctx.assert_capability_sub_has(Cap::DAC_OVERRIDE);
        ctx.assert_capability_sub_has(Cap::SYS_ADMIN);
        ctx.assert_capability_sub_has(Cap::SYS_BOOT);

        debug!("=====");
        // Test whitelist del
        ctx.assert_command_success("r complete t t_complete cred caps whitelist del cap_dac_override cap_sys_admin cap_sys_boot");
        ctx.assert_capability_add_not_has(Cap::DAC_OVERRIDE);
        ctx.assert_capability_add_not_has(Cap::SYS_ADMIN);
        ctx.assert_capability_add_not_has(Cap::SYS_BOOT);

        debug!("=====");
        // Test blacklist del
        ctx.assert_command_success("r complete t t_complete cred caps blacklist del cap_dac_override cap_sys_admin cap_sys_boot");
        ctx.assert_capability_sub_not_has(Cap::DAC_OVERRIDE);
        ctx.assert_capability_sub_not_has(Cap::SYS_ADMIN);
        ctx.assert_capability_sub_not_has(Cap::SYS_BOOT);
    }
    #[test]
    fn test_options_show_all() {
        let (ctx, _defer) = TestContext::new("options_show_all");

        // Test show commands (should not change anything)
        ctx.assert_command_no_change("options show all");
        ctx.assert_command_no_change("r complete options show path");
        ctx.assert_command_no_change("r complete options show bounding");
    }
    #[test]
    fn test_r_complete_t_t_complete_options_show_env() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_options_show_env");

        // Test show commands (should not change anything)
        ctx.assert_command_no_change("r complete t t_complete options show env");
        ctx.assert_command_no_change("r complete t t_complete options show root");
        ctx.assert_command_no_change("r complete t t_complete options show bounding");

        // Test path set command (should make changes)
        ctx.assert_command_success("r complete t t_complete o path set /usr/bin:/bin");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_setpolicy_delete_all() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_path_setpolicy_delete_all");

        ctx.assert_command_success("r complete t t_complete o path setpolicy delete-all");
        ctx.assert_path_default_behavior(PathBehavior::Delete);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_setpolicy_keep_unsafe() {
        let (ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_path_setpolicy_keep_unsafe");

        ctx.assert_command_success("r complete t t_complete o path setpolicy keep-unsafe");
        ctx.assert_path_default_behavior(PathBehavior::KeepUnsafe);

        ctx.assert_command_success("r complete t t_complete o path setpolicy keep-safe");
        ctx.assert_path_default_behavior(PathBehavior::KeepSafe);

        debug!("=====");
        ctx.assert_command_success("r complete t t_complete o path setpolicy inherit");
        ctx.assert_path_default_behavior(PathBehavior::Inherit);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_whitelist_add() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_path_whitelist_add");

        // Test whitelist add
        ctx.assert_command_success("r complete t t_complete o path whitelist add /usr/bin:/bin");
        ctx.assert_path_whitelist_contains("/usr/bin");
        ctx.assert_path_whitelist_contains("/bin");

        // Test whitelist del
        ctx.assert_command_success("r complete t t_complete o path whitelist del /usr/bin:/bin");
        ctx.assert_path_whitelist_not_contains("/usr/bin");
        ctx.assert_path_whitelist_not_contains("/bin");

        debug!("=====");
        // Test whitelist purge
        ctx.assert_command_success("r complete t t_complete o path whitelist purge");
        ctx.assert_path_whitelist_is_empty();

        debug!("=====");
        // Test whitelist set
        ctx.assert_command_success("r complete t t_complete o path whitelist set /usr/bin:/bin");
        ctx.assert_path_whitelist_contains("/usr/bin");
        ctx.assert_path_whitelist_contains("/bin");
        ctx.assert_path_whitelist_len(2);

        debug!("=====");
        // Test blacklist set
        ctx.assert_command_success("r complete t t_complete o path blacklist set /usr/bin:/bin");

        debug!("=====");
        // Test blacklist add
        ctx.assert_command_success("r complete t t_complete o path blacklist add /tmp");
        ctx.assert_path_blacklist_contains("/tmp");

        // Test blacklist del
        ctx.assert_command_success("r complete t t_complete o path blacklist del /usr/bin:/bin");
        ctx.assert_path_blacklist_len(1);
        ctx.assert_path_blacklist_contains("/tmp");
        ctx.assert_path_blacklist_not_contains("/usr/bin");
        ctx.assert_path_blacklist_not_contains("/bin");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_blacklist_purge() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_path_blacklist_purge");

        ctx.assert_command_success("r complete t t_complete o path blacklist purge");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_keep_only_myvar_var2() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_keep_only_MYVAR_VAR2");

        ctx.assert_command_success("r complete t t_complete o env keep-only MYVAR,VAR2");
        ctx.assert_env_default_behavior_is_delete();
        ctx.assert_env_keep_contains("MYVAR");
        ctx.assert_env_keep_contains("VAR2");
        ctx.assert_env_keep_len(2);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_delete_only_myvar_var2() {
        let (ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_delete_only_MYVAR_VAR2");

        ctx.assert_command_success("r complete t t_complete o env delete-only MYVAR,VAR2");
        ctx.assert_env_default_behavior_is_keep();
        ctx.assert_env_delete_contains("MYVAR");
        ctx.assert_env_delete_contains("VAR2");
        ctx.assert_env_delete_len(2);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_set_myvar_value_var2_value2() {
        let (ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_set_MYVAR_value_VAR2_value2");

        ctx.assert_command_success(
            r#"r complete t t_complete o env set MYVAR=value,VAR2="value2""#,
        );
        ctx.assert_env_set_key_value("MYVAR", "value");
        ctx.assert_env_set_key_value("VAR2", "value2");
        ctx.assert_env_set_len(2);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_add_myvar_value_var2_value2() {
        let (ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_add_MYVAR_value_VAR2_value2");

        // Test setlist set
        ctx.assert_command_success(r#"r complete t t_complete o env setlist set VAR3=value3"#);

        // Test setlist add
        ctx.assert_command_success(
            r#"r complete t t_complete o env setlist add MYVAR=value,VAR2="value2""#,
        );
        ctx.assert_env_set_key_value("MYVAR", "value");
        ctx.assert_env_set_key_value("VAR2", "value2");
        ctx.assert_env_set_key_value("VAR3", "value3");
        ctx.assert_env_set_len(3);

        // Test setlist del
        ctx.assert_command_success(r#"r complete t t_complete o env setlist del MYVAR,VAR2"#);
        ctx.assert_env_set_len(1);
        ctx.assert_env_set_key_not_exists("MYVAR");
        ctx.assert_env_set_key_not_exists("VAR2");

        // Test setlist purge
        ctx.assert_command_success(r#"r complete t t_complete o env setlist purge"#);
        ctx.assert_env_set_is_none();
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_delete_all() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_setpolicy_delete_all");

        ctx.assert_command_success("r complete t t_complete o env setpolicy delete-all");
        ctx.assert_env_default_behavior(EnvBehavior::Delete);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_keep_all() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_setpolicy_keep_all");

        ctx.assert_command_success("r complete t t_complete o env setpolicy keep-all");
        ctx.assert_env_default_behavior(EnvBehavior::Keep);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_inherit() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_setpolicy_inherit");

        ctx.assert_command_success("r complete t t_complete o env setpolicy inherit");
        ctx.assert_env_default_behavior(EnvBehavior::Inherit);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_whitelist_add_myvar() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_whitelist_add_MYVAR");

        // Test whitelist add
        ctx.assert_command_success("r complete t t_complete o env whitelist add MYVAR");
        ctx.assert_env_keep_contains("MYVAR");
        // Note: Length > 1 suggests there are default environment variables

        // Test whitelist del
        ctx.assert_command_success("r complete t t_complete o env whitelist del MYVAR");
        ctx.assert_env_keep_not_contains("MYVAR");

        debug!("=====");
        // Test whitelist set
        ctx.assert_command_success("r complete t t_complete o env whitelist set MYVAR");
        ctx.assert_env_keep_contains("MYVAR");
        ctx.assert_env_keep_len(1);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_whitelist_purge() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_whitelist_purge");

        ctx.assert_command_success("r complete t t_complete o env whitelist purge");
        ctx.assert_env_keep_is_none();
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_add_myvar() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_blacklist_add_MYVAR");

        // Test blacklist add
        ctx.assert_command_success("r complete t t_complete o env blacklist add MYVAR");
        ctx.assert_env_delete_contains("MYVAR");

        // Test blacklist del
        ctx.assert_command_success("r complete t t_complete o env blacklist del MYVAR");
        ctx.assert_env_delete_not_contains("MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_set_myvar() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_blacklist_set_MYVAR");

        ctx.assert_command_success("r complete t t_complete o env blacklist set MYVAR");
        ctx.assert_env_delete_contains("MYVAR");
        ctx.assert_env_delete_len(1);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_purge() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_blacklist_purge");

        ctx.assert_command_success("r complete t t_complete o env blacklist purge");
        ctx.assert_env_delete_is_none();
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_checklist_add_myvar() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_checklist_add_MYVAR");

        // Test checklist add
        ctx.assert_command_success("r complete t t_complete o env checklist add MYVAR");
        ctx.assert_env_check_contains("MYVAR");

        debug!("=====");
        // Test checklist del
        ctx.assert_command_success("r complete t t_complete o env checklist del MYVAR");
        ctx.assert_env_check_not_contains("MYVAR");

        debug!("=====");
        // Test checklist set
        ctx.assert_command_success("r complete t t_complete o env checklist set MYVAR");
        ctx.assert_env_check_contains("MYVAR");
        ctx.assert_env_check_len(1);

        debug!("=====");
        // Test checklist purge
        ctx.assert_command_success("r complete t t_complete o env checklist purge");
        ctx.assert_env_check_is_none();
    }
    #[test]
    fn test_r_complete_t_t_complete_o_root_privileged() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_root_privileged");

        // Test root privileged
        ctx.assert_command_success("r complete t t_complete o root privileged");
        ctx.assert_root_option(&Some(SPrivileged::Privileged));

        debug!("=====");
        // Test root user
        ctx.assert_command_success("r complete t t_complete o root user");
        ctx.assert_root_option(&Some(SPrivileged::User));

        debug!("=====");
        // Test root unset
        ctx.assert_command_success("r complete t t_complete o root unset");
        ctx.assert_root_option(&None);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_bounding_strict() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_bounding_strict");

        ctx.assert_command_success("r complete t t_complete o bounding strict");
        ctx.assert_bounding_option(&Some(SBounding::Strict));
    }
    #[test]
    fn test_r_complete_t_t_complete_o_bounding_ignore() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_bounding_ignore");

        ctx.assert_command_success("r complete t t_complete o bounding ignore");
        ctx.assert_bounding_option(&Some(SBounding::Ignore));
    }
    #[test]
    fn test_r_complete_t_t_complete_o_bounding_inherit() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_bounding_inherit");

        ctx.assert_command_success("r complete t t_complete o bounding unset");
        ctx.assert_bounding_option(&None);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_auth_skip() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_auth_skip");

        // Test auth skip
        ctx.assert_command_success("r complete t t_complete o auth skip");
        ctx.assert_authentication_option(&Some(SAuthentication::Skip));

        debug!("=====");
        // Test auth perform
        ctx.assert_command_success("r complete t t_complete o auth perform");
        ctx.assert_authentication_option(&Some(SAuthentication::Perform));

        debug!("=====");
        // Test auth unset
        ctx.assert_command_success("r complete t t_complete o auth unset");
        ctx.assert_authentication_option(&None);
    }

    #[test]
    fn test_r_complete_t_t_complete_o_execinfo() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_execinfo");

        // Test execinfo set
        ctx.assert_command_success("r complete t t_complete o execinfo show");
        ctx.assert_execinfo_option(&Some(SInfo::Show));

        ctx.assert_command_success("r complete t t_complete o execinfo hide");
        ctx.assert_execinfo_option(&Some(SInfo::Hide));

        debug!("=====");
        // Test execinfo unset
        ctx.assert_command_success("r complete t t_complete o execinfo unset");
        ctx.assert_execinfo_option(&None);
    }

    #[test]
    fn test_r_complete_t_t_complete_o_umask() {
        let (ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_umask");

        // Test umask set
        ctx.assert_command_success("r complete t t_complete o umask 027");
        ctx.assert_umask_option(&Some(0o27.into()));

        debug!("=====");
        // Test umask unset
        ctx.assert_command_success("r complete t t_complete o umask unset");
        ctx.assert_umask_option(&None);
    }

    fn normalize_json_object(value: Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut sorted_map = Map::new();
                let mut sorted_entries: Vec<_> = map.into_iter().collect();
                sorted_entries.sort_by(|a, b| a.0.cmp(&b.0));

                for (key, val) in sorted_entries {
                    sorted_map.insert(key, normalize_json_object(val));
                }
                Value::Object(sorted_map)
            }
            Value::Array(arr) => Value::Array(arr.into_iter().map(normalize_json_object).collect()),
            other => other,
        }
    }

    #[test]
    fn test_convert() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();
        let (ctx, _defer) = TestContext::new("convert");

        ctx.assert_command_success(&format!("convert cbor {}.convert.bin", ROOTASROLE));
        ctx.assert_command_success(&format!("convert json {}.convert.json.1", ROOTASROLE));

        assert!(fs::metadata(format!("{}.convert.bin", ROOTASROLE)).is_ok());

        ctx.assert_command_success(&format!(
            "convert --from cbor {0}.convert.bin json {0}.convert.json",
            ROOTASROLE
        ));
        assert!(fs::metadata(format!("{}.convert.json", ROOTASROLE)).is_ok());
        assert_eq!(
            normalize_json_object(
                serde_json::from_str::<Value>(
                    &fs::read_to_string(format!("{}.convert.json", ROOTASROLE)).unwrap()
                )
                .unwrap()
            ),
            normalize_json_object(
                serde_json::from_str::<Value>(
                    &fs::read_to_string(format!("{}.convert.json.1", ROOTASROLE)).unwrap()
                )
                .unwrap()
            )
        );

        ctx.assert_command_success(&format!(
            "convert --reconfigure cbor {}.reconfigure.convert.bin",
            ROOTASROLE
        ));

        assert_eq!(
            ctx.settings
                .as_ref()
                .borrow()
                .storage
                .settings
                .as_ref()
                .unwrap()
                .path
                .as_ref()
                .unwrap()
                .to_str()
                .unwrap(),
            format!("{}.reconfigure.convert.bin", ROOTASROLE)
        );

        fs::remove_file(format!("{}.convert.bin", ROOTASROLE)).unwrap();
        fs::remove_file(format!("{}.convert.json", ROOTASROLE)).unwrap();
    }
}
