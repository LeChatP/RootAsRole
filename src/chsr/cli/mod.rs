pub mod data;
#[cfg(not(tarpaulin_include))]
#[cfg(feature = "editor")]
pub mod editor;
pub mod pair;
pub mod process;
//TODO: UI miri tests
#[cfg(not(tarpaulin_include))]
pub mod usage;

use std::{error::Error, path::PathBuf};

use bon::builder;
use data::{Cli, InputAction, Inputs, Rule};

use landlock::RulesetStatus;
use log::debug;
use pair::recurse_pair;
use pest::Parser;
use process::process_input;
use rootasrole_core::file::FileSettings;
use usage::print_usage;

use crate::{cli::editor::start_editing, util::escape_parser_string_vec};

/// What chsr does without the policy: print the usage for `--help`, or when the arguments
/// cannot be parsed. `None` when the arguments need the policy, which chsr then reads.
pub fn usage_without_policy<I, S>(args: I) -> Option<Result<bool, Box<dyn Error>>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args = escape_parser_string_vec(args);
    let pairs = match Cli::parse(Rule::cli, &args) {
        Ok(pairs) => pairs,
        Err(e) => return Some(print_usage(e)),
    };
    let mut inputs = Inputs::default();
    for pair in pairs {
        if let Err(e) = recurse_pair(pair, &mut inputs) {
            return Some(Err(e));
        }
    }
    (inputs.action == InputAction::Help).then(|| {
        usage::help();
        Ok(false)
    })
}

#[builder]
pub fn main<I, S>(
    #[builder(start_fn)] storage: &mut FileSettings,
    #[builder(start_fn)] args: I,
    #[builder(default = &RulesetStatus::NotEnforced)] ruleset: &RulesetStatus,
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
    debug!("Inputs : {inputs:?}");
    if inputs.editor {
        if ruleset == &RulesetStatus::NotEnforced {
            return Err("Editor mode requires landlock to be enforced.".into());
        }
        if let Some(path) = inputs.editor_path {
            if let Some(storage) = storage.get(&path) {
                return start_editing(&path, &mut *storage.as_ref().borrow_mut());
            }
            let file = FileSettings::read_policy(&path, inputs.editor_type.unwrap_or_default())?;
            return start_editing(&path, &mut *file.data.data.as_ref().borrow_mut());
        }
        return start_editing(
            folder.ok_or("the editor needs a temporary folder")?,
            &mut *storage.get_root_mut(),
        );
    }
    process_input(storage, inputs)
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, fs, rc::Rc};

    use indexmap::IndexSet;
    use jiff::SignedDuration;
    use rootasrole_core::{
        RemoteStorageSettings, SettingsContent,
        database::{
            actor::{SActor, SGroups},
            options::*,
            structs::{SCredentials, *},
        },
        file::RootSettings,
        util::StorageMethod,
    };
    use serde_json::{Map, Value};

    use crate::util::RAR_CFG_PATH;

    use super::*;
    use capctl::Cap;
    use log::error;
    use test_log::test;

    pub struct Defer<F: FnOnce()>(Option<F>);

    impl<F: FnOnce()> Defer<F> {
        pub fn new(f: F) -> Self {
            Self(Some(f))
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
        settings: FileSettings,
        role_index: usize,
        task_index: usize,
    }

    impl TestContext {
        fn new(name: &str) -> (Self, Defer<impl FnOnce()>) {
            let defer = setup(name);
            let path = format!("{RAR_CFG_PATH}.{name}");
            let settings = FileSettings::write_all(path.clone(), path, StorageMethod::JSON)
                .expect("should work");
            (
                Self {
                    settings,
                    role_index: 0,
                    task_index: 0,
                },
                defer,
            )
        }

        fn run_command(&mut self, command: &str) -> Result<bool, Box<dyn Error>> {
            main(&mut self.settings, command.split(' '))
                .call()
                .inspect_err(|e| error!("{e}"))
                .inspect(|e| debug!("{e}"))
        }

        fn assert_command_success(&mut self, command: &str) {
            assert!(self.run_command(command).expect("Command should not fail"));
        }

        fn assert_command_no_change(&mut self, command: &str) {
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
                    let settings_ref = self.settings.get_root();
                    let config_ref = settings_ref.config.as_ref().borrow();
                    config_ref.options.as_ref().unwrap().clone()
                }
                _ => panic!("Invalid level"),
            }
        }

        fn get_role(&self, role_index: usize) -> Rc<RefCell<SRole>> {
            let settings_ref = self.settings.get_root();
            let config_ref = settings_ref.config.as_ref().borrow();
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
            });
        }

        fn assert_actor_not_exists(&self, actor: &SActor) {
            self.with_role_actors(|actors| {
                assert!(!actors.contains(actor));
            });
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
            });
        }

        fn assert_command_contains(&self, command: &SCommand) {
            self.with_task_commands(|commands| {
                assert!(commands.add.contains(command));
            });
        }

        fn assert_command_not_contains(&self, command: &SCommand) {
            self.with_task_commands(|commands| {
                assert!(!commands.add.contains(command));
            });
        }

        fn assert_command_blacklist_contains(&self, command: &SCommand) {
            self.with_task_commands(|commands| {
                assert!(commands.sub.contains(command));
            });
        }

        fn assert_command_blacklist_not_contains(&self, command: &SCommand) {
            self.with_task_commands(|commands| {
                assert!(!commands.sub.contains(command));
            });
        }

        fn run_command_vec(&mut self, args: Vec<&str>) -> Result<bool, Box<dyn Error>> {
            main(&mut self.settings, args)
                .call()
                .inspect_err(|e| error!("{e}"))
                .inspect(|e| debug!("{e}"))
        }

        fn assert_command_vec_success(&mut self, args: Vec<&str>) {
            assert!(self.run_command_vec(args).expect("Command should not fail"));
        }

        fn assert_capability_default_behavior_is_none(&self) {
            self.with_task_capabilities(|caps| {
                assert!(caps.unwrap().default_behavior.is_none());
            });
        }

        fn assert_capability_has(&self, cap: Cap) {
            self.with_task_capabilities(|caps| {
                assert!(caps.unwrap().add.has(cap));
            });
        }

        fn assert_capability_sub_size(&self, expected: usize) {
            self.with_task_capabilities(|caps| {
                assert_eq!(caps.unwrap().sub.size(), expected);
            });
        }

        fn assert_capability_add_size(&self, expected: usize) {
            self.with_task_capabilities(|caps| {
                assert_eq!(caps.unwrap().add.size(), expected);
            });
        }

        fn assert_capability_add_is_empty(&self) {
            self.with_task_capabilities(|caps| {
                assert!(caps.unwrap().add.is_empty());
            });
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
            });
        }

        fn assert_capability_sub_has(&self, cap: Cap) {
            self.with_task_capabilities(|caps| {
                assert!(caps.unwrap().sub.has(cap));
            });
        }

        fn assert_capability_add_not_has(&self, cap: Cap) {
            self.with_task_capabilities(|caps| {
                assert!(!caps.unwrap().add.has(cap));
            });
        }

        fn assert_capability_sub_not_has(&self, cap: Cap) {
            self.with_task_capabilities(|caps| {
                assert!(!caps.unwrap().sub.has(cap));
            });
        }

        fn with_path_options<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&SPathOptions) -> R,
        {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            f(task_ref.path.as_ref().unwrap())
        }

        fn assert_path_default_behavior(&self, expected: PathBehavior) {
            self.with_path_options(|path_options| {
                assert_eq!(path_options.default_behavior, expected);
            });
        }

        fn assert_path_whitelist_contains(&self, path: &str) {
            self.with_path_options(|path_options| {
                let default = IndexSet::new();
                assert!(
                    path_options
                        .add
                        .as_ref()
                        .unwrap_or(&default)
                        .contains(&path.to_string())
                );
            });
        }

        fn assert_path_whitelist_not_contains(&self, path: &str) {
            self.with_path_options(|path_options| {
                let default = IndexSet::new();
                assert!(
                    !path_options
                        .add
                        .as_ref()
                        .unwrap_or(&default)
                        .contains(&path.to_string())
                );
            });
        }

        fn assert_path_blacklist_contains(&self, path: &str) {
            self.with_path_options(|path_options| {
                let default = IndexSet::new();
                assert!(
                    path_options
                        .sub
                        .as_ref()
                        .unwrap_or(&default)
                        .contains(&path.to_string())
                );
            });
        }

        fn assert_path_blacklist_not_contains(&self, path: &str) {
            self.with_path_options(|path_options| {
                let default = IndexSet::new();
                assert!(
                    !path_options
                        .sub
                        .as_ref()
                        .unwrap_or(&default)
                        .contains(&path.to_string())
                );
            });
        }

        fn assert_path_whitelist_is_empty(&self) {
            self.assert_path_whitelist_len(0);
        }

        fn assert_path_whitelist_len(&self, expected: usize) {
            self.with_path_options(|path_options| {
                let default = IndexSet::new();
                assert_eq!(
                    path_options.add.as_ref().unwrap_or(&default).len(),
                    expected
                );
            });
        }

        fn assert_path_blacklist_len(&self, expected: usize) {
            self.with_path_options(|path_options| {
                let default = IndexSet::new();
                assert_eq!(
                    path_options.sub.as_ref().unwrap_or(&default).len(),
                    expected
                );
            });
        }

        fn with_workdir_set<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&SWorkdirSet) -> R,
        {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            let workdir = task_ref.workdir.as_ref().expect("workdir expected");
            match workdir {
                SWorkdirEither::Struct(workdir_set) => f(workdir_set),
                SWorkdirEither::Path(_) => panic!("workdir set expected"),
            }
        }

        fn assert_workdir_is_path(&self, expected: &str) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            let workdir = task_ref.workdir.as_ref().expect("workdir expected");
            match workdir {
                SWorkdirEither::Path(path) => assert_eq!(path, expected),
                SWorkdirEither::Struct(workdir_set) => {
                    assert_eq!(workdir_set.fallback.as_deref(), Some(expected));
                }
            }
        }

        fn assert_workdir_default_behavior(&self, expected: WorkdirBehavior) {
            self.with_workdir_set(|workdir_set| {
                assert_eq!(workdir_set.default_behavior, expected);
            });
        }

        fn assert_workdir_whitelist_contains(&self, path: &str) {
            self.with_workdir_set(|workdir_set| {
                let default = IndexSet::new();
                assert!(
                    workdir_set
                        .add
                        .as_ref()
                        .unwrap_or(&default)
                        .contains(&path.to_string())
                );
            });
        }

        fn assert_workdir_whitelist_not_contains(&self, path: &str) {
            self.with_workdir_set(|workdir_set| {
                let default = IndexSet::new();
                assert!(
                    !workdir_set
                        .add
                        .as_ref()
                        .unwrap_or(&default)
                        .contains(&path.to_string())
                );
            });
        }

        fn assert_workdir_blacklist_contains(&self, path: &str) {
            self.with_workdir_set(|workdir_set| {
                let default = IndexSet::new();
                assert!(
                    workdir_set
                        .sub
                        .as_ref()
                        .unwrap_or(&default)
                        .contains(&path.to_string())
                );
            });
        }

        fn assert_workdir_blacklist_not_contains(&self, path: &str) {
            self.with_workdir_set(|workdir_set| {
                let default = IndexSet::new();
                assert!(
                    !workdir_set
                        .sub
                        .as_ref()
                        .unwrap_or(&default)
                        .contains(&path.to_string())
                );
            });
        }

        fn assert_workdir_whitelist_is_empty(&self) {
            self.assert_workdir_whitelist_len(0);
        }

        fn assert_workdir_whitelist_len(&self, expected: usize) {
            self.with_workdir_set(|workdir_set| {
                let default = IndexSet::new();
                assert_eq!(workdir_set.add.as_ref().unwrap_or(&default).len(), expected);
            });
        }

        fn assert_workdir_blacklist_len(&self, expected: usize) {
            self.with_workdir_set(|workdir_set| {
                let default = IndexSet::new();
                assert_eq!(workdir_set.sub.as_ref().unwrap_or(&default).len(), expected);
            });
        }

        fn with_env_options<F, R>(&self, f: F) -> R
        where
            F: FnOnce(&SEnvOptions) -> R,
        {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            f(task_ref.env.as_ref().unwrap())
        }

        fn assert_env_default_behavior_is_delete(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.default_behavior.is_delete());
            });
        }

        fn assert_env_default_behavior_is_keep(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.default_behavior.is_keep());
            });
        }

        fn assert_env_default_behavior(&self, expected: EnvBehavior) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.default_behavior, expected);
            });
        }

        fn assert_env_keep_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(
                    env_options
                        .keep
                        .as_ref()
                        .unwrap()
                        .contains::<EnvKey>(&var.to_string().into())
                );
            });
        }

        fn assert_env_keep_len(&self, expected: usize) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.keep.as_ref().unwrap().len(), expected);
            });
        }

        fn assert_env_delete_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(
                    env_options
                        .delete
                        .as_ref()
                        .unwrap()
                        .contains::<EnvKey>(&var.to_string().into())
                );
            });
        }

        fn assert_env_delete_len(&self, expected: usize) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.delete.as_ref().unwrap().len(), expected);
            });
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
            });
        }

        fn assert_env_set_len(&self, expected: usize) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.set.as_ref().unwrap().len(), expected);
            });
        }

        fn assert_env_set_is_none(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.set.is_none());
            });
        }

        fn assert_env_set_key_not_exists(&self, key: &str) {
            self.with_env_options(|env_options| {
                assert!(
                    env_options
                        .set
                        .as_ref()
                        .unwrap()
                        .get_key_value(key)
                        .is_none()
                );
            });
        }

        fn assert_env_keep_not_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(
                    !env_options
                        .keep
                        .as_ref()
                        .unwrap()
                        .contains::<EnvKey>(&var.to_string().into())
                );
            });
        }

        fn assert_env_keep_is_none(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.keep.is_none());
            });
        }

        fn assert_env_delete_not_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(
                    !env_options
                        .delete
                        .as_ref()
                        .unwrap()
                        .contains::<EnvKey>(&var.to_string().into())
                );
            });
        }

        fn assert_env_delete_is_none(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.delete.is_none());
            });
        }

        fn assert_env_check_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(
                    env_options
                        .check
                        .as_ref()
                        .unwrap()
                        .contains::<EnvKey>(&var.to_string().into())
                );
            });
        }

        fn assert_env_check_not_contains(&self, var: &str) {
            self.with_env_options(|env_options| {
                assert!(
                    !env_options
                        .check
                        .as_ref()
                        .unwrap()
                        .contains::<EnvKey>(&var.to_string().into())
                );
            });
        }

        fn assert_env_check_len(&self, expected: usize) {
            self.with_env_options(|env_options| {
                assert_eq!(env_options.check.as_ref().unwrap().len(), expected);
            });
        }

        fn assert_env_check_is_none(&self) {
            self.with_env_options(|env_options| {
                assert!(env_options.check.is_none());
            });
        }

        // Root option helpers
        fn assert_root_option(&self, expected: Option<&SPrivileged>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.root.as_ref(), expected);
        }

        // Bounding option helpers
        fn assert_bounding_option(&self, expected: Option<&SBounding>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.bounding.as_ref(), expected);
        }

        // Authentication option helpers
        fn assert_authentication_option(&self, expected: Option<&SAuthentication>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.authentication.as_ref(), expected);
        }

        // Execinfo option helpers
        fn assert_execinfo_option(&self, expected: Option<&SInfo>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.execinfo.as_ref(), expected);
        }

        // SUMask option helpers
        fn assert_umask_option(&self, expected: Option<&SUMask>) {
            let settings_ref = self.opt(Level::Task);
            let task_ref = settings_ref.as_ref().borrow();
            assert_eq!(task_ref.umask.as_ref(), expected);
        }
    }

    #[allow(clippy::too_many_lines)]
    fn setup(name: &str) -> Defer<impl FnOnce()> {
        let file_path = format!("{RAR_CFG_PATH}.{name}");
        println!("Setting up test with file path: {file_path}");
        let mut versionned = FileSettings::builder()
            .root(
                file_path.clone().into(),
                RootSettings::builder()
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
                        SPolicy::builder()
                            .options(|opt| {
                                opt.timeout(
                                    STimeout::builder()
                                        .type_field(TimestampType::PPID)
                                        .duration(
                                            SignedDuration::from_hours(15)
                                                .checked_add(SignedDuration::from_mins(30))
                                                .unwrap()
                                                .checked_add(SignedDuration::from_secs(30))
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
                                                    SignedDuration::from_hours(15)
                                                        .checked_add(SignedDuration::from_mins(30))
                                                        .unwrap()
                                                        .checked_add(SignedDuration::from_secs(30))
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
                                                            SignedDuration::from_hours(15)
                                                                .checked_add(
                                                                    SignedDuration::from_mins(30),
                                                                )
                                                                .unwrap()
                                                                .checked_add(
                                                                    SignedDuration::from_secs(30),
                                                                )
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
            )
            .unwrap()
            .build();
        versionned.save_all().unwrap();
        defer(move || {
            std::fs::remove_file(file_path).unwrap();
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

    // chsr o workdir set /home/user
    // chsr o workdir setpolicy (all|none|inherit)
    // chsr o workdir (whitelist|blacklist) (add|del|set|purge) /home/user/**

    #[test]
    fn test_usage_without_policy() {
        // printed without the policy
        assert!(matches!(usage_without_policy(["--help"]), Some(Ok(false))));
        assert!(matches!(usage_without_policy(["-h"]), Some(Ok(false))));
        assert!(matches!(
            usage_without_policy(["not-a-command"]),
            Some(Err(_))
        ));
        // these need the policy
        assert!(usage_without_policy(["list"]).is_none());
        assert!(usage_without_policy(["role", "r", "add"]).is_none());
        assert!(usage_without_policy(["upgrade"]).is_none());
    }

    /// The policy as saved in the file of the test `name`, which must load again (parsed, not
    /// opened: the test still holds the lock of the file).
    fn saved_policy(ctx: &mut TestContext, name: &str) -> Value {
        ctx.settings.save_all().unwrap();
        let content = fs::read_to_string(format!("{RAR_CFG_PATH}.{name}")).unwrap();
        serde_json::from_str::<RootSettings>(&content).expect("the saved policy loads again");
        serde_json::from_str(&content).unwrap()
    }

    fn saved_role<'v>(saved: &'v Value, role: &str) -> &'v Value {
        saved["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == role)
            .unwrap()
    }

    fn saved_task<'v>(saved: &'v Value, role: &str, task: &str) -> &'v Value {
        saved_role(saved, role)["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == task)
            .unwrap()
    }

    #[test]
    fn test_new_options_hold_only_what_is_set() {
        let name = "new_options_hold_only_what_is_set";
        let (mut ctx, _defer) = TestContext::new(name);
        ctx.settings.get_root().config.as_ref().borrow_mut().options = None;
        ctx.assert_command_success("o bounding strict");
        ctx.assert_command_success("r fresh create");
        ctx.assert_command_success("r fresh o root user");
        ctx.assert_command_success("r fresh t t1 add");
        ctx.assert_command_success("r fresh t t1 o path whitelist add /opt/bin");
        let saved = saved_policy(&mut ctx, name);
        // the other options stay inherited, not written with the built-in defaults
        assert_eq!(saved["options"], serde_json::json!({"bounding": "strict"}));
        assert_eq!(
            saved_role(&saved, "fresh")["options"],
            serde_json::json!({"root": "user"})
        );
        assert_eq!(
            saved_task(&saved, "fresh", "t1")["options"],
            serde_json::json!({"path": {"add": ["/opt/bin"]}})
        );
    }

    #[test]
    fn test_list_edits_on_a_level_without_the_option() {
        let name = "list_edits_on_a_level_without_the_option";
        let (mut ctx, _defer) = TestContext::new(name);
        ctx.assert_command_success("r fresh create");
        ctx.assert_command_success("r fresh t t1 add");
        ctx.assert_command_success("r fresh t t1 o env whitelist add MYVAR");
        ctx.assert_command_success("r fresh t t1 o env checklist add TZ");
        ctx.assert_command_success("r fresh o path blacklist add /tmp");
        // removing from a list that the level does not define changes nothing
        ctx.assert_command_success("r fresh o env blacklist del LD_PRELOAD");
        ctx.assert_command_success("r fresh t t1 o path whitelist del /usr/bin");
        let saved = saved_policy(&mut ctx, name);
        assert_eq!(
            saved_task(&saved, "fresh", "t1")["options"],
            serde_json::json!({"env": {"keep": ["MYVAR"], "check": ["TZ"]}})
        );
        assert_eq!(
            saved_role(&saved, "fresh")["options"],
            serde_json::json!({"path": {"sub": ["/tmp"]}})
        );
    }

    #[test]
    fn test_options_timeout() {
        let name = "options_timeout";
        let (mut ctx, _defer) = TestContext::new(name);
        // set changes the fields given and keeps the others
        ctx.assert_command_success("o timeout set --type tty");
        ctx.assert_command_success("o timeout set -d 5:00");
        assert_eq!(
            saved_policy(&mut ctx, name)["options"]["timeout"],
            serde_json::json!({"type": "tty", "duration": "00:05:00", "max_usage": 1})
        );
        // unset removes the fields named, then the option once nothing is left
        ctx.assert_command_success("o timeout unset --max-usage");
        assert_eq!(
            saved_policy(&mut ctx, name)["options"]["timeout"],
            serde_json::json!({"type": "tty", "duration": "00:05:00"})
        );
        ctx.assert_command_success("o timeout unset --type --duration");
        assert!(
            saved_policy(&mut ctx, name)["options"]
                .get("timeout")
                .is_none()
        );
        // a field that this version does not know is kept
        ctx.opt(Level::Role)
            .as_ref()
            .borrow_mut()
            .timeout
            .as_mut()
            .unwrap()
            .extra_fields
            .insert("future".into(), Value::from(1));
        ctx.assert_command_success("r complete o timeout unset --type --duration --max-usage");
        ctx.assert_command_success("r complete o timeout set --max-usage 3");
        // a level without the option
        ctx.assert_command_success("r fresh create");
        ctx.assert_command_success("r fresh o timeout set --type uid");
        // refused, without a change
        for command in [
            "o timeout set --type",
            "o timeout set --duration",
            "o timeout set --max-usage",
        ] {
            assert!(ctx.run_command(command).is_err(), "{command}");
        }
        ctx.assert_command_no_change("r complete t t_complete o show timeout");
        let saved = saved_policy(&mut ctx, name);
        assert!(saved["options"].get("timeout").is_none());
        assert_eq!(
            saved_role(&saved, "complete")["options"]["timeout"],
            serde_json::json!({"max_usage": 3, "future": 1})
        );
        assert_eq!(
            saved_role(&saved, "fresh")["options"],
            serde_json::json!({"timeout": {"type": "uid"}})
        );
    }

    #[test]
    fn test_options_env_names() {
        let name = "options_env_names";
        let (mut ctx, _defer) = TestContext::new(name);
        // one letter and patterns, like the policy accepts
        ctx.assert_command_success("o env whitelist add A");
        ctx.assert_command_success("o env whitelist add LC_*,*_PROXY");
        ctx.assert_command_success("o env setlist add Z=1");
        // a name that the policy refuses is an error, not a panic
        for command in [
            "o env whitelist add MY-VAR",
            "o env whitelist add 1VAR",
            "o env setlist add BAD*=1",
        ] {
            assert!(ctx.run_command(command).is_err(), "{command}");
        }
        let saved = saved_policy(&mut ctx, name);
        assert_eq!(
            saved["options"]["env"]["keep"],
            serde_json::json!(["env1", "env2", "A", "LC_*", "*_PROXY"])
        );
        assert_eq!(saved["options"]["env"]["set"]["Z"], "1");
        assert!(saved["options"]["env"]["set"].get("BAD*").is_none());
    }

    #[test]
    fn test_options_show_every_option_at_every_level() {
        let (mut ctx, _defer) = TestContext::new("options_show_every_option_at_every_level");
        for level in ["", "r complete ", "r complete t t_complete "] {
            for option in [
                "",
                "all",
                "path",
                "env",
                "root",
                "bounding",
                "timeout",
                "password",
                "authentication",
                "auth",
                "execinfo",
                "info",
                "umask",
                "mask",
                "workdir",
            ] {
                ctx.assert_command_no_change(format!("{level}o show {option}").trim_end());
            }
            // not options: refused, never a panic
            for option in ["cmd", "cred"] {
                assert!(ctx.run_command(&format!("{level}o show {option}")).is_err());
            }
        }
    }

    #[test]
    fn test_missing_targets_are_errors() {
        let (mut ctx, _defer) = TestContext::new("missing_targets_are_errors");
        for command in [
            "r complete t nope purge",
            "r complete t nope show",
            "r nope t t1 purge",
            "r nope o root user",
            "r complete t nope o root user",
        ] {
            assert!(ctx.run_command(command).is_err(), "{command}");
        }
        // purges that the grammar accepts, whatever they do, never panic
        for command in [
            "r complete t t_complete cmd whitelist purge",
            "r complete t t_complete cred caps whitelist purge",
            "o workdir blacklist purge",
            "o env setlist purge",
        ] {
            let _ = ctx.run_command(command);
        }
    }

    /// The paths of the fields named `future` in `value`.
    fn future_fields(value: &Value, prefix: &str, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    let path = format!("{prefix}/{key}");
                    if key == "future" {
                        out.push(path.clone());
                    }
                    future_fields(value, &path, out);
                }
            }
            Value::Array(items) => {
                for (i, value) in items.iter().enumerate() {
                    future_fields(value, &format!("{prefix}[{i}]"), out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn test_unknown_fields_survive_a_save() {
        let path = format!("{RAR_CFG_PATH}.unknown_fields_survive_a_save");
        let _cleanup = defer(|| {
            let _ = fs::remove_file(format!("{RAR_CFG_PATH}.unknown_fields_survive_a_save"));
        });
        // the credential sets (setuid, setgid, capabilities) refuse unknown fields, as dosr does
        let policy = serde_json::json!({
            "version": rootasrole_core::PACKAGE_VERSION.to_string(),
            "future": 1,
            "storage": {"method": "json", "settings": {"path": path, "future": 1}, "future": 1},
            "options": {"future": 1,
                "path": {"default": "delete", "add": ["/usr/bin"], "future": 1},
                "env": {"default": "delete", "keep": ["A"], "future": 1},
                "timeout": {"type": "tty", "future": 1},
                "password": {"tries": 3, "future": 1},
                "workdir": {"default": "all", "fallback": "/", "future": 1}},
            "roles": [{"name": "r", "future": 1,
                "actors": [{"type": "user", "id": 0, "future": 1},
                    {"type": "group", "groups": ["root"], "future": 1}],
                "options": {"future": 1, "path": {"default": "keep-safe", "future": 1}},
                "tasks": [{"name": "t", "future": 1,
                    "cred": {"future": 1,
                        "setuid": {"default": "all", "fallback": "root"},
                        "setgid": {"default": "all", "fallback": ["root"]},
                        "capabilities": {"default": "none", "add": ["CAP_NET_RAW"]}},
                    "commands": {"default": "none", "add": ["/usr/bin/ls"], "future": 1},
                    "options": {"future": 1}}]}]
        });
        fs::write(&path, serde_json::to_string_pretty(&policy).unwrap()).unwrap();
        let mut settings =
            FileSettings::write_all(path.clone(), path.clone(), StorageMethod::JSON).unwrap();
        assert!(
            main(&mut settings, "o bounding strict".split(' '))
                .call()
                .unwrap()
        );
        settings.save_all().unwrap();
        drop(settings);
        let saved: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let (mut before, mut after) = (Vec::new(), Vec::new());
        future_fields(&policy, "", &mut before);
        future_fields(&saved, "", &mut after);
        assert_eq!(before.len(), 18);
        let lost: Vec<_> = before
            .iter()
            .filter(|field| !after.contains(field))
            .collect();
        assert!(lost.is_empty(), "lost: {lost:?}");
    }

    #[test]
    fn test_purge_returns_to_inheritance() {
        let name = "purge_returns_to_inheritance";
        let (mut ctx, _defer) = TestContext::new(name);
        ctx.assert_command_success("o workdir whitelist add /srv");
        ctx.assert_command_success("o workdir blacklist add /tmp");
        // the level no longer defines the list, the upper ones apply again
        for command in [
            "o path whitelist purge",
            "o path blacklist purge",
            "o workdir whitelist purge",
            "o env checklist purge",
            "o env blacklist purge",
        ] {
            ctx.assert_command_success(command);
        }
        let policy = saved_policy(&mut ctx, name);
        let options = &policy["options"];
        assert!(options["path"].get("add").is_none(), "{options}");
        assert!(options["path"].get("sub").is_none(), "{options}");
        assert!(options["workdir"].get("add").is_none(), "{options}");
        assert_eq!(options["workdir"]["sub"], serde_json::json!(["/tmp"]));
        assert!(options["env"].get("check").is_none(), "{options}");
        assert!(options["env"].get("delete").is_none(), "{options}");
        // on a level without the option, nothing changes
        ctx.assert_command_success("r fresh create");
        ctx.assert_command_success("r fresh o path blacklist purge");
        ctx.assert_command_success("r fresh o workdir whitelist purge");
        let policy = saved_policy(&mut ctx, name);
        assert!(saved_role(&policy, "fresh").get("options").is_none());
    }

    #[test]
    fn test_env_keep_only_keeps_the_other_fields() {
        let name = "env_keep_only_keeps_the_other_fields";
        let (mut ctx, _defer) = TestContext::new(name);
        ctx.assert_command_success("o env keep-only A,B");
        let env = saved_policy(&mut ctx, name)["options"]["env"].clone();
        assert_eq!(
            env,
            serde_json::json!({
                "default": "delete",
                "keep": ["A", "B"],
                "check": ["env3", "env4"],
                "delete": ["env5", "env6"],
                "set": {"env7": "val7", "env8": "val8"}
            })
        );
        ctx.assert_command_success("o env delete-only C");
        let env = saved_policy(&mut ctx, name)["options"]["env"].clone();
        assert_eq!(env["default"], "keep");
        assert_eq!(env["delete"], serde_json::json!(["C"]));
        assert_eq!(env["keep"], serde_json::json!(["A", "B"]));
        assert_eq!(env["check"], serde_json::json!(["env3", "env4"]));
    }

    #[test]
    fn test_simple_edits_are_saved() {
        let name = "simple_edits_are_saved";
        let (mut ctx, _defer) = TestContext::new(name);
        for command in [
            "o root user",
            "o bounding strict",
            "o auth skip",
            "o info hide",
            "o umask 077",
            "r complete o root user",
            "r complete o umask 027",
            "r complete t t_complete o workdir set /srv",
            "r complete t t_complete o auth perform",
            "r complete grant -u alice -g staff&wheel",
            "r complete t t_complete cred set --setuid root --setgid root,adm",
            "r complete t t_complete cred caps whitelist add cap_net_raw",
            "r complete t t_complete cmd whitelist add /usr/bin/id -u",
            "r complete t t_complete cmd setpolicy deny-all",
            "r complete t t2 add",
        ] {
            ctx.assert_command_success(command);
        }
        let saved = saved_policy(&mut ctx, name);
        let global = &saved["options"];
        assert_eq!(global["root"], "user");
        assert_eq!(global["bounding"], "strict");
        assert_eq!(global["authentication"], "skip");
        assert_eq!(global["execinfo"], "hide");
        assert_eq!(global["umask"], "077");
        let role = saved_role(&saved, "complete");
        assert_eq!(role["options"]["root"], "user");
        assert_eq!(role["options"]["umask"], "027");
        let actors = role["actors"].as_array().unwrap();
        assert!(actors.contains(&serde_json::json!({"type": "user", "id": "alice"})));
        assert!(
            actors.contains(&serde_json::json!({"type": "group", "groups": ["staff", "wheel"]}))
        );
        let task = saved_task(&saved, "complete", "t_complete");
        assert_eq!(task["options"]["workdir"], "/srv");
        assert_eq!(task["options"]["authentication"], "perform");
        assert_eq!(task["cred"]["setuid"], "root");
        assert_eq!(task["cred"]["setgid"], serde_json::json!(["root", "adm"]));
        assert!(
            task["cred"]["capabilities"]["add"]
                .as_array()
                .unwrap()
                .contains(&Value::from("NET_RAW"))
        );
        assert_eq!(task["commands"]["default"], "none");
        assert!(
            task["commands"]["add"]
                .as_array()
                .unwrap()
                .contains(&Value::from("/usr/bin/id -u"))
        );
        assert_eq!(saved_task(&saved, "complete", "t2")["name"], "t2");
        // deletions
        for command in ["o root del", "o umask del", "r complete t t2 del"] {
            ctx.assert_command_success(command);
        }
        let saved = saved_policy(&mut ctx, name);
        assert!(saved["options"].get("root").is_none());
        assert!(saved["options"].get("umask").is_none());
        assert!(
            saved_role(&saved, "complete")["tasks"]
                .as_array()
                .unwrap()
                .iter()
                .all(|task| task["name"] != "t2")
        );
    }

    #[test]
    fn test_cred_setuid_and_setgid_forms() {
        let name = "cred_setuid_and_setgid_forms";
        let (mut ctx, _defer) = TestContext::new(name);
        for (command, setuid, setgid) in [
            (
                "r complete t t_complete cred set -u root -g adm",
                "root",
                serde_json::json!("adm"),
            ),
            (
                "r complete t t_complete cred set --setuid=nobody --setgid=root&adm",
                "nobody",
                serde_json::json!(["root", "adm"]),
            ),
            (
                "r complete t t_complete cred set --setuid daemon --setgid root,adm,staff",
                "daemon",
                serde_json::json!(["root", "adm", "staff"]),
            ),
        ] {
            ctx.assert_command_success(command);
            let saved = saved_policy(&mut ctx, name);
            let cred = &saved_task(&saved, "complete", "t_complete")["cred"];
            assert_eq!(cred["setuid"], setuid, "{command}");
            assert_eq!(cred["setgid"], setgid, "{command}");
        }
    }

    #[test]
    fn test_umask_is_octal() {
        let (mut ctx, _defer) = TestContext::new("umask_is_octal");
        for command in ["o umask 999", "o umask 1000", "o umask 7777"] {
            assert!(ctx.run_command(command).is_err(), "{command}");
        }
        assert!(ctx.opt(Level::Global).as_ref().borrow().umask.is_none());
    }

    /// A root file pointing to a policy directory holding `files`, as the Debian package and
    /// `cargo xtask install` lay them out. Returns the root file and the directory.
    fn policy_directory(
        name: &str,
        files: &[(&str, Value)],
    ) -> (String, String, impl Drop + use<>) {
        let root = format!("{RAR_CFG_PATH}.{name}");
        let dir = format!("{RAR_CFG_PATH}.{name}.d");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let version = rootasrole_core::PACKAGE_VERSION.to_string();
        fs::write(
            &root,
            serde_json::to_string_pretty(&serde_json::json!({
                "version": version,
                "storage": {"method": "json", "settings": {"path": dir, "immutable": false}}
            }))
            .unwrap(),
        )
        .unwrap();
        for (file, policy) in files {
            let mut policy = policy.clone();
            policy["version"] = Value::from(version.clone());
            fs::write(
                format!("{dir}/{file}"),
                serde_json::to_string_pretty(&policy).unwrap(),
            )
            .unwrap();
        }
        let (root_cleanup, dir_cleanup) = (root.clone(), dir.clone());
        let cleanup = defer(move || {
            let _ = fs::remove_file(&root_cleanup);
            let _ = fs::remove_dir_all(&dir_cleanup);
        });
        (root, dir, cleanup)
    }

    /// Run `command` with chsr on the policy of `root`, and save it like chsr does.
    fn chsr_on(root: &str, command: &str) -> Result<bool, Box<dyn Error>> {
        let mut settings =
            FileSettings::write_all(root.to_string(), root.to_string(), StorageMethod::JSON)?;
        let changed = main(&mut settings, command.split(' ')).call()?;
        if changed {
            settings.save_all()?;
        }
        Ok(changed)
    }

    fn role_names(path: &str) -> Vec<String> {
        let policy: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        policy["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|role| role["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn test_policy_directory_targets_one_file() {
        let (root, dir, _cleanup) = policy_directory(
            "policy_directory_targets_one_file",
            &[
                ("default.json", serde_json::json!({"roles": []})),
                (
                    "extra.json",
                    serde_json::json!({"roles": [{"name": "x", "actors": [{"user": "root"}]}]}),
                ),
            ],
        );
        let (default, extra) = (format!("{dir}/default.json"), format!("{dir}/extra.json"));
        let root_before = fs::read_to_string(&root).unwrap();
        let extra_before = fs::read_to_string(&extra).unwrap();
        // without a file named, the role goes to default.json, the files that did not change
        // are not written again (extra.json keeps its short form)
        assert!(chsr_on(&root, "r newrole create").unwrap());
        assert_eq!(role_names(&default), ["newrole"]);
        assert_eq!(fs::read_to_string(&root).unwrap(), root_before);
        assert_eq!(fs::read_to_string(&extra).unwrap(), extra_before);
        // a file named by its name in the directory, or by its path
        let default_before = fs::read_to_string(&default).unwrap();
        assert!(chsr_on(&root, "file extra.json r other create").unwrap());
        assert!(chsr_on(&root, &format!("file {extra} r another create")).unwrap());
        assert_eq!(role_names(&extra), ["x", "other", "another"]);
        assert_eq!(fs::read_to_string(&default).unwrap(), default_before);
        assert!(chsr_on(&root, "file extra.json r x grant -u daemon").unwrap());
        // a file that is not one of the policy
        assert!(chsr_on(&root, "file nope.json r y create").is_err());
        assert!(chsr_on(&root, "file /etc/passwd r y create").is_err());
        // listings change nothing
        assert!(!chsr_on(&root, "list").unwrap());
        assert!(!chsr_on(&root, "file list").unwrap());
        assert!(!chsr_on(&root, "file extra.json list").unwrap());
        assert_eq!(fs::read_to_string(&default).unwrap(), default_before);
    }

    #[test]
    fn test_policy_directory_without_default_file() {
        let (root, dir, _cleanup) = policy_directory(
            "policy_directory_without_default_file",
            &[
                ("a.json", serde_json::json!({"roles": []})),
                ("b.json", serde_json::json!({"roles": []})),
            ],
        );
        // which file a role belongs to is not guessed
        let error = chsr_on(&root, "r y create").unwrap_err().to_string();
        assert!(error.contains("chsr file"), "{error}");
        assert!(chsr_on(&root, "file b.json r y create").unwrap());
        assert_eq!(role_names(&format!("{dir}/b.json")), ["y"]);
        assert!(role_names(&format!("{dir}/a.json")).is_empty());
    }

    /// The password option of `level`, as (tries, delay in seconds, unknown fields).
    fn password(ctx: &TestContext, level: Level) -> Option<(Option<u8>, Option<i64>, usize)> {
        ctx.opt(level)
            .as_ref()
            .borrow()
            .password
            .as_ref()
            .map(|password| {
                (
                    password.tries.map(std::num::NonZeroU8::get),
                    password.delay.map(|delay| delay.as_secs()),
                    password.extra_fields.len(),
                )
            })
    }

    #[test]
    fn test_options_password() {
        let name = "options_password";
        let (mut ctx, _defer) = TestContext::new(name);
        // at each level; set changes the fields given and keeps the others
        ctx.assert_command_success("o password set --tries 5 --delay 00:00:10");
        ctx.assert_command_success("r complete o password set --tries=4");
        ctx.assert_command_success("r complete t t_complete o password set -d 2");
        assert_eq!(password(&ctx, Level::Global), Some((Some(5), Some(10), 0)));
        assert_eq!(password(&ctx, Level::Role), Some((Some(4), None, 0)));
        assert_eq!(password(&ctx, Level::Task), Some((None, Some(2), 0)));
        ctx.assert_command_success("o password set --delay 1:00");
        assert_eq!(password(&ctx, Level::Global), Some((Some(5), Some(60), 0)));
        // unset removes the fields named, then the option once nothing is left
        ctx.assert_command_success("o password unset --tries");
        assert_eq!(password(&ctx, Level::Global), Some((None, Some(60), 0)));
        ctx.assert_command_success("o password unset -d");
        assert_eq!(password(&ctx, Level::Global), None);
        // a field that this version does not know is kept
        ctx.opt(Level::Role)
            .as_ref()
            .borrow_mut()
            .password
            .as_mut()
            .unwrap()
            .extra_fields
            .insert("future".into(), Value::from(1));
        ctx.assert_command_success("r complete o password unset --tries");
        assert_eq!(password(&ctx, Level::Role), Some((None, None, 1)));
        ctx.assert_command_success("r complete o password set --tries 4");
        assert_eq!(password(&ctx, Level::Role), Some((Some(4), None, 1)));
        // refused, without a change
        for command in [
            "o password set --tries 0",
            "o password set --tries 256",
            "o password set --tries",
            "o password set --delay",
            "o password set --delay 153722867280912930:59:59",
        ] {
            assert!(ctx.run_command(command).is_err(), "{command}");
        }
        assert_eq!(password(&ctx, Level::Global), None);
        ctx.assert_command_no_change("r complete t t_complete o show password");
        // what is saved is what dosr reads
        ctx.settings.save_all().unwrap();
        let saved: Value =
            serde_json::from_str(&fs::read_to_string(format!("{RAR_CFG_PATH}.{name}")).unwrap())
                .unwrap();
        let role = saved["roles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["name"] == "complete")
            .unwrap();
        assert_eq!(
            role["options"]["password"],
            serde_json::json!({"tries": 4, "future": 1})
        );
        let task = role["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|task| task["name"] == "t_complete")
            .unwrap();
        assert_eq!(
            task["options"]["password"],
            serde_json::json!({"delay": "00:00:02"})
        );
        assert!(saved["options"].get("password").is_none());
    }

    #[test]
    fn test_all_main() {
        let (mut ctx, _defer) = TestContext::new("all_main");

        // Test --help command (should not change anything)
        ctx.assert_command_no_change("--help");

        // Test role creation
        ctx.assert_command_success("r r1 create");

        // Test role deletion
        ctx.assert_command_success("r complete delete");
    }
    #[test]
    fn test_r_complete_show_actors() {
        let (mut ctx, _defer) = TestContext::new("r_complete_show_actors");

        // Test show commands (should not change anything)
        ctx.assert_command_no_change("r complete show actors");
        ctx.assert_command_no_change("r complete show tasks");
        ctx.assert_command_no_change("r complete show all");

        // Test purge actors command (should make changes)
        ctx.assert_command_success("r complete purge actors");
    }
    #[test]
    fn test_purge_tasks() {
        let (mut ctx, _defer) = TestContext::new("purge_tasks");

        // Test purge tasks command (should make changes)
        ctx.assert_command_success("r complete purge tasks");
    }
    #[test]
    fn test_r_complete_purge_all() {
        let (mut ctx, _defer) = TestContext::new("r_complete_purge_all");

        // Test purge all command (should make changes)
        ctx.assert_command_success("r complete purge all");
    }
    #[test]
    fn test_r_complete_grant_u_user1_g_group1_g_group2_group3() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_grant_u_user1_g_group1_g_group2_group3");

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
        let (mut ctx, _defer) = TestContext::new("r_complete_task_t_complete_show_all");

        // Test show commands (should not change anything)
        ctx.assert_command_no_change("r complete task t_complete show all");
        ctx.assert_command_no_change("r complete task t_complete show cmd");
        ctx.assert_command_no_change("r complete task t_complete show cred");

        // Test purge all command (should make changes)
        ctx.assert_command_success("r complete task t_complete purge all");
    }
    #[test]
    fn test_r_complete_task_t_complete_purge_cmd() {
        let (mut ctx, _defer) = TestContext::new("r_complete_task_t_complete_purge_cmd");

        // Test purge cmd command (should make changes)
        ctx.assert_command_success("r complete task t_complete purge cmd");
    }
    #[test]
    fn test_r_complete_task_t_complete_purge_cred() {
        let (mut ctx, _defer) = TestContext::new("r_complete_task_t_complete_purge_cred");

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
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_cmd_setpolicy_deny_all");

        ctx.assert_command_success("r complete t t_complete cmd setpolicy deny-all");
        ctx.assert_command_default_behavior(Some(SetBehavior::None));
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_setpolicy_allow_all() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_cmd_setpolicy_allow_all");

        ctx.assert_command_success("r complete t t_complete cmd setpolicy allow-all");
        ctx.assert_command_default_behavior(Some(SetBehavior::All));
    }
    #[test]
    fn test_r_complete_t_t_complete_cmd_whitelist_add_super_command_with_spaces() {
        let (mut ctx, _defer) =
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
        let (mut ctx, _defer) =
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
    fn test_r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2()
     {
        let (mut ctx, _defer) = TestContext::new(
            "r_complete_t_t_complete_cred_set_caps_cap_dac_override_cap_sys_admin_cap_sys_boot_setuid_user1_setgid_group1_group2",
        );

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
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_cred_caps_setpolicy_deny_all");

        ctx.assert_command_success("r complete t t_complete cred caps setpolicy deny-all");
        ctx.assert_capability_default_behavior(SetBehavior::None);
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_setpolicy_allow_all() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_cred_caps_setpolicy_allow_all");

        ctx.assert_command_success("r complete t t_complete cred caps setpolicy allow-all");
        ctx.assert_capability_default_behavior(SetBehavior::All);
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot()
     {
        let (mut ctx, _defer) = TestContext::new(
            "r_complete_t_t_complete_cred_caps_whitelist_add_cap_dac_override_cap_sys_admin_cap_sys_boot",
        );

        ctx.assert_command_success("r complete t t_complete cred caps whitelist add cap_dac_override cap_sys_admin cap_sys_boot");
        ctx.assert_capability_has(Cap::DAC_OVERRIDE);
        ctx.assert_capability_has(Cap::SYS_ADMIN);
        ctx.assert_capability_has(Cap::SYS_BOOT);
    }
    #[test]
    fn test_r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot()
     {
        let (mut ctx, _defer) = TestContext::new(
            "r_complete_t_t_complete_cred_caps_blacklist_add_cap_dac_override_cap_sys_admin_cap_sys_boot",
        );

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
        let (mut ctx, _defer) = TestContext::new("options_show_all");

        // Test show commands (should not change anything)
        ctx.assert_command_no_change("options show all");
        ctx.assert_command_no_change("r complete options show path");
        ctx.assert_command_no_change("r complete options show bounding");
    }
    #[test]
    fn test_r_complete_t_t_complete_options_show_env() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_options_show_env");

        // Test show commands (should not change anything)
        ctx.assert_command_no_change("r complete t t_complete options show env");
        ctx.assert_command_no_change("r complete t t_complete options show root");
        ctx.assert_command_no_change("r complete t t_complete options show bounding");

        // Test path set command (should make changes)
        ctx.assert_command_success("r complete t t_complete o path set /usr/bin:/bin");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_setpolicy_delete_all() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_path_setpolicy_delete_all");

        ctx.assert_command_success("r complete t t_complete o path setpolicy delete-all");
        ctx.assert_path_default_behavior(PathBehavior::Delete);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_path_setpolicy_keep_unsafe() {
        let (mut ctx, _defer) =
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
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_path_whitelist_add");

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
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_path_blacklist_purge");

        ctx.assert_command_success("r complete t t_complete o path blacklist purge");
    }

    #[test]
    fn test_r_complete_t_t_complete_o_workdir_set() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_workdir_set");

        ctx.assert_command_success("r complete t t_complete o workdir set /home/user");
        ctx.assert_workdir_is_path("/home/user");
    }

    #[test]
    fn test_r_complete_t_t_complete_o_workdir_setpolicy() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_workdir_setpolicy");

        ctx.assert_command_success("r complete t t_complete o workdir setpolicy all");
        ctx.assert_workdir_default_behavior(WorkdirBehavior::Blacklist);

        ctx.assert_command_success("r complete t t_complete o workdir setpolicy none");
        ctx.assert_workdir_default_behavior(WorkdirBehavior::Allowlist);

        ctx.assert_command_success("r complete t t_complete o workdir setpolicy inherit");
        ctx.assert_workdir_default_behavior(WorkdirBehavior::Inherit);
    }

    #[test]
    fn test_r_complete_t_t_complete_o_workdir_whitelist_add() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_workdir_whitelist_add");

        ctx.assert_command_success("r complete t t_complete o workdir whitelist add /home/user");
        ctx.assert_workdir_whitelist_contains("/home/user");

        ctx.assert_command_success("r complete t t_complete o workdir whitelist del /home/user");
        ctx.assert_workdir_whitelist_not_contains("/home/user");

        ctx.assert_command_success(
            "r complete t t_complete o workdir whitelist set /home/user:/tmp",
        );
        ctx.assert_workdir_whitelist_contains("/home/user");
        ctx.assert_workdir_whitelist_contains("/tmp");
        ctx.assert_workdir_whitelist_len(2);

        ctx.assert_command_success("r complete t t_complete o workdir whitelist purge");
        ctx.assert_workdir_whitelist_is_empty();
    }

    #[test]
    fn test_r_complete_t_t_complete_o_workdir_blacklist_add() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_workdir_blacklist_add");

        ctx.assert_command_success("r complete t t_complete o workdir blacklist set /home/user");
        ctx.assert_workdir_blacklist_contains("/home/user");
        ctx.assert_workdir_blacklist_len(1);

        ctx.assert_command_success("r complete t t_complete o workdir blacklist add /tmp");
        ctx.assert_workdir_blacklist_contains("/tmp");
        ctx.assert_workdir_blacklist_len(2);

        ctx.assert_command_success("r complete t t_complete o workdir blacklist del /home/user");
        ctx.assert_workdir_blacklist_not_contains("/home/user");
        ctx.assert_workdir_blacklist_contains("/tmp");
        ctx.assert_workdir_blacklist_len(1);

        ctx.assert_command_success("r complete t t_complete o workdir blacklist purge");
        ctx.assert_workdir_blacklist_len(0);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_keep_only_myvar_var2() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_keep_only_MYVAR_VAR2");

        ctx.assert_command_success("r complete t t_complete o env keep-only MYVAR,VAR2");
        ctx.assert_env_default_behavior_is_delete();
        ctx.assert_env_keep_contains("MYVAR");
        ctx.assert_env_keep_contains("VAR2");
        ctx.assert_env_keep_len(2);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_delete_only_myvar_var2() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_delete_only_MYVAR_VAR2");

        ctx.assert_command_success("r complete t t_complete o env delete-only MYVAR,VAR2");
        ctx.assert_env_default_behavior_is_keep();
        ctx.assert_env_delete_contains("MYVAR");
        ctx.assert_env_delete_contains("VAR2");
        ctx.assert_env_delete_len(2);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_set_myvar_value_var2_value2() {
        let (mut ctx, _defer) =
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
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_add_MYVAR_value_VAR2_value2");

        // Test setlist set
        ctx.assert_command_success(r"r complete t t_complete o env setlist set VAR3=value3");

        // Test setlist add
        ctx.assert_command_success(
            r#"r complete t t_complete o env setlist add MYVAR=value,VAR2="value2""#,
        );
        ctx.assert_env_set_key_value("MYVAR", "value");
        ctx.assert_env_set_key_value("VAR2", "value2");
        ctx.assert_env_set_key_value("VAR3", "value3");
        ctx.assert_env_set_len(3);

        // Test setlist del
        ctx.assert_command_success(r"r complete t t_complete o env setlist del MYVAR,VAR2");
        ctx.assert_env_set_len(1);
        ctx.assert_env_set_key_not_exists("MYVAR");
        ctx.assert_env_set_key_not_exists("VAR2");

        // Test setlist purge
        ctx.assert_command_success(r"r complete t t_complete o env setlist purge");
        ctx.assert_env_set_is_none();
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_delete_all() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_setpolicy_delete_all");

        ctx.assert_command_success("r complete t t_complete o env setpolicy delete-all");
        ctx.assert_env_default_behavior(EnvBehavior::Delete);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_keep_all() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_setpolicy_keep_all");

        ctx.assert_command_success("r complete t t_complete o env setpolicy keep-all");
        ctx.assert_env_default_behavior(EnvBehavior::Keep);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_setpolicy_inherit() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_setpolicy_inherit");

        ctx.assert_command_success("r complete t t_complete o env setpolicy inherit");
        ctx.assert_env_default_behavior(EnvBehavior::Inherit);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_whitelist_add_myvar() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_whitelist_add_MYVAR");

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
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_whitelist_purge");

        ctx.assert_command_success("r complete t t_complete o env whitelist purge");
        ctx.assert_env_keep_is_none();
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_add_myvar() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_blacklist_add_MYVAR");

        // Test blacklist add
        ctx.assert_command_success("r complete t t_complete o env blacklist add MYVAR");
        ctx.assert_env_delete_contains("MYVAR");

        // Test blacklist del
        ctx.assert_command_success("r complete t t_complete o env blacklist del MYVAR");
        ctx.assert_env_delete_not_contains("MYVAR");
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_set_myvar() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_blacklist_set_MYVAR");

        ctx.assert_command_success("r complete t t_complete o env blacklist set MYVAR");
        ctx.assert_env_delete_contains("MYVAR");
        ctx.assert_env_delete_len(1);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_blacklist_purge() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_env_blacklist_purge");

        ctx.assert_command_success("r complete t t_complete o env blacklist purge");
        ctx.assert_env_delete_is_none();
    }
    #[test]
    fn test_r_complete_t_t_complete_o_env_checklist_add_myvar() {
        let (mut ctx, _defer) =
            TestContext::new("r_complete_t_t_complete_o_env_checklist_add_MYVAR");

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
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_root_privileged");

        // Test root privileged
        ctx.assert_command_success("r complete t t_complete o root privileged");
        ctx.assert_root_option(Some(&SPrivileged::Privileged));

        debug!("=====");
        // Test root user
        ctx.assert_command_success("r complete t t_complete o root user");
        ctx.assert_root_option(Some(&SPrivileged::User));

        debug!("=====");
        // Test root unset
        ctx.assert_command_success("r complete t t_complete o root unset");
        ctx.assert_root_option(None);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_bounding_strict() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_bounding_strict");

        ctx.assert_command_success("r complete t t_complete o bounding strict");
        ctx.assert_bounding_option(Some(&SBounding::Strict));
    }
    #[test]
    fn test_r_complete_t_t_complete_o_bounding_ignore() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_bounding_ignore");

        ctx.assert_command_success("r complete t t_complete o bounding ignore");
        ctx.assert_bounding_option(Some(&SBounding::Ignore));
    }
    #[test]
    fn test_r_complete_t_t_complete_o_bounding_inherit() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_bounding_inherit");

        ctx.assert_command_success("r complete t t_complete o bounding unset");
        ctx.assert_bounding_option(None);
    }
    #[test]
    fn test_r_complete_t_t_complete_o_auth_skip() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_auth_skip");

        // Test auth skip
        ctx.assert_command_success("r complete t t_complete o auth skip");
        ctx.assert_authentication_option(Some(&SAuthentication::Skip));

        debug!("=====");
        // Test auth perform
        ctx.assert_command_success("r complete t t_complete o auth perform");
        ctx.assert_authentication_option(Some(&SAuthentication::Perform));

        debug!("=====");
        // Test auth unset
        ctx.assert_command_success("r complete t t_complete o auth unset");
        ctx.assert_authentication_option(None);
    }

    #[test]
    fn test_r_complete_t_t_complete_o_execinfo() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_execinfo");

        // Test execinfo set
        ctx.assert_command_success("r complete t t_complete o execinfo show");
        ctx.assert_execinfo_option(Some(&SInfo::Show));

        ctx.assert_command_success("r complete t t_complete o execinfo hide");
        ctx.assert_execinfo_option(Some(&SInfo::Hide));

        debug!("=====");
        // Test execinfo unset
        ctx.assert_command_success("r complete t t_complete o execinfo unset");
        ctx.assert_execinfo_option(None);
    }

    #[test]
    fn test_r_complete_t_t_complete_o_umask() {
        let (mut ctx, _defer) = TestContext::new("r_complete_t_t_complete_o_umask");

        // Test umask set
        ctx.assert_command_success("r complete t t_complete o umask 027");
        ctx.assert_umask_option(Some(&0o27.into()));

        debug!("=====");
        // Test umask unset
        ctx.assert_command_success("r complete t t_complete o umask unset");
        ctx.assert_umask_option(None);
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

    fn read_json(path: &str) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    fn upgrade(path: &str, command: &str) -> Result<bool, Box<dyn Error>> {
        let mut settings = FileSettings::write_all(path, path, StorageMethod::JSON).unwrap();
        main(&mut settings, command.split(' ')).call()
    }

    #[test]
    fn test_upgrade() {
        let path = format!("{RAR_CFG_PATH}.upgrade");
        let _cleanup = defer(|| {
            let _ = fs::remove_file(format!("{RAR_CFG_PATH}.upgrade"));
        });
        // saved by 4.0.2, with an environment regex
        fs::write(
            &path,
            format!(
                r#"{{"version":"4.0.2","storage":{{"method":"json","settings":{{"path":"{path}","immutable":false}}}},"options":{{"env":{{"check":["LC_.*"]}}}},"roles":[]}}"#
            ),
        )
        .unwrap();

        // --check fails and writes nothing
        assert!(upgrade(&path, "upgrade --check").is_err());
        let saved = read_json(&path);
        assert_eq!(saved["version"], "4.0.2");
        assert_eq!(
            saved["options"]["env"]["check"],
            serde_json::json!(["LC_.*"])
        );

        // upgrade saves the file itself, nothing is left for save_all
        assert!(!upgrade(&path, "upgrade").unwrap());
        let saved = read_json(&path);
        assert_eq!(
            saved["version"],
            rootasrole_core::PACKAGE_VERSION.to_string()
        );
        assert_eq!(
            saved["options"]["env"]["check"],
            serde_json::json!(["LC_*"])
        );

        // up to date: the file is not written again
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(!upgrade(&path, "upgrade --check").unwrap());
        assert!(!upgrade(&path, "upgrade").unwrap());
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    }

    #[test]
    fn test_upgrade_policy_directory() {
        let path = format!("{RAR_CFG_PATH}.upgrade_dir");
        let dir = format!("{path}.d");
        let _cleanup = defer(|| {
            let _ = fs::remove_file(format!("{RAR_CFG_PATH}.upgrade_dir"));
            let _ = fs::remove_dir_all(format!("{RAR_CFG_PATH}.upgrade_dir.d"));
        });
        let version = rootasrole_core::PACKAGE_VERSION;
        fs::write(
            &path,
            format!(
                r#"{{"version":"{version}","storage":{{"method":"json","settings":{{"path":"{dir}","immutable":false}}}}}}"#
            ),
        )
        .unwrap();
        fs::create_dir_all(&dir).unwrap();
        let policy = format!("{dir}/policy.json");
        fs::write(
            &policy,
            r#"{"version":"4.0.2","options":{"env":{"keep":["^HOME$"]}},"roles":[]}"#,
        )
        .unwrap();
        // not convertible, the file cannot be loaded
        let invalid = format!("{dir}/invalid.json");
        fs::write(
            &invalid,
            r#"{"version":"4.0.3","options":{"env":{"keep":["PS[1-4]"]}},"roles":[]}"#,
        )
        .unwrap();
        let root = fs::read_to_string(&path).unwrap();

        assert!(upgrade(&path, "upgrade --check").is_err());
        assert_eq!(read_json(&policy)["version"], "4.0.2");

        // the file that cannot be loaded is reported, the other one is upgraded
        assert!(upgrade(&path, "upgrade").is_err());
        let saved = read_json(&policy);
        assert_eq!(saved["version"], version.to_string());
        assert_eq!(saved["options"]["env"]["keep"], serde_json::json!(["HOME"]));
        assert_eq!(
            read_json(&invalid)["options"]["env"]["keep"],
            serde_json::json!(["PS[1-4]"])
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), root);
    }

    #[test]
    fn test_convert() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();
        let (mut ctx, _defer) = TestContext::new("convert");

        ctx.assert_command_success(&format!("convert cbor {RAR_CFG_PATH}.convert.bin"));
        ctx.assert_command_success(&format!("convert json {RAR_CFG_PATH}.convert.json.1"));

        assert!(fs::metadata(format!("{RAR_CFG_PATH}.convert.bin")).is_ok());

        ctx.assert_command_success(&format!(
            "convert --from cbor {RAR_CFG_PATH}.convert.bin json {RAR_CFG_PATH}.convert.json"
        ));
        assert!(fs::metadata(format!("{RAR_CFG_PATH}.convert.json")).is_ok());
        assert_eq!(
            normalize_json_object(
                serde_json::from_str::<Value>(
                    &fs::read_to_string(format!("{RAR_CFG_PATH}.convert.json")).unwrap()
                )
                .unwrap()
            ),
            normalize_json_object(
                serde_json::from_str::<Value>(
                    &fs::read_to_string(format!("{RAR_CFG_PATH}.convert.json.1")).unwrap()
                )
                .unwrap()
            )
        );

        ctx.assert_command_success(&format!(
            "convert --reconfigure cbor {RAR_CFG_PATH}.reconfigure.convert.bin"
        ));

        assert_eq!(
            ctx.settings
                .get_root()
                .storage
                .settings
                .as_ref()
                .unwrap()
                .path
                .as_ref()
                .unwrap()
                .to_str()
                .unwrap(),
            format!("{RAR_CFG_PATH}.reconfigure.convert.bin")
        );

        fs::remove_file(format!("{RAR_CFG_PATH}.convert.bin")).unwrap();
        fs::remove_file(format!("{RAR_CFG_PATH}.convert.json")).unwrap();
    }
}
