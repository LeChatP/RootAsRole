use std::path::{Path, PathBuf};

use rootasrole_core::database::actor::SActor;
use rootasrole_core::database::options::{EnvBehavior, SAuthentication, SEnvOptions};
use rootasrole_core::database::structs::{SCommand, SCommands, SPolicy, SRole, STask, SetBehavior};
use rootasrole_core::database::versionning::Versioning;
use rootasrole_core::file::{LockedSettingsFile, RootSettings};
use rootasrole_core::util::RAR_CFG_TYPE;
use rootasrole_core::{RemoteStorageSettings, SettingsContent};

fn save_config<T>(path: &Path, data: T) -> std::io::Result<()>
where
    T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug + Default + Clone,
{
    let mut config =
        LockedSettingsFile::open_write(path, |_, _| Ok(Versioning::new(data.clone())))?;
    config
        .save(RAR_CFG_TYPE, false)
        .map_err(|error| std::io::Error::other(error.to_string()))
}

pub fn setup_config() -> std::io::Result<()> {
    let root_path = std::env::var_os("DOSR_CFG_PATH")
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::other("DOSR_CFG_PATH is required"))?;
    let policy_path = root_path.with_extension("environment-policy");
    if let Some(parent) = root_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let env_options = || {
        SEnvOptions::builder(EnvBehavior::Delete)
            .override_behavior(true)
            .keep(["KEEP"])
            .unwrap()
            .check(["TZ"])
            .unwrap()
            .delete(["DELETE"])
            .unwrap()
            .build()
    };
    let task = |name, override_behavior| {
        STask::builder(name)
            .purpose("environment fuzz target".to_owned())
            .commands(
                SCommands::builder(SetBehavior::None)
                    .add([SCommand::Simple("/usr/bin/env ^.*$".to_owned())])
                    .build(),
            )
            .options(|opt| {
                opt.env(
                    SEnvOptions::builder(EnvBehavior::Inherit)
                        .override_behavior(override_behavior)
                        .set([("TASK", "environment")])
                        .build(),
                )
                .authentication(SAuthentication::Skip)
                .build()
            })
            .build()
    };
    let current_uid = unsafe { libc::getuid() } as u32;
    let role = SRole::builder("environment")
        .actor(SActor::user(current_uid).build())
        .task(task("allowed", true))
        .task(task("denied", false))
        .options(|opt| opt.env(env_options()).build())
        .build();
    let policy = SPolicy::builder().role(role).build();

    let root = RootSettings::builder()
        .storage(
            SettingsContent::builder()
                .method(RAR_CFG_TYPE)
                .settings(
                    RemoteStorageSettings::builder()
                        .path(&policy_path)
                        .not_immutable()
                        .build(),
                )
                .build(),
        )
        .config(SPolicy::builder().build())
        .build();
    save_config(&root_path, root)?;
    save_config(&policy_path, policy)
}

fn main() {
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/fuzz_bins/rootasrole_setup_environment");
    unsafe { std::env::set_var("DOSR_BIN", binary) };
    if let Err(error) = setup_config() {
        eprintln!("failed to set up environment fuzz config: {error}");
        std::process::exit(1);
    }
}
