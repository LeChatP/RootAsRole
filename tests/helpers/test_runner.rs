use std::env;
use std::fs::File;
use std::io::{self, BufReader, Result as IoResult, read_to_string};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use bon::bon;
use rar_common::database::versionning::Versioning;
use rar_common::file::{LockedSettingsFile, RootSettings};
use rar_common::util::{RAR_CFG_TYPE, StorageMethod};

use crate::helpers::{FileLock, RAR_CFG_DATA_PATH, RAR_CFG_PATH, ensure_binary_built};
/// Represents the result of running the dosr command
#[derive(Debug)]
pub struct CommandResult {
    pub success: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Main test runner that manages the dosr binary and test configurations
pub struct TestRunner {
    binary_path: PathBuf,
    rar_cfg_path: String,
    rar_cfg_type: StorageMethod,
    lock: FileLock,
}

struct UserGroupGuard {
    users: Vec<String>,
    groups: Vec<String>,
}

impl UserGroupGuard {
    const fn new() -> Self {
        Self {
            users: Vec::new(),
            groups: Vec::new(),
        }
    }
    fn add_user(&mut self, u: String) {
        self.users.push(u);
    }
    fn add_group(&mut self, g: String) {
        self.groups.push(g);
    }
}

impl Drop for UserGroupGuard {
    fn drop(&mut self) {
        for user in &self.users {
            let _ = Command::new("userdel").args(["-r", user]).status();
        }
        for group in &self.groups {
            let _ = Command::new("groupdel").args([group]).status();
        }
    }
}

impl Drop for TestRunner {
    fn drop(&mut self) {
        self.lock.file.unlock().expect("Not unlocked");
    }
}

#[bon]
#[allow(clippy::unwrap_used)]
impl TestRunner {
    /// Creates a new ``TestRunner`` instance and compiles the dosr binary
    #[builder]
    pub fn new(
        #[builder(default = RAR_CFG_PATH)] rar_cfg_path: &str,
        #[builder(default = RAR_CFG_DATA_PATH)] rar_cfg_data_path: &str,
        #[builder(default = RAR_CFG_TYPE)] rar_cfg_type: StorageMethod,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let lock = FileLock::new("target/tmp/dosr_integration.lock")?;
        let binary_path = ensure_binary_built(rar_cfg_path, rar_cfg_data_path, rar_cfg_type)?;

        Ok(Self {
            binary_path,
            rar_cfg_path: rar_cfg_path.to_string(),
            rar_cfg_type,
            lock,
        })
    }

    /// Run the dosr command with a specific policy fixture
    #[builder]
    #[allow(clippy::too_many_lines)]
    pub fn run_dosr(
        &self,
        #[builder(start_fn)] args: &[&str],
        rar_cfg_data_path: Option<&str>,
        env_vars: Option<&[(&str, &str)]>,
        users: Option<&[&str]>,
        groups: Option<&[&str]>,
    ) -> IoResult<CommandResult> {
        println!("Running {} with args: {args:?}", self.binary_path.display());
        if let Some(data_path) = rar_cfg_data_path {
            let mut settings_file: LockedSettingsFile<Versioning<RootSettings>> =
                LockedSettingsFile::open_write(self.rar_cfg_path.clone(), |_, file| {
                    let settings: Versioning<RootSettings> = match self.rar_cfg_type {
                        StorageMethod::JSON => serde_json::from_reader(file).unwrap_or_default(),
                        StorageMethod::CBOR => {
                            cbor4ii::serde::from_reader(BufReader::new(file)).unwrap_or_default()
                        }
                    };
                    Ok(settings)
                })?;
            settings_file
                .data
                .data
                .storage
                .settings
                .get_or_insert_default()
                .path = Some(data_path.into());
            settings_file
                .save(self.rar_cfg_type, false)
                .map_err(|e| io::Error::other(e.to_string()))?;
        } else {
            let mut settings_file: LockedSettingsFile<Versioning<RootSettings>> =
                LockedSettingsFile::open_write(self.rar_cfg_path.clone(), |_, file| {
                    let settings: Versioning<RootSettings> = match self.rar_cfg_type {
                        StorageMethod::JSON => serde_json::from_reader(file).unwrap_or_default(),
                        StorageMethod::CBOR => {
                            cbor4ii::serde::from_reader(BufReader::new(file)).unwrap_or_default()
                        }
                    };
                    Ok(settings)
                })?;
            settings_file
                .save(self.rar_cfg_type, false)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }

        let mut guard = UserGroupGuard::new();
        if let Some(user_list) = users {
            // Check if users exist and create them if necessary
            for &user in user_list {
                let user_check = Command::new("id").arg(user).status();
                match user_check {
                    Ok(e) => {
                        //check if error is due to user not existing
                        if !e.success() {
                            // User does not exist, attempt to create
                            let create_status = Command::new("useradd").args(["-m", user]).status();
                            if let Err(e) = create_status {
                                println!("Warning: Failed to create user '{user}': {e}");
                            }
                            println!("Created user '{user}' for testing purposes");
                            guard.add_user(user.to_string());
                        }
                        println!("User '{user}' exists");
                    }
                    Err(e) => {
                        println!("Warning: Failed to check user '{user}': {e}");
                    }
                }
            }
        }
        if let Some(group_list) = groups {
            // Check if groups exist and create them if necessary
            for &group in group_list {
                let group_check = Command::new("getent").args(["group", group]).status();
                match group_check {
                    Ok(e) => {
                        if !e.success() {
                            // Group does not exist, attempt to create
                            let create_status = Command::new("groupadd").args([group]).status();
                            if let Err(e) = create_status {
                                println!("Warning: Failed to create group '{group}': {e}");
                            }
                            guard.add_group(group.to_string());
                            println!("Created group '{group}' for testing purposes");
                        }
                    }
                    Err(e) => {
                        println!("Warning: Failed to check group '{group}': {e}");
                    }
                }
            }
        }
        let output = Command::new(&self.binary_path)
            .args(args)
            .envs(
                env::vars().chain(
                    env_vars
                        .unwrap_or(&[])
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string())),
                ),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        println!(
            "Output : {}",
            String::from_utf8(output.stdout.clone()).unwrap()
        );
        println!(
            "Error  : {}",
            String::from_utf8(output.stderr.clone()).unwrap()
        );

        Ok(CommandResult {
            success: output.status.success(),
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}
