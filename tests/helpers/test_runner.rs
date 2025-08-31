use std::io::Result as IoResult;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use bon::bon;

use crate::helpers::config_manager::ConfigManager;

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
    config_manager: ConfigManager,
}

#[bon]
impl TestRunner {
    /// Creates a new TestRunner instance and compiles the dosr binary
    pub fn new(
        binary_path: PathBuf,
        test_config_path: PathBuf,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config_manager = ConfigManager::new(&test_config_path)?;

        Ok(TestRunner {
            binary_path,
            config_manager,
        })
    }

    /// Run the dosr command with a specific policy fixture
    #[builder]
    pub fn run_dosr(
        &self,
        #[builder(start_fn)] args: &[&str],
        fixture_name: Option<&str>,
        env_vars: Option<&[(&str, &str)]>,
        users: Option<&[&str]>,
        groups: Option<&[&str]>,
    ) -> IoResult<CommandResult> {
        // If a fixture is specified, update the configuration
        if let Some(fixture) = fixture_name {
            if let Err(e) = self.config_manager.load_fixture(fixture.into()) {
                eprintln!("Warning: Failed to load fixture '{}': {}", fixture, e);
            }
        }
        let mut added_users = Vec::new();
        let mut added_groups = Vec::new();
        if let Some(user_list) = users {
            // Check if users exist and create them if necessary
            for &user in user_list {
                let user_check = Command::new("id").arg(user).status();
                match user_check {
                    Ok(e) => {
                        //check if error is due to user not existing
                        if !e.success() {
                            // User does not exist, attempt to create
                            let create_status =
                                Command::new("useradd").args(["-m", user]).status();
                            if let Err(e) = create_status {
                                println!("Warning: Failed to create user '{}': {}", user, e);
                            }
                            println!("Created user '{}' for testing purposes", user);
                            added_users.push(user.to_string());
                        }
                        println!("User '{}' exists", user);
                    }
                    Err(e) => {
                        println!("Warning: Failed to check user '{}': {}", user, e);
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
                                println!("Warning: Failed to create group '{}': {}", group, e);
                            }
                            added_groups.push(group.to_string());
                            println!("Created group '{}' for testing purposes", group);
                        }
                    }
                    Err(e) => {
                        println!("Warning: Failed to check group '{}': {}", group, e);
                    }
                }
            }
        }
        let mut command = Command::new(&self.binary_path);
        command
            .args(args)
            .envs(env_vars.unwrap_or(&[]).iter().cloned())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = command.output()?;
        println!(
            "Output : {}",
            String::from_utf8(output.stdout.clone()).unwrap()
        );
        println!(
            "Error  : {}",
            String::from_utf8(output.stderr.clone()).unwrap()
        );

        // Clean up any users or groups we added
        for user in added_users {
            let _ = Command::new("userdel").args(["-r", &user]).status()?;
        }
        for group in added_groups {
            let _ = Command::new("groupdel").args([&group]).status()?;
        }

        Ok(CommandResult {
            success: output.status.success(),
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}
