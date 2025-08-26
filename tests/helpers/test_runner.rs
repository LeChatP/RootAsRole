use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::io::Result as IoResult;

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
    pub fn new(binary_path: PathBuf, test_config_path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {


        let config_manager = ConfigManager::new(&test_config_path)?;
        
        Ok(TestRunner {
            binary_path,
            config_manager,
        })
    }

    /// Run the dosr command with a specific policy fixture
    #[builder]
    pub fn run_dosr(&self, 
        #[builder(start_fn)]
        args: &[&str], 
        fixture_name: Option<&str>,
        env_vars: Option<&[(&str, &str)]>,
    ) -> IoResult<CommandResult> {
        // If a fixture is specified, update the configuration
        if let Some(fixture) = fixture_name {
            if let Err(e) = self.config_manager.load_fixture(&fixture.into()) {
                eprintln!("Warning: Failed to load fixture '{}': {}", fixture, e);
            }
        }
        let mut command = Command::new(&self.binary_path);
        command
            .args(args)
            .envs(env_vars.unwrap_or(&[]).iter().cloned())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = command.output()?;
        
        Ok(CommandResult {
            success: output.status.success(),
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}