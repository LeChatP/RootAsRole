use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use rar_common::database::versionning::Versioning;
use rar_common::{FullSettings, RemoteStorageSettings, SettingsContent, StorageMethod};

/// Manages the test configuration file that points to different policy fixtures
pub struct ConfigManager {
    config_file_path: PathBuf,
}

impl ConfigManager {
    /// Creates a new ConfigManager instance
    pub fn new(config_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let manager = ConfigManager {
            config_file_path: config_path.to_path_buf(),
        };

        // Create initial empty configuration
        manager.create_initial_config()?;

        Ok(manager)
    }

    /// Creates the initial test configuration file
    fn create_initial_config(&self) -> Result<(), Box<dyn std::error::Error>> {
        let settings = FullSettings::builder()
            .storage(
                SettingsContent::builder()
                    .method(StorageMethod::JSON)
                    .build(),
            )
            .build();

        self.write_config(settings)?;
        Ok(())
    }

    /// Load a specific policy fixture by updating the configuration
    pub fn load_fixture(&self, fixture_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        // Create a configuration that points to the fixture file
        let settings = FullSettings::builder()
            .storage(
                SettingsContent::builder()
                    .method(StorageMethod::JSON)
                    .settings(
                        RemoteStorageSettings::builder()
                            .path(fixture_path.canonicalize()?)
                            .not_immutable()
                            .build(),
                    )
                    .build(),
            )
            .build();

        self.write_config(settings)?;

        Ok(())
    }

    /// Write configuration to the test config file
    fn write_config(&self, settings: FullSettings) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = File::create(&self.config_file_path).inspect_err(|e| {
            eprintln!(
                "Unable to create file {} : {}",
                self.config_file_path.display(),
                e
            )
        })?;
        let json = serde_json::to_string_pretty(&Versioning::new(settings))
            .inspect_err(|e| eprintln!("serializing error : {}", e))?;
        file.write_all(json.as_bytes())
            .inspect_err(|e| eprintln!("unable to write config : {}", e))?;
        file.flush()
            .inspect_err(|e| eprintln!("Unable to flush data : {}", e))?;
        Ok(())
    }
}

impl Drop for ConfigManager {
    fn drop(&mut self) {
        // Clean up the configuration file
        if self.config_file_path.exists() {
            if let Err(e) = fs::remove_file(&self.config_file_path) {
                eprintln!(
                    "Warning: Failed to clean up config file {}: {}",
                    self.config_file_path.display(),
                    e
                );
            }
        }
    }
}
