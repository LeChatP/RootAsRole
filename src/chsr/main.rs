//extern crate sudoers_reader;


use common::{config::{self, Storage}, database::{read_json_config, save_json}, drop_effective, plugin::register_plugins, read_effective};
use common::subsribe;
use tracing::{debug, error};

mod cli;
#[path = "../mod.rs"]
mod common;




fn main() -> Result<(), Box<dyn std::error::Error>>{
    subsribe("chsr");
    drop_effective()?;
    register_plugins();
    read_effective(true).expect("Operation not permitted");
    let settings = config::get_settings();
    let config = match settings.method {
        config::StorageMethod::JSON => {
            Storage::JSON(read_json_config(&settings)?)
        }
        _ => {
            error!("Unsupported storage method");
            std::process::exit(1);
        }
    };
    read_effective(false).expect("Operation not permitted");

    if cli::main(&config).is_ok() {
        match config {
            Storage::JSON(config) => {
                debug!("Saving configuration");
                save_json(&settings, config)?;
                Ok(())
            }
        }
    } else {
        Ok(())
    }
}