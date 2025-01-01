//extern crate sudoers_reader;

use rar_common::{
    database::{read_json_config, save_json},
    plugin::register_plugins,
    util::{drop_effective, read_effective, subsribe},
    Storage,
};
use log::{debug, error};

mod cli;
mod util;

#[cfg(not(test))]
const ROOTASROLE: &str = "/etc/security/rootasrole.json";
#[cfg(test)]
const ROOTASROLE: &str = "target/rootasrole.json";

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rar_common::{get_settings, StorageMethod};

    subsribe("chsr")?;
    drop_effective()?;
    register_plugins();
    let settings = get_settings(ROOTASROLE).expect("Error on config read");
    let config = match settings.clone().as_ref().borrow().storage.method {
        StorageMethod::JSON => Storage::JSON(read_json_config(settings.clone(), ROOTASROLE)?),
        _ => {
            error!("Unsupported storage method");
            std::process::exit(1);
        }
    };
    read_effective(false).expect("Operation not permitted");

    if cli::main(&config, std::env::args().skip(1)).is_ok_and(|b| b) {
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
