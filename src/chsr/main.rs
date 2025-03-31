//extern crate sudoers_reader;

use log::{debug, error};
use rar_common::{
    database::{read_sconfig, save_sconfig},
    plugin::register_plugins,
    util::{drop_effective, read_effective, subsribe},
    Storage,
};

mod cli;
mod util;

#[cfg(not(test))]
const ROOTASROLE: &str = env!("RAR_CFG_PATH");
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
        StorageMethod::JSON => Storage::SConfig(read_sconfig(settings.clone(), ROOTASROLE)?),
        _ => {
            error!("Unsupported storage method");
            std::process::exit(1);
        }
    };
    read_effective(false).expect("Operation not permitted");

    if cli::main(&config, std::env::args().skip(1)).is_ok_and(|b| b) {
        match config {
            Storage::SConfig(config) => {
                debug!("Saving configuration");
                save_sconfig(settings, config)?;
                Ok(())
            },
        }
    } else {
        Ok(())
    }
}
