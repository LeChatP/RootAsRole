//extern crate sudoers_reader;

use log::error;
use rar_common::{
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
    use rar_common::{get_settings, save_settings, StorageMethod};

    subsribe("chsr")?;
    drop_effective()?;
    register_plugins();
    let settings = get_settings(&ROOTASROLE.to_string()).expect("Error on config read");
    let config = match settings.clone().as_ref().borrow().storage.method {
        StorageMethod::JSON | StorageMethod::CBOR => Storage::SConfig(settings.as_ref().borrow().config.clone().unwrap()),
        StorageMethod::Unknown => {
            error!("Unknown storage method");
            return Err("Unknown storage method".into());
        },
    };
    read_effective(false).expect("Operation not permitted");

    if cli::main(&config, std::env::args().skip(1)).is_ok_and(|b| b) {
        save_settings(&ROOTASROLE.to_string(), settings)
    } else {
        Ok(())
    }
}
