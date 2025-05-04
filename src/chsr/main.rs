//extern crate sudoers_reader;

use rar_common::util::{drop_effective, read_effective, subsribe};

mod cli;
mod util;

#[cfg(not(test))]
const ROOTASROLE: &str = env!("RAR_CFG_PATH");
#[cfg(test)]
const ROOTASROLE: &str = "target/rootasrole.json";

#[cfg(not(tarpaulin_include))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rar_common::{get_full_settings, full_save_settings};

    subsribe("chsr")?;
    drop_effective()?;
    let settings = get_full_settings(&ROOTASROLE.to_string()).expect("Error on config read");
    read_effective(false).expect("Operation not permitted");

    if cli::main(settings.clone(), std::env::args().skip(1)).is_ok_and(|b| b) {
        full_save_settings(&ROOTASROLE.to_string(), settings, true)
    } else {
        Ok(())
    }
}
