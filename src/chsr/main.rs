//extern crate sudoers_reader;

use capctl::Cap;
use common::{config::{self, Storage}, database::read_json_config, read_effective};
use tracing::error;

mod cli;
#[path = "../mod.rs"]
mod common;


fn main() {
    let settings = config::get_settings();
    let config = match settings.storage_method {
        config::StorageMethod::JSON => {
            Storage::JSON(read_json_config(settings).expect("Failed to read config"))
        }
        _ => {
            error!("Unsupported storage method");
            std::process::exit(1);
        }
    };
    cli::main(&config);
}

fn olmain() {
    read_effective(true).expect("Failed to read_effective");
    let settings = config::get_settings();
    read_effective(false).expect("Failed to read_effective");

}
