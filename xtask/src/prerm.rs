use std::fs::File;

use util::{toggle_lock_config, ROOTASROLE};

mod util;
fn main() {
    if File::open(ROOTASROLE).is_ok() {
        toggle_lock_config(&ROOTASROLE.to_string(), util::ImmutableLock::Unset)
            .expect("Error while removing lock from config file");
    }
}
