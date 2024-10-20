use std::{env::args, fs::File, io::BufReader};

use configure::check_filesystem;
use log::warn;
use util::{OsTarget, SettingsFile, ROOTASROLE};

mod configure;
mod installer;
mod util;

fn main() {
    let action = args().nth(1);
    if let Some(action) = action {
        match action.as_str() {
            "configure" => {
                let res =
                    installer::install::install(&None, installer::Profile::Release, false, false);
                if let Err(e) = res {
                    warn!("{:#}", e);
                    std::process::exit(1);
                }
                let res = configure::configure(Some(OsTarget::Debian));
                if let Err(e) = res {
                    warn!("{:#}", e);
                    std::process::exit(1);
                }
            }
            "abort-remove" | "abort-deconfigure" => {
                // We replace the immutable flag if it was set in config file
                if let Ok(f) = File::open(ROOTASROLE) {
                    let config = BufReader::new(f);
                    let config: SettingsFile =
                        serde_json::from_reader(config).expect("Failed to parse config file");
                    if config
                        .storage
                        .settings
                        .is_some_and(|s| s.immutable.unwrap_or(false))
                    {
                        let res = check_filesystem();
                        if let Err(e) = res {
                            warn!("{:#}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}
