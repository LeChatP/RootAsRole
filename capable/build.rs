use std::{error::Error, fs, io};

use aya::util::KernelVersion;

fn main() {
    // get kernel version
    match kernel_version() {
        Ok(version) => {
            // create version.rs file
            fs::write(
                "src/version.rs",
                format!("pub const LINUX_VERSION_CODE: u32 = {};", version.code()),
            )
            .unwrap();
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn kernel_version() -> Result<KernelVersion, impl Error> {
    aya::util::KernelVersion::current()
}
