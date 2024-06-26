use capctl::{prctl, Cap, CapState};
use serde::Serialize;
use std::{error::Error, ffi::CString, fs::File, path::Path};
use tracing::{debug, Level};
use tracing_subscriber::util::SubscriberInitExt;

pub mod api;
pub mod config;
pub mod database;
pub mod util;
pub mod version;

pub mod plugin;

#[cfg(debug_assertions)]
pub fn subsribe(tool: &str) {
    use std::io;
    let identity = CString::new(tool).unwrap();
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let _syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_file(true)
        .with_line_number(true)
        .with_writer(io::stdout)
        .finish()
        .init();
}

#[cfg(not(debug_assertions))]
pub fn subsribe(tool: &str) {
    use std::panic::set_hook;

    let identity = CString::new(tool).unwrap();
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
    tracing_subscriber::fmt()
        .compact()
        .with_max_level(Level::WARN)
        .with_file(false)
        .with_timer(false)
        .with_line_number(false)
        .with_target(false)
        .without_time()
        .with_writer(syslog)
        .finish()
        .init();
    set_hook(Box::new(|info| {
        if let Some(s) = info.payload().downcast_ref::<String>() {
            println!("{}", s);
        }
    }));
}

pub fn drop_effective() -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.clear();
    current.set_current()
}

pub fn cap_effective(cap: Cap, enable: bool) -> Result<(), capctl::Error> {
    let mut current = CapState::get_current()?;
    current.effective.set_state(cap, enable);
    current.set_current()
}

pub fn setpcap_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETPCAP, enable)
}

pub fn setuid_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETUID, enable)
}

pub fn setgid_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::SETGID, enable)
}

pub fn fowner_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::FOWNER, enable)
}

pub fn read_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::DAC_READ_SEARCH, enable)
}

pub fn dac_override_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::DAC_OVERRIDE, enable)
}

pub fn immutable_effective(enable: bool) -> Result<(), capctl::Error> {
    cap_effective(Cap::LINUX_IMMUTABLE, enable)
}

pub fn activates_no_new_privs() -> Result<(), capctl::Error> {
    prctl::set_no_new_privs()
}

pub fn write_json_config<T: Serialize, S>(settings: &T, path: S) -> Result<(), Box<dyn Error>>
where
    S: std::convert::AsRef<Path> + Clone,
{
    let file = create_with_privileges(path)?;
    serde_json::to_writer_pretty(file, &settings)?;
    Ok(())
}

pub fn create_with_privileges<P: AsRef<Path>>(p: P) -> Result<File, std::io::Error> {
    std::fs::File::create(&p).or_else(|e| {
        debug!(
            "Error creating file without privilege, trying with privileges: {}",
            e
        );
        dac_override_effective(true)?;
        let res = std::fs::File::create(p).inspect_err(|e| {
            debug!(
                "Error creating file without privilege, trying with privileges: {}",
                e
            );
        });
        dac_override_effective(false)?;
        res
    })
}

pub fn open_with_privileges<P: AsRef<Path>>(p: P) -> Result<File, std::io::Error> {
    std::fs::File::open(&p).or_else(|e| {
        debug!(
            "Error creating file without privilege, trying with privileges: {}",
            e
        );
        read_effective(true).or(dac_override_effective(true))?;
        let res = std::fs::File::open(p);
        read_effective(false)?;
        dac_override_effective(false)?;
        res
    })
}

pub fn remove_with_privileges<P: AsRef<Path>>(p: P) -> Result<(), std::io::Error> {
    std::fs::remove_file(&p).or_else(|e| {
        debug!(
            "Error creating file without privilege, trying with privileges: {}",
            e
        );
        dac_override_effective(true)?;
        let res = std::fs::remove_file(p);
        dac_override_effective(false)?;
        res
    })
}

pub fn create_dir_all_with_privileges<P: AsRef<Path>>(p: P) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(&p).or_else(|e| {
        debug!(
            "Error creating file without privilege, trying with privileges: {}",
            e
        );
        dac_override_effective(true)?;
        let res = std::fs::create_dir_all(p);
        read_effective(false)?;
        dac_override_effective(false)?;
        res
    })
}
