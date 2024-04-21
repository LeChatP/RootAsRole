use capctl::{prctl, Cap, CapState};
use tracing::Level;
use tracing_subscriber::util::SubscriberInitExt;

pub mod util;
pub mod version;
pub mod database;
pub mod config;
pub mod api;

pub mod plugin;

#[cfg(debug_assertions)]
pub fn subsribe() {
    let identity = std::ffi::CStr::from_bytes_with_nul(b"sr\0").unwrap();
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_file(true)
        .with_line_number(true)
        .with_writer(syslog)
        .finish()
        .init();
}

#[cfg(not(debug_assertions))]
pub fn subsribe() {
    use std::panic::set_hook;

    let identity = std::ffi::CStr::from_bytes_with_nul(b"sr\0").unwrap();
    let options = syslog_tracing::Options::LOG_PID;
    let facility = syslog_tracing::Facility::Auth;
    let syslog = syslog_tracing::Syslog::new(identity, options, facility).unwrap();
    tracing_subscriber::fmt()
        .with_max_level(Level::ERROR)
        .with_writer(syslog)
        .finish()
        .init();
    set_hook(Box::new(|info| {
        if let Some(s) = info.payload().downcast_ref::<String>() {
            println!("{}", s);
        }
    }));
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