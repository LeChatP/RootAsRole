#[cfg(debug_assertions)]
#[allow(clippy::unnecessary_wraps)] // Same signature as non debug.
/// # Errors
/// Returns an error if the logger fails to initialize
pub fn subsribe(_: &str) -> std::io::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Trace)
        .format_module_path(true)
        .init();
    Ok(())
}

#[cfg(not(debug_assertions))]
pub fn subsribe(tool: &str) -> std::io::Result<()> {
    use log::LevelFilter;
    use std::ffi::CString;

    // 1. Prepare the identity string (the tool name).
    let ident = CString::new(tool).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid tool name: {}", e),
        )
    })?;

    let ident_ptr = ident.into_raw();

    // SAFETY: Valid string created with CString::new, and will be freed when the program exits.
    unsafe {
        libc::openlog(ident_ptr, libc::LOG_PID, libc::LOG_AUTH);
    }

    let logger = CustomSysLogger {
        level: LevelFilter::Info,
    };

    log::set_boxed_logger(Box::new(logger)).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to set global logger: {}", e),
        )
    })?;

    log::set_max_level(LevelFilter::Info);

    Ok(())
}

#[cfg(not(debug_assertions))]
struct CustomSysLogger {
    level: log::LevelFilter,
}
#[cfg(not(debug_assertions))]
impl log::Log for CustomSysLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let msg = std::ffi::CString::new(record.args().to_string()).unwrap_or_default();

            let priority = match record.level() {
                log::Level::Error => libc::LOG_ERR,
                log::Level::Warn => libc::LOG_WARNING,
                log::Level::Info => libc::LOG_INFO,
                log::Level::Debug | log::Level::Trace => libc::LOG_DEBUG,
            };

            unsafe {
                libc::syslog(
                    priority,
                    b"%s\0".as_ptr() as *const libc::c_char,
                    msg.as_ptr(),
                );
            }
        }
    }

    fn flush(&self) {}
}
