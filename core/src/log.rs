#[cfg(debug_assertions)]
#[allow(clippy::unnecessary_wraps)] // Same signature as non debug.
/// # Errors
/// Returns an error if the logger fails to initialize
pub fn subscribe(_: &str) -> std::io::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Trace)
        .format_module_path(true)
        .init();
    Ok(())
}

#[cfg(not(debug_assertions))]
/// # Errors
/// Returns an error if the tool name holds a NUL, or if a logger is already set
pub fn subscribe(tool: &str) -> std::io::Result<()> {
    use log::LevelFilter;
    use std::ffi::CString;

    // 1. Prepare the identity string (the tool name).
    let ident = CString::new(tool).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid tool name: {e}"),
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

    log::set_boxed_logger(Box::new(logger))
        .map_err(|e| std::io::Error::other(format!("Failed to set global logger: {e}")))?;

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
            let priority = match record.level() {
                log::Level::Error => libc::LOG_ERR,
                log::Level::Warn => libc::LOG_WARNING,
                log::Level::Info => libc::LOG_INFO,
                log::Level::Debug | log::Level::Trace => libc::LOG_DEBUG,
            };

            for message in syslog_messages(&record.args().to_string()) {
                // SAFETY: the format is a C string with one %s, given `message`, a C string that
                // lives during the call
                unsafe {
                    libc::syslog(priority, c"%s".as_ptr(), message.as_ptr());
                }
            }
        }
    }

    fn flush(&self) {}
}

/// The longest message given to `syslog(3)`, its marks included, as in sudo-rs. glibc sends a
/// message as one datagram to `/dev/log`, and drops it without a word when it does not fit in
/// the buffer of the socket (`net.core.wmem_default`, 212992 bytes by default): a line that
/// holds the command line of the user would be lost.
#[cfg(any(test, not(debug_assertions)))]
const MAX_MESSAGE: usize = 960;
#[cfg(any(test, not(debug_assertions)))]
const CUT_END: &str = " [...]";
#[cfg(any(test, not(debug_assertions)))]
const CUT_START: &str = "[...] ";

/// `message` as the messages given to `syslog(3)`, each of `MAX_MESSAGE` bytes at most: a longer
/// one is cut before a white space, or else on a character boundary, and its parts are marked
/// `[...]` where they were cut (sudo-rs `log/syslog.rs`). A NUL is written `\0`: it would end the
/// C string there.
#[cfg(any(test, not(debug_assertions)))]
fn syslog_messages(message: &str) -> Vec<std::ffi::CString> {
    let message = message.replace('\0', "\\0");
    let mut messages = Vec::new();
    let mut rest = message.as_str();
    let mut start = "";
    while start.len() + rest.len() > MAX_MESSAGE {
        let room = MAX_MESSAGE - start.len() - CUT_END.len();
        // never 0: the room holds more than one character
        let cut = rest.as_bytes()[1..room]
            .iter()
            .rposition(u8::is_ascii_whitespace)
            .map_or_else(|| rest.floor_char_boundary(room), |space| space + 1);
        messages.push(format!("{start}{}{CUT_END}", &rest[..cut]));
        rest = &rest[cut..];
        start = CUT_START;
    }
    messages.push(format!("{start}{rest}"));
    messages
        .into_iter()
        .filter_map(|message| std::ffi::CString::new(message).ok())
        .collect()
}

/// The former, misspelled name of [`subscribe`], kept for the users of rootasrole-core 4.1.
///
/// # Errors
/// As [`subscribe`].
#[deprecated(since = "4.2.0", note = "use subscribe")]
pub fn subsribe(tool: &str) -> std::io::Result<()> {
    subscribe(tool)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parts of `message` as `syslog_messages` cuts them, without their marks.
    fn parts(message: &str) -> Vec<String> {
        let messages: Vec<String> = syslog_messages(message)
            .into_iter()
            .map(|m| m.into_string().unwrap())
            .collect();
        let last = messages.len() - 1;
        messages
            .iter()
            .enumerate()
            .map(|(i, m)| {
                assert!(m.len() <= 960, "{} bytes", m.len());
                let m = if i > 0 {
                    m.strip_prefix("[...] ").unwrap()
                } else {
                    m
                };
                let m = if i < last {
                    m.strip_suffix(" [...]").unwrap()
                } else {
                    m
                };
                m.to_string()
            })
            .collect()
    }

    #[test]
    fn test_a_short_message_is_given_as_it_is() {
        assert_eq!(parts(""), [""]);
        assert_eq!(
            parts("dosr: Permission denied"),
            ["dosr: Permission denied"]
        );
        assert_eq!(parts(&"a".repeat(960)), ["a".repeat(960)]);
    }

    // every part fits in a datagram, and together they are the message
    #[test]
    fn test_a_long_message_is_cut_into_parts_that_fit() {
        let command = format!("COMMAND=/usr/bin/sh -c 'echo {}' x", "a".repeat(250_000));
        for message in [
            "a".repeat(961),
            "a".repeat(250_000),
            format!("one {} two", "b".repeat(2000)),
            command,
            "é".repeat(1000),
            format!("a{}", "€".repeat(1000)),
            format!("{} {}", "x".repeat(953), "y".repeat(10)),
            " ".repeat(3000),
        ] {
            let parts = parts(&message);
            assert!(parts.len() > 1);
            assert_eq!(parts.concat(), message);
        }
        // before a white space when there is one
        let parts = parts(&format!("{} {}", "x".repeat(900), "y".repeat(100)));
        assert_eq!(parts, ["x".repeat(900), format!(" {}", "y".repeat(100))]);
    }

    #[test]
    fn test_a_nul_does_not_end_the_message() {
        assert_eq!(parts("before\0after"), ["before\\0after"]);
    }
}
