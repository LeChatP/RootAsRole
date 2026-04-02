use rootasrole_exec::terminal::{self, ProcessId, TermSize, Terminal, UserTerm};
use std::fs::File;

#[test]
fn test_terminal_trait_on_file() {
    // A regular file is not a terminal
    let file = File::open("Cargo.toml").expect("Failed to open file");

    // safe_isatty should be false
    assert!(!terminal::safe_isatty(&file));

    // is_terminal_for_pgrp should be false
    assert!(!file.is_terminal_for_pgrp(ProcessId::new(1)));

    // ttyname should fail
    assert!(file.ttyname().is_err());
}

#[test]
fn test_safe_isatty_stdout() {
    let stdout = std::io::stdout();
    let _ = terminal::safe_isatty(stdout);
}

#[test]
fn test_process_id() {
    let pid_val = 1234;
    let pid = ProcessId::new(pid_val);
    assert_eq!(pid.inner(), pid_val);
    assert_eq!(format!("{pid}"), "1234");
}

#[test]
fn test_term_size() {
    let ts = TermSize::new(24, 80);
    assert_eq!(format!("{ts}"), "24 x 80");
}

#[test]
fn test_user_term_open() {
    // This test might fail if there is no /dev/tty (e.g. in some CI environments or non-interactive shells)
    // We handle the result gracefully.
    match UserTerm::open() {
        Ok(mut term) => {
            assert!(terminal::safe_isatty(&term));

            // Try enabling raw mode
            let res = term.set_raw_mode(false, false);
            assert!(res.is_ok());

            // Restore
            let res = term.restore(false);
            assert!(res.is_ok());
        }
        Err(e) => {
            println!("Skipping UserTerm test as /dev/tty cannot be opened: {e}");
        }
    }
}

#[test]
fn test_is_pipe_or_socket() {
    use std::os::unix::net::UnixStream;

    let file = File::open("Cargo.toml").expect("Failed to open file");
    assert!(!file.is_pipe_or_socket());

    let (s1, _s2) = UnixStream::pair().expect("Failed to create socket pair");
    assert!(s1.is_pipe_or_socket());
}
