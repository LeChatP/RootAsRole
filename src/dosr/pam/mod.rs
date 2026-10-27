use std::{
    borrow::Cow,
    ffi::CStr,
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
};

use bon::Builder;
use log::{debug, error, info, warn};
use nonstick2::{
    AuthnFlags, ConversationAdapter, EnvironMap, ErrorCode, LibPamTransaction, PamShared,
    Result as PamResult, TransactionBuilder, conv::Demux, items::Items, items::ItemsMut,
    libpam::SessionActive,
};
use rootasrole_core::{eprintln_ignore_io_error, println_ignore_io_error};

use crate::finder::PasswordSettings;
#[cfg(feature = "timeout")]
use crate::timeout;
use crate::{
    Cli,
    error::{SrError, SrResult},
};
use rootasrole_core::{
    Cred,
    database::options::{SAuthentication, STimeout},
};

use self::rpassword::Terminal;

#[allow(dead_code, reason = "This file is part of sudo-rs.")]
mod cutils;
#[allow(dead_code, reason = "This file is part of sudo-rs.")]
pub mod rpassword;
#[allow(dead_code, reason = "This file is part of sudo-rs.")]
pub mod securemem;

const PAM_SERVICE: &str = env!("RAR_PAM_SERVICE");
pub const PAM_PROMPT: &str = "Password: ";

#[derive(Builder)]
pub struct SrConversationHandler<'a> {
    #[builder(into)]
    username: Option<Cow<'a, str>>,
    #[builder(default = "Password: ", into)]
    prompt: Cow<'a, str>,
    #[builder(default)]
    use_stdin: bool,
    #[builder(default)]
    no_interact: bool,
}

impl SrConversationHandler<'_> {
    fn open(&self) -> std::io::Result<Terminal<'_>> {
        if self.use_stdin {
            Ok(Terminal::open_stdie())
        } else {
            Terminal::open_tty()
        }
    }
    /// Whether PAM asks for the password with its default prompt, `Password:` or
    /// `<user>'s Password:`, optionally followed by one space.
    fn is_pam_password_prompt(&self, prompt: &impl AsRef<str>) -> bool {
        let is_password = |prompt: &str| matches!(prompt, "Password:" | "Password: ");
        let pam_prompt = prompt.as_ref();
        is_password(pam_prompt)
            || self.username.as_ref().is_some_and(|username| {
                pam_prompt
                    .strip_prefix(username.as_ref())
                    .and_then(|prompt| prompt.strip_prefix("'s "))
                    .is_some_and(is_password)
            })
    }
}

impl Default for SrConversationHandler<'_> {
    fn default() -> Self {
        SrConversationHandler {
            prompt: "Password: ".into(),
            username: None,
            use_stdin: false,
            no_interact: false,
        }
    }
}

impl ConversationAdapter for SrConversationHandler<'_> {
    fn prompt(&self, prompt: impl AsRef<std::ffi::OsStr>) -> PamResult<std::ffi::OsString> {
        if self.no_interact {
            return Err(ErrorCode::ConversationError);
        }
        let mut term = self.open().map_err(|_| ErrorCode::ConversationError)?;
        term.prompt(&prompt.as_ref().to_string_lossy().to_string())
            .map_err(|_| ErrorCode::ConversationError)?;
        let read = term.read_cleartext().map_err(|_| ErrorCode::BufferError)?;
        drop(term);
        Ok(std::ffi::OsString::from(
            String::from_utf8_lossy(&read).to_string(),
        ))
    }

    fn masked_prompt(&self, prompt: impl AsRef<std::ffi::OsStr>) -> PamResult<std::ffi::OsString> {
        if self.no_interact {
            return Err(ErrorCode::ConversationError);
        }
        //if the prompted message is the password prompt, we replace to self.prompt
        let pam_prompt = if self.is_pam_password_prompt(&prompt.as_ref().to_string_lossy()) {
            self.prompt.clone()
        } else {
            prompt.as_ref().to_string_lossy()
        };
        let mut term = self.open().map_err(|_| ErrorCode::ConversationError)?;
        term.prompt(&pam_prompt)
            .map_err(|_| ErrorCode::ConversationError)?;
        let read = term.read_password().map_err(|_| ErrorCode::BufferError)?;
        drop(term);
        let os_str = CStr::from_bytes_until_nul(&read)
            .map_err(|_| ErrorCode::BufferError)?
            .to_str()
            .map_err(|_| ErrorCode::BufferError)?;
        Ok(std::ffi::OsString::from(os_str))
    }

    fn error_msg(&self, message: impl AsRef<std::ffi::OsStr>) {
        error!("{}", message.as_ref().to_string_lossy());
        eprintln_ignore_io_error!("{}", message.as_ref().to_string_lossy());
    }

    fn info_msg(&self, message: impl AsRef<std::ffi::OsStr>) {
        info!("{}", message.as_ref().to_string_lossy());
        println_ignore_io_error!("{}", message.as_ref().to_string_lossy());
    }
}

/// The terminal and the requesting user of the transaction, like sudo sets them: modules such
/// as `pam_access`, `pam_securetty` or `pam_tty_audit`, and the logs, read them.
fn set_pam_items(txn: &mut impl PamShared, user: &Cred) -> PamResult<()> {
    use rootasrole_exec::terminal::TerminalExt;
    let mut items = txn.items_mut();
    items.set_remote_user(Some(std::ffi::OsStr::new(&user.user.name)))?;
    if let Ok(tty) = std::io::stdin().ttyname() {
        items.set_tty_name(Some(&tty))?;
    }
    Ok(())
}

/// Whether the user of the PAM transaction is still the one dosr asked for.
fn same_pam_user(pam_user: Option<&std::ffi::OsStr>, requested: &str) -> bool {
    pam_user == Some(std::ffi::OsStr::new(requested))
}

/// A PAM module may change `PAM_USER` during the transaction (`pam_get_item(3)`): dosr refuses
/// to go on for another user than the one it authenticates.
fn check_pam_user(txn: &impl PamShared, user: &Cred) -> SrResult<()> {
    let pam_user = txn.items().user().map_err(|e| {
        error!("Cannot read the user of the PAM transaction: {e}");
        SrError::AuthenticationFailed
    })?;
    if same_pam_user(pam_user.as_deref(), &user.user.name) {
        Ok(())
    } else {
        error!(
            "A PAM module changed the user from {} to {pam_user:?}",
            user.user.name
        );
        Err(SrError::AuthenticationFailed)
    }
}

/// The variables that PAM modules set for the session (`pam_getenvlist(3)`), such as `pam_env`
/// or `pam_systemd`. The environment of the command is UTF-8: another variable is left out, as
/// a variable without a name.
pub fn session_env(txn: &impl PamShared) -> Vec<(String, String)> {
    txn.environ()
        .iter()
        .filter_map(|(key, value)| match (key.into_string(), value.into_string()) {
            (Ok(key), Ok(value)) if !key.is_empty() => Some((key, value)),
            (key, _) => {
                warn!("A variable of the PAM session is left out, it is not UTF-8 or has no name: {key:?}");
                None
            }
        })
        .collect()
}

/// An exclusive lock on the user's terminal, released when dropped (when its file is closed).
struct TerminalLock {
    _terminal: File,
}

/// Lock the terminal at `path`, waiting while another dosr of the same pipeline authenticates on
/// it. `None` when there is no terminal or it cannot be locked: dosr then goes on without it.
fn lock_terminal(path: &Path) -> Option<TerminalLock> {
    let terminal = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOCTTY)
        .open(path)
        .ok()?;
    loop {
        // SAFETY: flock does not access memory, and the descriptor stays open during the call
        if unsafe { libc::flock(terminal.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Some(TerminalLock {
                _terminal: terminal,
            });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            debug!("cannot lock the terminal: {error}");
            return None;
        }
    }
}

/// Run `attempt` until it succeeds, at most `settings.tries` times. Only a wrong password
/// (`PAM_AUTH_ERR`) is asked again, after `settings.delay`: any other error, such as the end of
/// the input or an unknown user, stops at once.
fn retry_authentication<T, U>(
    mut state: T,
    settings: PasswordSettings,
    mut attempt: impl FnMut(T) -> Result<U, (T, ErrorCode)>,
) -> Result<U, ErrorCode> {
    let tries = settings.tries.get();
    let mut try_number = 1;
    loop {
        match attempt(state) {
            Ok(done) => return Ok(done),
            Err((next, error)) => {
                warn!("Authentication failed (try {try_number} of {tries}): {error}");
                if error != ErrorCode::AuthenticationError {
                    return Err(error);
                }
                std::thread::sleep(settings.delay.unsigned_abs());
                if try_number >= tries {
                    return Err(error);
                }
                eprintln_ignore_io_error!("Sorry, try again.");
                try_number += 1;
                state = next;
            }
        }
    }
}

pub fn start_session<'a>(
    authentication: SAuthentication,
    #[cfg_attr(not(feature = "timeout"), allow(unused_variables))] timeout: &STimeout,
    password: PasswordSettings,
    user: &Cred,
    cli: &Cli,
) -> SrResult<LibPamTransaction<Demux<SrConversationHandler<'a>>, SessionActive>> {
    // `dosr a | dosr b` would read both passwords from the terminal at the same time, each one
    // getting part of the keystrokes: the terminal is locked until this authentication is done,
    // and the other dosr checks its timestamp once it gets the lock (sudo-rs #1650).
    let _terminal_lock = if authentication.is_skip() || cli.stdin {
        None
    } else {
        lock_terminal(Path::new("/dev/tty"))
    };
    let need_password_auth = if authentication.is_skip() {
        warn!("Skipping password authentication (PAM session-only mode).");
        false
    } else {
        #[cfg(feature = "timeout")]
        {
            !timeout::is_valid(user, user, timeout)
        }
        #[cfg(not(feature = "timeout"))]
        {
            true
        }
    };

    debug!("need password authentication: {need_password_auth}");

    let conv = SrConversationHandler::builder()
        .maybe_prompt(cli.prompt.as_ref().map(|s| Cow::Owned(s.clone())))
        .use_stdin(cli.stdin)
        .build();

    let mut txn = TransactionBuilder::new_with_service(PAM_SERVICE)
        .username(&user.user.name)
        .build(conv.into_conversation())
        .map_err(|e| {
            error!("Failed to create PAM transaction: {e}");
            SrError::SystemError
        })?;
    set_pam_items(&mut txn, user).map_err(|e| {
        error!("Failed to set the terminal and the requesting user for PAM: {e}");
        SrError::SystemError
    })?;

    let txn = if need_password_auth {
        retry_authentication(txn, password, |txn| txn.authenticate(AuthnFlags::SILENT))
            .map_err(|e| {
                error!("Authentication failed: {e}");
                SrError::AuthenticationFailed
            })?
            .account_management(AuthnFlags::SILENT)
            .map_err(|e| {
                error!("Authentication failed: {}", e.1);
                SrError::AuthenticationFailed
            })?
    } else {
        txn.account_management(AuthnFlags::SILENT).map_err(|e| {
            error!("Account management failed: {}", e.1);
            SrError::AuthenticationFailed
        })?
    };
    check_pam_user(&txn, user)?;

    let txn = txn
        .establish_credentials()
        .map_err(|e| {
            error!("Failed to establish credentials: {}", e.1);
            SrError::SystemError
        })?
        .open_session()
        .map_err(|e| {
            error!("Failed to open session: {}", e.1);
            SrError::SystemError
        })?;
    check_pam_user(&txn, user)?;

    // Failing to save the cookie only means that the user will be asked to authenticate again;
    // a task that skips the authentication keeps no cookie
    #[cfg(feature = "timeout")]
    if let Err(e) = timeout::record_authentication(authentication, user, timeout) {
        error!("Failed to update timeout cookie: {e}");
    }

    Ok(txn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::SignedDuration;
    use nix::{libc::dev_t, unistd::Pid};
    use nonstick2::{EnvironMapMut, items::Items};
    use rootasrole_core::{
        Cred,
        database::options::{SAuthentication, STimeout, TimestampType},
    };
    use rootasrole_exec::terminal::TerminalExt;
    use serde_json::Map;
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt, sync::Mutex};
    use test_log::test;

    static PAM_TEST_LOCK: Mutex<()> = Mutex::new(());

    // Helper function to create a test user
    fn create_test_user() -> Cred {
        Cred::builder()
            .maybe_tty(Some(0 as dev_t))
            .ppid(Pid::from_raw(1))
            .groups()
            .unwrap()
            .user()
            .unwrap()
            .curdir()
            .unwrap()
            .build()
    }

    // Helper function to create a test timeout
    fn create_test_timeout() -> STimeout {
        STimeout {
            type_field: Some(TimestampType::TTY),
            duration: Some(SignedDuration::from_secs(300)), // 5 minutes
            max_usage: Some(3),
            extra_fields: Map::default(),
        }
    }

    fn pam_ready(user: &Cred) -> bool {
        let conv = SrConversationHandler::builder().no_interact(true).build();

        let Ok(txn) = TransactionBuilder::new_with_service(PAM_SERVICE)
            .username(&user.user.name)
            .build(conv.into_conversation())
        else {
            return false;
        };

        txn.account_management(AuthnFlags::SILENT).is_ok()
    }

    #[test]
    fn test_pam_items_are_set() {
        let user = create_test_user();
        let conv = SrConversationHandler::builder().no_interact(true).build();
        let Ok(mut txn) = TransactionBuilder::new_with_service(PAM_SERVICE)
            .username(&user.user.name)
            .build(conv.into_conversation())
        else {
            eprintln!("Skipping test, PAM is not available");
            return;
        };
        set_pam_items(&mut txn, &user).unwrap();
        assert_eq!(
            txn.items().remote_user().unwrap(),
            Some(std::ffi::OsString::from(&user.user.name))
        );
        // the terminal of the test, when it has one
        assert_eq!(
            txn.items().tty_name().unwrap(),
            std::io::stdin().ttyname().ok()
        );
    }

    #[test]
    fn test_sr_conversation_handler_new() {
        let handler = SrConversationHandler::builder()
            .prompt("Test prompt: ")
            .build();
        assert_eq!(handler.prompt, "Test prompt: ");
        assert!(handler.username.is_none());
        assert!(!handler.use_stdin);
        assert!(!handler.no_interact);
    }

    #[test]
    fn test_sr_conversation_handler_default() {
        let handler = SrConversationHandler::default();
        assert_eq!(handler.prompt, "Password: ");
        assert!(handler.username.is_none());
        assert!(!handler.use_stdin);
        assert!(!handler.no_interact);
    }

    #[test]
    fn test_is_pam_password_prompt_basic() {
        let handler = SrConversationHandler::default();

        // Test basic password prompts
        assert!(handler.is_pam_password_prompt(&"Password:"));
        assert!(handler.is_pam_password_prompt(&"Password: "));
        assert!(!handler.is_pam_password_prompt(&"Enter password:"));
        assert!(!handler.is_pam_password_prompt(&"Password required:"));
        assert!(!handler.is_pam_password_prompt(&""));
    }

    #[test]
    fn test_is_pam_password_prompt_with_username() {
        let handler = SrConversationHandler::builder()
            .username("testuser")
            .build();

        // Test user-specific password prompts
        assert!(handler.is_pam_password_prompt(&"testuser's Password:"));
        assert!(handler.is_pam_password_prompt(&"testuser's Password: "));
        assert!(!handler.is_pam_password_prompt(&"otheruser's Password:"));
        assert!(!handler.is_pam_password_prompt(&"testuser Password:")); // Missing apostrophe-s
        assert!(!handler.is_pam_password_prompt(&"testuser's Password:  "));
        assert!(!handler.is_pam_password_prompt(&"testuser's Password: x"));
        // the username is compared as text, never as a pattern
        let handler = SrConversationHandler::builder().username("a.b").build();
        assert!(handler.is_pam_password_prompt(&"a.b's Password:"));
        assert!(!handler.is_pam_password_prompt(&"axb's Password:"));
    }

    #[test]
    fn test_conversation_handler_error_msg() {
        let handler = SrConversationHandler::default();

        // This test verifies the error_msg method doesn't panic
        // In a real test environment, you might want to capture stderr
        handler.error_msg(OsStr::new("Test error message"));
    }

    #[test]
    fn test_conversation_handler_info_msg() {
        let handler = SrConversationHandler::default();

        // This test verifies the info_msg method doesn't panic
        // In a real test environment, you might want to capture stdout
        handler.info_msg(OsStr::new("Test info message"));
    }

    #[test]
    fn test_check_auth_skip_authentication() {
        let _ = env_logger::builder().is_test(true).try_init();
        let authentication = SAuthentication::Skip;
        let timeout = create_test_timeout();
        let user = create_test_user();

        let _guard = PAM_TEST_LOCK.lock().unwrap();

        if !pam_ready(&user) {
            eprintln!("Skipping: PAM backend not available in this test environment");
            return;
        }

        // When authentication is skipped, it should always succeed
        let cli = Cli::builder().prompt("Password: ").build();
        let result = start_session(
            authentication,
            &timeout,
            PasswordSettings::default(),
            &user,
            &cli,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_auth_required_but_valid_timeout() {
        let _guard = PAM_TEST_LOCK.lock().unwrap();
        if env!("RAR_PAM_SERVICE") == "dosr" {
            println!(
                "Skipping test_check_auth_required_but_valid_timeout because RAR_PAM_SERVICE is set to original dosr"
            );
            return;
        }
        let authentication = SAuthentication::Perform;
        let timeout = create_test_timeout();
        let user = create_test_user();

        let cli = Cli::builder().prompt("Password: ").build();
        let _ = start_session(
            authentication,
            &timeout,
            PasswordSettings::default(),
            &user,
            &cli,
        );
    }

    #[test]
    fn test_conversation_handler_no_interact_flag() {
        let handler = SrConversationHandler::builder().no_interact(true).build();

        let prompt_result = handler.prompt(OsStr::new("Test prompt"));
        assert!(matches!(prompt_result, Err(ErrorCode::ConversationError)));

        let masked_prompt_result = handler.masked_prompt(OsStr::new("Password:"));
        assert!(matches!(
            masked_prompt_result,
            Err(ErrorCode::ConversationError)
        ));
    }

    #[test]
    fn test_password_prompt_replacement() {
        let custom_prompt = "Enter your secret: ";
        let handler = SrConversationHandler::builder()
            .prompt(custom_prompt)
            .build();

        assert_eq!(handler.prompt, custom_prompt);

        assert!(handler.is_pam_password_prompt(&"Password:"));
        assert!(handler.is_pam_password_prompt(&"Password: "));
    }

    #[test]
    fn test_regex_patterns_edge_cases() {
        let handler = SrConversationHandler::builder()
            .username("user.with.dots")
            .build();

        // Test with username containing special regex characters
        assert!(handler.is_pam_password_prompt(&"user.with.dots's Password:"));

        // Test case sensitivity
        assert!(!handler.is_pam_password_prompt(&"password:"));
        assert!(!handler.is_pam_password_prompt(&"PASSWORD:"));

        // Test with extra spaces and characters
        assert!(!handler.is_pam_password_prompt(&"Password:  ")); // Extra spaces
        assert!(!handler.is_pam_password_prompt(&" Password:")); // Leading space
    }

    #[test]
    fn test_conversation_handler_fields() {
        let handler = SrConversationHandler::builder()
            .prompt("Custom: ")
            .use_stdin(true)
            .no_interact(true)
            .username("alice")
            .build();

        assert!(handler.use_stdin);
        assert!(handler.no_interact);
        assert_eq!(handler.username.as_ref().unwrap(), "alice");
        assert_eq!(handler.prompt, "Custom: ");
    }

    #[test]
    fn test_timeout_types() {
        let _guard = PAM_TEST_LOCK.lock().unwrap();
        let timeout_ppid = STimeout {
            type_field: Some(TimestampType::PPID),
            duration: Some(SignedDuration::from_secs(300)),
            max_usage: Some(1),
            extra_fields: Map::default(),
        };

        let timeout_tty = STimeout {
            type_field: Some(TimestampType::TTY),
            duration: Some(SignedDuration::from_secs(600)),
            max_usage: Some(5),
            extra_fields: Map::default(),
        };

        let user = create_test_user();
        if !pam_ready(&user) {
            eprintln!("Skipping: PAM backend not available in this test environment");
            return;
        }
        let auth = SAuthentication::Skip;

        let cli = Cli::builder().prompt("Password: ").build();
        // Test different timeout types don't cause errors
        assert!(
            start_session(
                auth,
                &timeout_ppid,
                PasswordSettings::default(),
                &user,
                &cli
            )
            .is_ok()
        );
        assert!(
            start_session(auth, &timeout_tty, PasswordSettings::default(), &user, &cli).is_ok()
        );
    }

    // Another dosr of the same pipeline opens the terminal on its own: while one holds the lock,
    // the other cannot take it, and it can once the lock is dropped.
    #[test]
    fn test_terminal_lock_is_exclusive_and_released_on_drop() {
        let pty = rootasrole_exec::pty::Pty::open().expect("open a pty");
        let path = Path::new(OsStr::from_bytes(pty.path.as_bytes()));
        let other = File::open(path).expect("open the terminal again");
        // SAFETY: flock does not access memory, and `other` stays open while the closure lives
        let try_lock = || unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };

        let lock = lock_terminal(path).expect("lock the terminal");
        assert_eq!(try_lock(), -1, "the terminal is locked");
        drop(lock);
        assert_eq!(try_lock(), 0, "the lock is released");
    }

    #[test]
    fn test_no_terminal_lock_without_a_terminal() {
        assert!(lock_terminal(Path::new("/nonexistent/tty")).is_none());
    }

    fn quick(tries: u8, delay_ms: i64) -> PasswordSettings {
        PasswordSettings {
            tries: std::num::NonZeroU8::new(tries).unwrap(),
            delay: SignedDuration::from_millis(delay_ms),
        }
    }

    #[test]
    fn test_retry_authentication_until_the_password_is_right() {
        let mut calls = 0;
        let result = retry_authentication((), quick(3, 10), |state| {
            calls += 1;
            if calls < 2 {
                Err((state, ErrorCode::AuthenticationError))
            } else {
                Ok("authenticated")
            }
        });
        assert_eq!(result, Ok("authenticated"));
        assert_eq!(calls, 2);
    }

    // a delay after each wrong password, the last one included, then dosr gives up
    #[test]
    fn test_retry_authentication_gives_up_after_the_tries() {
        let start = std::time::Instant::now();
        let mut calls = 0;
        let result: Result<(), _> = retry_authentication((), quick(3, 50), |state| {
            calls += 1;
            Err((state, ErrorCode::AuthenticationError))
        });
        assert_eq!(result, Err(ErrorCode::AuthenticationError));
        assert_eq!(calls, 3);
        assert!(start.elapsed() >= std::time::Duration::from_millis(150));
    }

    // the end of the input or an unknown user is not a wrong password: no retry, no delay
    #[test]
    fn test_retry_authentication_stops_on_other_errors() {
        for error in [
            ErrorCode::ConversationError,
            ErrorCode::UserUnknown,
            ErrorCode::MaxTries,
        ] {
            let start = std::time::Instant::now();
            let mut calls = 0;
            let result: Result<(), _> = retry_authentication((), quick(3, 1000), |state| {
                calls += 1;
                Err((state, error))
            });
            assert_eq!(result, Err(error));
            assert_eq!(calls, 1);
            assert!(start.elapsed() < std::time::Duration::from_millis(500));
        }
    }

    #[test]
    fn test_same_pam_user() {
        assert!(same_pam_user(Some(OsStr::new("alice")), "alice"));
        assert!(!same_pam_user(Some(OsStr::new("root")), "alice"));
        assert!(!same_pam_user(None, "alice"));
    }

    #[test]
    fn test_session_env_reads_the_pam_environment() {
        let user = create_test_user();
        let conv = SrConversationHandler::builder().no_interact(true).build();
        let Ok(mut txn) = TransactionBuilder::new_with_service(PAM_SERVICE)
            .username(&user.user.name)
            .build(conv.into_conversation())
        else {
            eprintln!("Skipping test, PAM is not available");
            return;
        };
        // what a module such as pam_env does (pam_putenv(3))
        {
            let mut environ = txn.environ_mut();
            environ.insert("PAM_TEST_VAR", "value=with=equals");
            environ.insert("PAM_TEST_EMPTY", "");
            environ.insert(
                OsStr::from_bytes(b"PAM_TEST_\xff"),
                "a name that is not UTF-8",
            );
            environ.insert("PAM_TEST_BYTES", OsStr::from_bytes(b"\xff"));
        }
        let env = session_env(&txn);
        let pam_test_vars: Vec<_> = env
            .iter()
            .filter(|(key, _)| key.starts_with("PAM_TEST_"))
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        assert_eq!(pam_test_vars.len(), 2, "{pam_test_vars:?}");
        assert!(pam_test_vars.contains(&("PAM_TEST_VAR", "value=with=equals")));
        assert!(pam_test_vars.contains(&("PAM_TEST_EMPTY", "")));
    }
}
