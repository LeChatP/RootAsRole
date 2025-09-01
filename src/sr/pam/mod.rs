use std::{borrow::Cow, ffi::CStr, ops::Deref};

use bon::Builder;
use log::{debug, error, info, warn};
use nonstick::{
    AuthnFlags, ConversationAdapter, ErrorCode, Result as PamResult, Transaction,
    TransactionBuilder,
};
use pcre2::bytes::RegexBuilder;

#[cfg(feature = "timeout")]
use crate::timeout;
use crate::{
    error::{SrError, SrResult},
    Cli,
};
use rar_common::{
    database::options::{SAuthentication, STimeout},
    Cred,
};

use self::rpassword::Terminal;

#[allow(dead_code, reason = "This file is part of sudo-rs.")]
mod cutils;
#[allow(dead_code, reason = "This file is part of sudo-rs.")]
mod rpassword;
#[allow(dead_code, reason = "This file is part of sudo-rs.")]
mod securemem;

const PAM_SERVICE: &str = env!("RAR_PAM_SERVICE");
pub(crate) const PAM_PROMPT: &str = "Password: ";

#[derive(Builder)]
struct SrConversationHandler<'a> {
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
            Terminal::open_stdie()
        } else {
            Terminal::open_tty()
        }
    }
    fn is_pam_password_prompt(&self, prompt: &impl AsRef<str>) -> bool {
        let pam_prompt = prompt.as_ref();
        RegexBuilder::new()
            .build("^Password: ?$")
            .unwrap()
            .is_match(pam_prompt.as_bytes())
            .is_ok_and(|f| f)
            || self.username.as_ref().is_some_and(|username| {
                RegexBuilder::new()
                    .build(&format!("^{}'s Password: ?$", username))
                    .unwrap()
                    .is_match(pam_prompt.as_bytes())
                    .is_ok_and(|f| f)
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
        Ok(std::ffi::OsString::from(
            String::from_utf8_lossy(read.deref()).to_string(),
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
        let os_str = CStr::from_bytes_until_nul(read.deref()).unwrap();
        Ok(std::ffi::OsString::from(os_str.to_str().unwrap()))
    }

    fn error_msg(&self, message: impl AsRef<std::ffi::OsStr>) {
        error!("{}", message.as_ref().to_string_lossy());
        eprintln!("{}", message.as_ref().to_string_lossy());
    }

    fn info_msg(&self, message: impl AsRef<std::ffi::OsStr>) {
        info!("{}", message.as_ref().to_string_lossy());
        println!("{}", message.as_ref().to_string_lossy());
    }
}

pub(super) fn check_auth(
    authentication: &SAuthentication,
    #[cfg_attr(not(feature = "timeout"), allow(unused_variables))] timeout: &STimeout,
    user: &Cred,
    cli: &Cli,
) -> SrResult<()> {
    if authentication.is_skip() {
        warn!("Skipping authentication, this is a security risk!");
        return Ok(());
    }
    #[cfg(feature = "timeout")]
    let is_valid = timeout::is_valid(user, user, timeout);
    #[cfg(not(feature = "timeout"))]
    let is_valid = false;
    debug!("need to re-authenticate : {}", !is_valid);
    if !is_valid {
        let conv = SrConversationHandler::builder()
            .maybe_prompt(cli.prompt.as_ref().map(|s| Cow::Borrowed(s.as_str())))
            .use_stdin(cli.stdin)
            .build();
        let mut txn = TransactionBuilder::new_with_service(PAM_SERVICE)
            .username(&user.user.name)
            .build(conv.into_conversation())
            .map_err(|e| {
                error!("Failed to create PAM transaction: {}", e);
                SrError::SystemError
            })?;
        txn.authenticate(AuthnFlags::SILENT).map_err(|e| {
            error!("Authentication failed: {}", e);
            SrError::AuthenticationFailed
        })?;
        txn.account_management(AuthnFlags::SILENT).map_err(|e| {
            error!("Account management failed: {}", e);
            SrError::AuthenticationFailed
        })?;
    }
    #[cfg(feature = "timeout")]
    timeout::update_cookie(user, user, timeout).map_err(|e| {
        error!("Failed to update timeout cookie: {}", e);
        SrError::SystemError
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use nix::{libc::dev_t, unistd::Pid};
    use rar_common::{
        database::options::{SAuthentication, STimeout, TimestampType},
        Cred,
    };
    use std::ffi::OsStr;

    // Helper function to create a test user
    fn create_test_user() -> Cred {
        Cred::builder()
            .maybe_tty(Some(0 as dev_t))
            .ppid(Pid::from_raw(1))
            .build()
    }

    // Helper function to create a test timeout
    fn create_test_timeout() -> STimeout {
        STimeout {
            type_field: Some(TimestampType::TTY),
            duration: Some(Duration::seconds(300)), // 5 minutes
            max_usage: Some(3),
            _extra_fields: Default::default(),
        }
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
        let authentication = SAuthentication::Skip;
        let timeout = create_test_timeout();
        let user = create_test_user();

        // When authentication is skipped, it should always succeed
        let result = check_auth(
            &authentication,
            &timeout,
            &user,
            &Cli::builder().prompt("Password: ").build(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_auth_required_but_valid_timeout() {
        if env!("RAR_PAM_SERVICE") == "dosr" {
            println!("Skipping test_check_auth_required_but_valid_timeout because RAR_PAM_SERVICE is set to original dosr");
            return;
        }
        let authentication = SAuthentication::Perform;
        let timeout = create_test_timeout();
        let user = create_test_user();

        let _ = check_auth(
            &authentication,
            &timeout,
            &user,
            &Cli::builder().prompt("Password: ").build(),
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
        let timeout_ppid = STimeout {
            type_field: Some(TimestampType::PPID),
            duration: Some(Duration::seconds(300)),
            max_usage: Some(1),
            _extra_fields: Default::default(),
        };

        let timeout_tty = STimeout {
            type_field: Some(TimestampType::TTY),
            duration: Some(Duration::seconds(600)),
            max_usage: Some(5),
            _extra_fields: Default::default(),
        };

        let user = create_test_user();
        let auth = SAuthentication::Skip;

        // Test different timeout types don't cause errors
        assert!(check_auth(
            &auth,
            &timeout_ppid,
            &user,
            &Cli::builder().prompt("Password: ").build()
        )
        .is_ok());
        assert!(check_auth(
            &auth,
            &timeout_tty,
            &user,
            &Cli::builder().prompt("Password: ").build()
        )
        .is_ok());
    }
}
