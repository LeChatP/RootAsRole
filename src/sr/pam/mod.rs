use std::{ffi::CStr, ops::Deref};

use log::{debug, error, info, warn};
use nonstick::{
    AuthnFlags, ConversationAdapter, ErrorCode, Result as PamResult, Transaction,
    TransactionBuilder,
};
use pcre2::bytes::RegexBuilder;

use crate::{
    error::{SrError, SrResult},
    timeout,
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

#[cfg(not(test))]
const PAM_SERVICE: &str = "dosr";
#[cfg(test)]
const PAM_SERVICE: &str = "dosr_test";

pub(crate) const PAM_PROMPT: &str = "Password: ";

struct SrConversationHandler {
    username: Option<String>,
    prompt: String,
    use_stdin: bool,
    no_interact: bool,
}

impl SrConversationHandler {
    fn new(prompt: &str) -> Self {
        SrConversationHandler {
            prompt: prompt.to_string(),
            username: None,
            use_stdin: false,
            no_interact: false,
        }
    }
    fn open(&self) -> std::io::Result<Terminal> {
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

impl Default for SrConversationHandler {
    fn default() -> Self {
        SrConversationHandler {
            prompt: "Password: ".to_string(),
            username: None,
            use_stdin: false,
            no_interact: false,
        }
    }
}

impl ConversationAdapter for SrConversationHandler {
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
            prompt.as_ref().to_string_lossy().to_string()
        };
        let mut term = self.open().map_err(|_| ErrorCode::ConversationError)?;
        term.prompt(&pam_prompt)
            .map_err(|_| ErrorCode::ConversationError)?;
        let read = term.read_password().map_err(|_| ErrorCode::BufferError)?;
        let os_str = CStr::from_bytes_until_nul(&read.deref()).unwrap();
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
    timeout: &STimeout,
    user: &Cred,
    prompt: &str,
) -> SrResult<()> {
    if authentication.is_skip() {
        warn!("Skipping authentication, this is a security risk!");
        return Ok(());
    }
    let is_valid = timeout::is_valid(user, user, &timeout);
    debug!("need to re-authenticate : {}", !is_valid);
    if !is_valid {
        let conv = SrConversationHandler::new(prompt);
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
    timeout::update_cookie(user, user, &timeout).map_err(|e| {
        error!("Failed to update timeout cookie: {}", e);
        SrError::SystemError
    })?;
    Ok(())
}
