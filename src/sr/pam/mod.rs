use std::{
    error::Error,
    ffi::{CStr, CString},
    ops::Deref,
};

use log::{debug, error, info, warn};
use pam_client2::{Context, ConversationHandler, ErrorCode, Flag};
use pcre2::bytes::RegexBuilder;

use crate::timeout;
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
const PAM_SERVICE: &str = "sr";
#[cfg(test)]
const PAM_SERVICE: &str = "sr_test";

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
    fn is_pam_password_prompt(&self, prompt: &CStr) -> bool {
        let pam_prompt = prompt.to_string_lossy();
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

impl ConversationHandler for SrConversationHandler {
    fn prompt_echo_on(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
        if self.no_interact {
            return Err(ErrorCode::CONV_ERR);
        }
        let mut term = self.open().map_err(|_| ErrorCode::CONV_ERR)?;
        term.prompt(prompt.to_string_lossy().as_ref())
            .map_err(|_| ErrorCode::CONV_ERR)?;
        let read = term.read_cleartext().map_err(|_| ErrorCode::BUF_ERR)?;
        Ok(unsafe { CString::from_vec_unchecked(read.deref().to_vec()) })
    }

    fn prompt_echo_off(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
        if self.no_interact {
            return Err(ErrorCode::CONV_ERR);
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

    fn text_info(&mut self, msg: &CStr) {
        info!("{}", msg.to_string_lossy());
        println!("{}", msg.to_string_lossy());
    }

    fn error_msg(&mut self, msg: &CStr) {
        error!("{}", msg.to_string_lossy());
        eprintln!("{}", msg.to_string_lossy());
    }
}

pub(super) fn check_auth(
    authentication: &SAuthentication,
    timeout: &STimeout,
    user: &Cred,
    prompt: &str,
) -> Result<(), Box<dyn Error>> {
    if authentication.is_skip() {
        warn!("Skipping authentication, this is a security risk!");
        return Ok(());
    }
    let is_valid = timeout::is_valid(user, user, &timeout);
    debug!("need to re-authenticate : {}", !is_valid);
    if !is_valid {
        let conv = SrConversationHandler::new(prompt);
        let mut context = Context::new(PAM_SERVICE, Some(&user.user.name), conv)
            .expect("Failed to initialize PAM");
        context.authenticate(Flag::SILENT)?;
        context.acct_mgmt(Flag::SILENT)?;
    }
    timeout::update_cookie(user, user, &timeout)?;
    Ok(())
}
