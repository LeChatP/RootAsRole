//! Entry points for the fuzz targets in `fuzz/`, only built with the `fuzzing` feature.
//! They are thin wrappers without side effects, so enabling this feature never changes `dosr`.

use std::{cell::Cell, collections::HashMap, io, ops::Deref, path::PathBuf};

use rootasrole_core::{Cred, database::FilterMatcher};
use serde::de::DeserializeSeed;

use crate::pam::securemem::PamBuffer;

pub use crate::finder::cmd::evaluate_command_match;
pub use crate::procfs::parse_stat_field;
pub use rootasrole_core::database::env::check_env;

/// Whether a value of `TZ` is safe, the check applied when `TZ` is in the check list.
#[must_use]
pub fn tz_is_safe(value: &str) -> bool {
    check_env("TZ", value)
}

/// A password read by `dosr`, wiped from memory when dropped.
pub struct Password(PamBuffer);

impl Deref for Password {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Read a password the way `dosr` reads it from a terminal.
/// # Errors
/// Same errors as reading the password in `dosr`.
pub fn read_password(source: &mut impl io::Read) -> io::Result<Password> {
    crate::pam::rpassword::read_unbuffered(source).map(Password)
}

/// Command line of `dosr`, as parsed by `dosr`.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ParsedArgs {
    pub opt_filter: Option<FilterMatcher>,
    pub prompt: Option<String>,
    pub info: bool,
    pub help: bool,
    pub cmd_path: PathBuf,
    pub cmd_args: Vec<String>,
    pub stdin: bool,
    pub del_ts: bool,
}

/// Parse `args` like the command line of `dosr`, the first argument is the program name.
#[must_use]
pub fn parse_args<I, S>(args: I) -> Option<ParsedArgs>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    crate::getopt(args).ok().map(|cli| ParsedArgs {
        opt_filter: cli.opt_filter,
        prompt: cli.prompt,
        info: cli.info,
        help: cli.help,
        cmd_path: cli.cmd_path,
        cmd_args: cli.cmd_args,
        stdin: cli.stdin,
        del_ts: cli.del_ts,
    })
}

/// Settings chosen by `dosr` for a command line.
#[derive(Debug)]
pub struct Decision {
    pub fully_matching: bool,
    pub final_path: PathBuf,
    pub role: String,
    pub task: Option<String>,
    pub env: HashMap<String, String>,
}

thread_local! {
    static PLUGINS_REGISTERED: Cell<bool> = const { Cell::new(false) };
}

/// Choose the execution settings of `args` for `cred`, like `dosr` does before authentication.
///
/// The first argument is the program name, `policy` is the content of a JSON policy file (the
/// roles, without the storage settings of the root file). Nothing is read from the disk.
/// Returns `None` when `dosr` would stop with an error.
#[must_use]
pub fn decide<I, S>(
    args: I,
    cred: &Cred,
    policy: &[u8],
    env_vars: Vec<(String, String)>,
    env_path: &[&str],
) -> Option<Decision>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    // the plugin API is thread-local, like in dosr
    PLUGINS_REGISTERED.with(|registered| {
        if !registered.replace(true) {
            crate::finder::api::register_plugins();
        }
    });
    let cli = crate::getopt(args).ok()?;
    let data = crate::finder::de::ConfigFinderDeserializer { cli: &cli, cred }
        .deserialize(&mut serde_json::Deserializer::from_slice(policy))
        .ok()?;
    let settings =
        crate::finder::BestExecSettings::retrieve_settings(&cli, cred, &data, env_vars, env_path)
            .ok()?;
    Some(Decision {
        fully_matching: settings.score.fully_matching(),
        final_path: settings.final_path,
        role: settings.role,
        task: settings.task,
        env: settings.env,
    })
}

#[cfg(test)]
mod tests {
    use nix::unistd::{Pid, Uid, User};

    use super::*;

    #[test]
    fn test_decide_reads_the_policy() {
        let policy = include_bytes!("../../tests/fixtures/env_override.json");
        let cred = Cred {
            user: User::from_uid(Uid::from_raw(0))
                .ok()
                .flatten()
                .unwrap_or_else(|| panic!("root must exist")),
            groups: Vec::new(),
            tty: None,
            ppid: Pid::from_raw(1),
            curdir: PathBuf::from("/"),
        };
        let env = vec![
            ("KEEP".to_string(), "kept".to_string()),
            ("DELETE".to_string(), "deleted".to_string()),
            ("TZ".to_string(), "../../etc/shadow".to_string()),
        ];
        let decision = decide(
            ["dosr", "/usr/bin/env"],
            &cred,
            policy,
            env,
            &["/usr/bin", "/bin"],
        );
        let decision = decision.unwrap_or_else(|| panic!("root holds the env role"));
        assert!(decision.fully_matching);
        assert_eq!(decision.role, "env");
        assert_eq!(decision.final_path, PathBuf::from("/usr/bin/env"));
        assert_eq!(decision.env.get("KEEP").map(String::as_str), Some("kept"));
        assert!(!decision.env.contains_key("DELETE"));
        assert!(!decision.env.contains_key("TZ"));
        // the policy is not valid JSON
        assert!(decide(["dosr", "/usr/bin/env"], &cred, b"{", Vec::new(), &[]).is_none());
    }
}
