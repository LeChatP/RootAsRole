#![no_main]

use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nix::unistd::{Pid, Uid, User};
use rootasrole::fuzzing::decide;
use rootasrole_core::Cred;

/// A policy document of the repository, embedded so that the target never reads files.
macro_rules! policy {
    ($path:literal) => {
        (
            $path,
            include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../", $path)),
        )
    };
}

/// Policies with the users they grant a role to.
const POLICIES: &[((&str, &[u8]), &[&str])] = &[
    (policy!("tests/fixtures/env_override.json"), &["root"]),
    (
        policy!("tests/fixtures/multi_role.json"),
        &["root", "nobody"],
    ),
    (policy!("tests/fixtures/perform_auth.json"), &["root"]),
    (policy!("tests/fixtures/user_group.json"), &["root"]),
    (
        policy!("resources/rootasrole.json"),
        &["root", "ROOTADMINISTRATOR"],
    ),
];

/// Options of dosr, and whether they take a value. `-v` exits the process, it is left out.
const OPTIONS: &[(&str, bool)] = &[
    ("-u", true),
    ("-g", true),
    ("-S", false),
    ("-r", true),
    ("-t", true),
    ("-E", false),
    ("-D", true),
    ("-K", false),
    ("-p", true),
    ("-i", false),
    ("-h", false),
];
const ROLES: &[&str] = &[
    "env", "A", "B", "C", "r_auth", "r_root", "allowed", "denied",
];
const COMMANDS: &[&str] = &[
    "/usr/bin/env",
    "env",
    "/usr/bin/ls",
    "ls",
    "/bin/sh",
    "true",
];
const PATHS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "bin", "", "/nonexistent"];

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn string(&mut self) -> Option<String> {
        let len = usize::from(self.byte()?).min(self.0.len());
        let (value, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(String::from_utf8_lossy(value).replace('\0', "?"))
    }

    /// A value from `known`, or an arbitrary string.
    fn pick(&mut self, known: &[&str]) -> Option<String> {
        let selector = usize::from(self.byte()?);
        known
            .get(selector % (known.len() + 1))
            .map(|known| (*known).to_owned())
            .or_else(|| self.string())
    }
}

fn users() -> &'static [Cred] {
    static USERS: OnceLock<Vec<Cred>> = OnceLock::new();
    USERS.get_or_init(|| {
        [Uid::from_raw(0), Uid::current(), Uid::from_raw(65534)]
            .into_iter()
            .filter_map(|uid| User::from_uid(uid).ok().flatten())
            .map(|user| Cred {
                user,
                groups: Vec::new(),
                tty: None,
                ppid: Pid::from_raw(1),
                curdir: PathBuf::from("/"),
            })
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let (Some(policy), Some(user), Some(option_count)) = (input.byte(), input.byte(), input.byte())
    else {
        return;
    };
    let ((name, policy), granted) = POLICIES[usize::from(policy) % POLICIES.len()];
    let cred = &users()[usize::from(user) % users().len()];

    let mut args = vec!["dosr".to_owned()];
    for _ in 0..option_count % 8 {
        let Some(selector) = input.byte() else {
            return;
        };
        let (option, takes_value) = OPTIONS[usize::from(selector) % OPTIONS.len()];
        args.push(option.to_owned());
        if takes_value {
            let Some(value) = input.pick(ROLES) else {
                return;
            };
            args.push(value);
        }
    }
    let Some(command) = input.pick(COMMANDS) else {
        return;
    };
    if command.is_empty() || command.starts_with('-') {
        return;
    }
    args.push(command);

    let mut env_path = Vec::new();
    let mut env_vars = Vec::new();
    for _ in 0..input.byte().unwrap_or_default() % 4 {
        env_path.extend(input.pick(PATHS));
    }
    for _ in 0..input.byte().unwrap_or_default() % 4 {
        if let (Some(key), Some(value)) = (input.string(), input.string()) {
            if !key.is_empty() && !key.contains('=') {
                env_vars.push((key, value));
            }
        }
    }
    while let Some(arg) = input.string() {
        args.push(arg);
    }
    let env_path: Vec<&str> = env_path.iter().map(String::as_str).collect();

    let Some(decision) = decide(&args, cred, policy, env_vars, &env_path) else {
        return;
    };
    if decision.fully_matching {
        assert!(
            granted.contains(&cred.user.name.as_str()),
            "{} granted by {name}: {decision:?}",
            cred.user.name
        );
        assert!(decision.final_path.is_absolute(), "{decision:?}");
    }
});
