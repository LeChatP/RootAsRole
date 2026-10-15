#![no_main]

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nix::unistd::{Pid, Uid, User};
use rootasrole::fuzzing::{check_env, decide, tz_is_safe};
use rootasrole_core::Cred;

/// Policy whose `env` role is granted to root, with `KEEP` kept, `TZ` checked and `DELETE` deleted.
const POLICY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../tests/fixtures/env_override.json"
));

/// Identity variables set by dosr, that the caller must never be able to choose.
const IDENTITY: &[&str] = &[
    "RAR_UID",
    "RAR_GID",
    "RAR_USER",
    "SUDO_UID",
    "SUDO_GID",
    "SUDO_USER",
];

fn variable_name(selector: u8) -> &'static str {
    match selector % 20 {
        0 => "KEEP",
        1 => "DELETE",
        2 => "TZ",
        3 => "PATH",
        4 => "HOME",
        5 => "TERM",
        6 => "FOO",
        7 => "LANG",
        8 => "LC_ALL",
        9 => "SHELL",
        10 => "USER",
        11 => "LOGNAME",
        12 => "LD_PRELOAD",
        13 => "BASH_ENV",
        14 => "IFS",
        15 => "SUDO_UID",
        16 => "SUDO_USER",
        17 => "RAR_UID",
        18 => "RAR_USER",
        _ => "RAR_FUZZ_VALUE",
    }
}

fn policy_arguments(selector: u8) -> Vec<&'static str> {
    let mut args = vec!["dosr"];
    if selector & 1 != 0 {
        args.push("-E");
    }
    match (selector >> 1) % 4 {
        0 => {}
        1 => args.extend(["--role", "env", "--task", "allowed"]),
        2 => args.extend(["--role", "env", "--task", "denied"]),
        _ => args.extend(["--role", "env"]),
    }
    args.push("/usr/bin/env");
    args
}

fn root() -> &'static Cred {
    static ROOT: OnceLock<Cred> = OnceLock::new();
    ROOT.get_or_init(|| Cred {
        user: User::from_uid(Uid::from_raw(0))
            .ok()
            .flatten()
            .expect("root must exist"),
        groups: Vec::new(),
        tty: None,
        ppid: Pid::from_raw(1),
        curdir: PathBuf::from("/"),
    })
}

/// A TZ value accepted by dosr must stay below the zoneinfo directory.
fn assert_tz_contained(value: &str) {
    let tz = value.strip_prefix(':').unwrap_or(value);
    assert!(!tz.starts_with('/'), "absolute TZ accepted: {value:?}");
    assert!(
        tz.chars().all(|c| c.is_ascii_graphic()),
        "TZ with non printable characters accepted: {value:?}"
    );
    assert!(
        Path::new(tz)
            .components()
            .all(|c| c != Component::ParentDir),
        "TZ with a '..' component accepted: {value:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut bytes = data.iter().copied();
    let Some(options) = bytes.next() else {
        return;
    };
    let mut variables = Vec::new();
    while let (Some(selector), Some(len)) = (bytes.next(), bytes.next()) {
        let value: Vec<u8> = bytes.by_ref().take(usize::from(len)).collect();
        // an environment value cannot contain a NUL byte
        let value = String::from_utf8_lossy(&value).replace('\0', "?");
        variables.push((variable_name(selector).to_owned(), value));
        if variables.len() == 32 {
            break;
        }
    }

    for (key, value) in &variables {
        let accepted = check_env(key, value);
        if key == "TZ" {
            assert_eq!(accepted, tz_is_safe(value));
            if accepted {
                assert_tz_contained(value);
            }
        } else if accepted {
            assert!(!value.contains(['/', '%']));
        }
    }

    let cred = root();
    let Some(decision) = decide(
        policy_arguments(options),
        cred,
        POLICY,
        variables,
        &["/usr/bin", "/bin"],
    ) else {
        return;
    };
    assert!(!decision.env.contains_key("DELETE"));
    if let Some(tz) = decision.env.get("TZ") {
        assert_tz_contained(tz);
    }
    for key in IDENTITY {
        let value = decision.env.get(*key).expect("dosr always sets it");
        let expected = match *key {
            "RAR_UID" | "SUDO_UID" => cred.user.uid.to_string(),
            "RAR_GID" | "SUDO_GID" => cred.user.gid.to_string(),
            _ => cred.user.name.clone(),
        };
        assert_eq!(value, &expected, "{key} chosen by the caller");
    }
});
