#![no_main]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

use libfuzzer_sys::fuzz_target;

fn set_dosr_binary() {
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/fuzz_bins/rootasrole_environment");
    unsafe { std::env::set_var("DOSR_BIN", binary) };
}

fn take_value<'a, I>(bytes: &mut I) -> String
where
    I: Iterator<Item = &'a u8>,
{
    let length = bytes.next().copied().unwrap_or_default() as usize;
    let value: Vec<_> = bytes.by_ref().take(length).copied().collect();
    String::from_utf8_lossy(&value).replace('\0', "?")
}

fn variable_name(selector: u8) -> &'static str {
    match selector % 16 {
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
        _ => "RAR_FUZZ_VALUE",
    }
}

fn policy_arguments(selector: u8, preserve_environment: bool) -> Vec<String> {
    let mut arguments = Vec::with_capacity(6);
    if preserve_environment {
        arguments.push("-E".to_owned());
    }

    match selector % 4 {
        0 => {}
        1 => arguments.extend(["--role", "env", "--task", "allowed"].map(str::to_owned)),
        2 => arguments.extend(["--role", "env", "--task", "denied"].map(str::to_owned)),
        _ => arguments.extend(["--role", "env"].map(str::to_owned)),
    }
    arguments.push("/usr/bin/env".to_owned());
    arguments
}

fuzz_target!(|data: &[u8]| {
    set_dosr_binary();
    let Ok(binary) = std::env::var("DOSR_BIN") else {
        return;
    };
    let mut bytes = data.iter();
    let options = bytes.next().copied().unwrap_or_default();
    let variable_count = bytes.next().copied().unwrap_or_default() as usize;
    let mut variables = Vec::with_capacity(variable_count.min(32));

    for _ in 0..variable_count.min(32) {
        let selector = bytes.next().copied().unwrap_or_default();
        variables.push((variable_name(selector), take_value(&mut bytes)));
    }

    let arguments = policy_arguments(options >> 1, options & 1 != 0);
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", "xterm")
        .env("HOME", "/tmp")
        .envs(variables)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let Ok(status) = command.status() else {
        return;
    };

    if status.code() == Some(101) {
        panic!("dosr panicked while handling environment input");
    }

    if ExitStatusExt::signal(&status).is_some() {
        panic!("dosr terminated by a signal while handling environment input");
    }
});
