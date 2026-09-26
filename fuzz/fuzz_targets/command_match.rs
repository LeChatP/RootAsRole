#![no_main]

use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use rootasrole_core::database::score::CmdMin;

fn set_dosr_binary() {
    let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/fuzz_bins/rootasrole_command_match");
    unsafe { std::env::set_var("DOSR_BIN", binary) };
}

#[path = "../../src/dosr/finder/cmd.rs"]
mod command;

fuzz_target!(|data: &[u8]| {
    set_dosr_binary();
    if data.is_empty() {
        return;
    }

    let path_end = data.len() / 4;
    let role_end = data.len() / 2;
    let environment_end = data.len() * 3 / 4;

    let command_path = PathBuf::from(String::from_utf8_lossy(&data[..path_end]).into_owned());
    let role_command = String::from_utf8_lossy(&data[path_end..role_end]);
    let environment_values: Vec<String> = String::from_utf8_lossy(&data[role_end..environment_end])
        .split(':')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect();
    let environment: Vec<&str> = environment_values.iter().map(String::as_str).collect();
    let arguments: Vec<String> = String::from_utf8_lossy(&data[environment_end..])
        .split('\n')
        .map(str::to_owned)
        .collect();
    let mut final_path = None;

    let result = command::evaluate_command_match(
        &environment,
        &command_path,
        &arguments,
        &role_command,
        CmdMin::empty(),
        &mut final_path,
    );

    if shell_words::split(&role_command).is_err() {
        assert!(!result.matching());
        assert!(final_path.is_none());
    }
});
