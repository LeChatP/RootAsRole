#![no_main]

use std::path::{Component, Path, PathBuf};

use libfuzzer_sys::fuzz_target;
use rootasrole::fuzzing::evaluate_command_match;
use rootasrole_core::database::score::CmdMin;

fuzz_target!(|data: &[u8]| {
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

    let result = evaluate_command_match(
        &environment,
        &command_path,
        &arguments,
        &role_command,
        CmdMin::empty(),
        &mut final_path,
    );

    let Ok(role_words) = shell_words::split(&role_command) else {
        assert!(!result.matching());
        assert!(final_path.is_none());
        return;
    };
    if !result.matching() {
        return;
    }
    // a match is only possible against a role command, and `**` is the only path matching anything
    let role_path = &role_words[0];
    if role_path != "**" {
        let final_path = final_path.expect("a matching path must be selected");
        assert!(final_path.is_absolute());
        // without pattern syntax (globset), the selected path is exactly the one of the role
        if role_path.contains(['*', '?', '[', '{', '\\']) {
            // a path matched by a pattern never has `.` or `..` components
            assert!(
                final_path
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
                "{final_path:?} matched {role_path:?}"
            );
        } else {
            assert_eq!(final_path, Path::new(role_path));
        }
    }
    // literal arguments of the role must be exactly the arguments given
    if role_words.len() > 1 {
        let role_args = shell_words::join(&role_words[1..]);
        let is_regex = role_args.starts_with("'^") && role_args.ends_with("$'");
        if !is_regex {
            assert_eq!(shell_words::join(&arguments), role_args);
        }
    }
});
