#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use rootasrole::fuzzing::parse_args;

/// Options of dosr, and whether they take a value.
/// `-v` and `--version` are left out: dosr exits the process when it reads them.
const OPTIONS: &[(&str, bool)] = &[
    ("-u", true),
    ("--user", true),
    ("-g", true),
    ("--group", true),
    ("-S", false),
    ("--stdin", false),
    ("-r", true),
    ("--role", true),
    ("-t", true),
    ("--task", true),
    ("-E", false),
    ("--preserve-env", false),
    ("-D", true),
    ("--chdir", true),
    ("-K", false),
    ("--remove-timestamp", false),
    ("-p", true),
    ("--prompt", true),
    ("-i", false),
    ("--info", false),
    ("-h", false),
    ("--help", false),
];

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
        Some(String::from_utf8_lossy(value).into_owned())
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Input(data);
    let Some(option_count) = input.byte() else {
        return;
    };
    let mut args = vec!["dosr".to_owned()];
    for _ in 0..option_count % 16 {
        let Some(selector) = input.byte() else {
            break;
        };
        let (option, takes_value) = OPTIONS[usize::from(selector) % OPTIONS.len()];
        args.push(option.to_owned());
        if takes_value {
            // a value may look like an option, it must still be taken as a value
            let Some(value) = input.string() else {
                // missing value at the end of the command line: must not panic
                let _ = parse_args(&args);
                return;
            };
            args.push(value);
        }
    }

    let Some(command) = input.string() else {
        let _ = parse_args(&args);
        return;
    };
    if command.is_empty() || command.starts_with('-') {
        return;
    }
    args.push(command.clone());
    let mut tail = Vec::new();
    while let Some(arg) = input.string() {
        tail.push(arg);
    }
    args.extend(tail.iter().cloned());

    if let Some(parsed) = parse_args(&args) {
        // everything after the command belongs to the command, never to dosr
        assert_eq!(parsed.cmd_path, Path::new(&command));
        // and they are passed as they are given
        assert_eq!(parsed.cmd_args, tail);
    }
});
