#![no_main]

use std::os::unix::prelude::ExitStatusExt;
use std::process::{Command, Stdio};

use libfuzzer_sys::fuzz_target;

fn take_value<'a, I>(bytes: &mut I) -> Option<String>
where
    I: Iterator<Item = &'a u8>,
{
    let length = *bytes.next()?;
    let value: Vec<_> = bytes.by_ref().take(length as usize).copied().collect();
    Some(String::from_utf8_lossy(&value).into_owned())
}

fuzz_target!(|data: &[u8]| {
    let Ok(binary) = std::env::var("DOSR_BIN") else {
        return;
    };

    let mut arguments = Vec::new();
    let mut bytes = data.iter().skip(1);
    let chunk_count = data.first().copied().unwrap_or_default() as usize;

    for _ in 0..chunk_count {
        let Some(&byte) = bytes.next() else {
            break;
        };

        let option = match byte % 10 {
            0 => "-u",
            1 => "-g",
            2 => "-r",
            3 => "-t",
            4 => "-D",
            5 => "-p",
            6 => "-S",
            7 => "-E",
            8 => "-i",
            9 => "-h",
            _ => "-v",
        };
        arguments.push(option.to_owned());

        if matches!(option, "-S" | "-E" | "-i" | "-h" | "-v") {
            continue;
        }

        if let Some(value) = take_value(&mut bytes) {
            arguments.push(value);
        }
    }

    // The command to execute. Keep stdio closed so flags like -S/-p do not block forever.
    if let Some(&length) = bytes.next() {
        if length == 0 {
            // We use a real binary so we don't trip a "No such file or directory" error.
            arguments.push("/bin/true".to_owned());
            if let Some(&next_length) = bytes.next()
                && next_length > 0
            {
                let value: Vec<_> = bytes.by_ref().take(next_length as usize).copied().collect();
                arguments.push(String::from_utf8_lossy(&value).into_owned());
            }
        }

        let value: Vec<_> = bytes.by_ref().take(length as usize).copied().collect();
        arguments.push(String::from_utf8_lossy(&value).into_owned());
    }

    let mut command = Command::new(&binary);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .args(&arguments);

    let Ok(status) = command.status() else {
        return;
    };

    if status.code() == Some(101) {
        panic!("dosr panicked");
    }

    if ExitStatusExt::signal(&status).is_some() {
        panic!("dosr terminated by a signal");
    }
});
