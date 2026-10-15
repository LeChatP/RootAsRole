#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use rootasrole::fuzzing::parse_stat_field;

/// Fields read by dosr in `/proc/<pid>/stat` (0-based).
const SESSION: usize = 5;
const TTY_NR: usize = 6;
const START_TIME: usize = 21;

fuzz_target!(|data: &[u8]| {
    // arbitrary content must never panic
    for field in [SESSION, TTY_NR, START_TIME] {
        let _ = parse_stat_field::<u64>(data, field);
        let _ = parse_stat_field::<i32>(data, field);
    }

    // the process name is chosen by the user (prctl, exec): at most 15 bytes, without NUL
    let Some((&len, rest)) = data.split_first() else {
        return;
    };
    let comm_len = usize::from(len % 16).min(rest.len());
    let (comm, numbers) = rest.split_at(comm_len);
    if comm.contains(&0) {
        return;
    }
    let mut numbers = numbers.chunks(4).map(|chunk| {
        let mut bytes = [0u8; 4];
        bytes[..chunk.len()].copy_from_slice(chunk);
        u32::from_le_bytes(bytes)
    });
    let session = numbers.next().unwrap_or_default() as i32;
    let tty_nr = numbers.next().unwrap_or_default() as i32;
    let start_time = u64::from(numbers.next().unwrap_or_default());

    let mut stat = Vec::new();
    write!(stat, "4242 (").unwrap();
    stat.extend_from_slice(comm);
    write!(
        stat,
        ") S 1 4242 {session} {tty_nr} 4242 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start_time} 0 0\n"
    )
    .unwrap();

    assert_eq!(parse_stat_field::<i32>(&stat, SESSION).unwrap(), session);
    assert_eq!(parse_stat_field::<i32>(&stat, TTY_NR).unwrap(), tty_nr);
    assert_eq!(
        parse_stat_field::<u64>(&stat, START_TIME).unwrap(),
        start_time
    );
});
