#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use rootasrole::fuzzing::read_password;

fuzz_target!(|data: &[u8]| {
    // the last byte of the buffer is kept for the terminating NUL
    let max_password_len = libpam_sys::PAM_MAX_RESP_SIZE as usize - 1;
    let password_len = data
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(data.len());
    match read_password(&mut Cursor::new(data)) {
        Ok(password) => {
            assert!(password_len <= max_password_len);
            assert_eq!(&password[..password_len], &data[..password_len]);
            assert!(password[password_len..].iter().all(|byte| *byte == 0));
        }
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
            assert!(password_len > max_password_len);
        }
    }
});
