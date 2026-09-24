#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

#[path = "../../src/dosr/pam/cutils.rs"]
mod cutils;
#[path = "../../src/dosr/pam/rpassword.rs"]
mod rpassword;
#[path = "../../src/dosr/pam/securemem.rs"]
mod securemem;

fuzz_target!(|data: &[u8]| {
    let max_password_len = libpam_sys::PAM_MAX_RESP_SIZE as usize - 1;
    let password_len = data
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(data.len());
    let mut input = Cursor::new(data);
    match rpassword::fuzzing_exports::fuzz_read_unbuffered(&mut input) {
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
