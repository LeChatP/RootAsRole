use rootasrole_exec::signal::{self, SignalStream};
use std::thread;
use std::time::Duration;

#[test]
fn test_signals_combined() {
    let stream = SignalStream::init().expect("Failed to init SignalStream");

    signal::register_signal_handler(libc::SIGUSR1).expect("Failed to register SIGUSR1");

    unsafe {
        libc::kill(libc::getpid(), libc::SIGUSR1);
    }

    let mut found = false;
    for _ in 0..50 {
        match stream.recv() {
            Ok(info) => {
                // Verify we received the correct data
                if info.signal == libc::SIGUSR1 {
                    found = true;
                    assert_eq!(info.pid, 0);
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("Error receiving SIGUSR1: {e}"),
        }
    }
    assert!(found, "Failed to receive SIGUSR1");

    // Verification that we can handle multiple different signals
    signal::register_signal_handler(libc::SIGTRAP).expect("Failed to register SIGTRAP");

    unsafe {
        libc::kill(libc::getpid(), libc::SIGTRAP);
    }

    found = false;
    for _ in 0..50 {
        match stream.recv() {
            Ok(info) => {
                if info.signal == libc::SIGTRAP {
                    found = true;
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("Error receiving SIGTRAP: {e}"),
        }
    }
    assert!(found, "Failed to receive SIGTRAP");
}
