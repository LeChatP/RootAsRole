use rootasrole_exec::pty::Pty;
use rootasrole_exec::terminal;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};

#[test]
fn test_pty_open_basic() {
    let pty = Pty::open().expect("Failed to open PTY");

    println!("Pty path: {:?}", pty.path);
    assert!(!pty.path.as_bytes().is_empty());

    assert!(terminal::safe_isatty(&pty.leader));
    assert!(terminal::safe_isatty(&pty.follower));
}

#[test]
fn test_pty_follower_clone() {
    let pty = Pty::open().expect("Failed to open PTY");
    let follower_clone = pty.follower.try_clone().expect("Failed to clone follower");
    assert!(terminal::safe_isatty(&follower_clone));
}

#[test]
fn test_pty_resize() {
    let pty = Pty::open().expect("Failed to open PTY");

    pty.leader.resize(42, 123).expect("Failed to resize");

    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        let ret = libc::ioctl(pty.follower.as_fd().as_raw_fd(), libc::TIOCGWINSZ, &mut ws);
        assert_eq!(ret, 0);
        assert_eq!(ws.ws_row, 42);
        assert_eq!(ws.ws_col, 123);
    }
}

#[test]
fn test_pty_communication() {
    let mut pty = Pty::open().expect("Failed to open PTY");

    // We want to write to the follower (simulating a program outputting text)
    // and read from the leader (simulating the terminal displaying it).

    // Since PtyFollower doesn't impl Write, we duplicate fd to a File.
    let mut follower_write =
        unsafe { File::from_raw_fd(libc::dup(pty.follower.as_fd().as_raw_fd())) };

    let message = "Hello PTY World";
    follower_write
        .write_all(message.as_bytes())
        .expect("Failed to write to follower");
    // Ensure it's flushed
    follower_write.flush().unwrap();

    // Read from leader
    let mut buf = [0u8; 1024];
    let n = pty
        .leader
        .read(&mut buf)
        .expect("Failed to read from leader");

    let output = String::from_utf8_lossy(&buf[..n]);
    // Note: TTY default processing might change newlines etc, but plain text should pass through.
    assert!(output.contains("Hello PTY World"));
}

#[test]
fn test_pty_nonblocking() {
    let mut pty = Pty::open().expect("Failed to open PTY");
    pty.leader
        .set_nonblocking()
        .expect("Failed to set nonblocking");

    // Reading should now return WouldBlock error instantly because pty is empty
    let mut buf = [0u8; 10];
    let res = pty.leader.read(&mut buf);
    match res {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (), // Success
        Ok(_) => panic!("Should not have read anything from empty PTY"),
        Err(e) => panic!("Unexpected error: {e}"),
    }
}
