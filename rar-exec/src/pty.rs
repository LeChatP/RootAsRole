use std::{
    ffi::{CString, c_uchar},
    fs::File,
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};

use libc::{TIOCSWINSZ, ioctl};

use super::terminal::TermSize;

// duplicated helper
#[inline]
fn cerr(res: libc::c_int) -> io::Result<libc::c_int> {
    if res == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res)
    }
}

pub struct Pty {
    pub path: CString,
    pub leader: PtyLeader,
    pub follower: PtyFollower,
}

impl Pty {
    /// # Errors
    /// Returns an error if system call fails or if the path of the pty cannot be converted to a valid `CString`.
    pub fn open() -> io::Result<Self> {
        const PATH_MAX: usize = libc::PATH_MAX as _;
        let mut path = vec![0 as c_uchar; PATH_MAX];
        let (mut leader, mut follower) = (0, 0);

        // SAFETY: C-style
        cerr(unsafe {
            libc::openpty(
                &raw mut leader,
                &raw mut follower,
                path.as_mut_ptr().cast(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        })?;

        if let Some(index) = path.iter().position(|&byte| byte == 0) {
            path.truncate(index);
        }

        let path = CString::new(path)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(Self {
            path,
            leader: PtyLeader {
                // SAFETY: from openpty
                file: unsafe { OwnedFd::from_raw_fd(leader) }.into(),
            },
            follower: PtyFollower {
                // SAFETY: from openpty
                file: unsafe { OwnedFd::from_raw_fd(follower) }.into(),
            },
        })
    }
}

pub struct PtyLeader {
    file: File,
}

impl PtyLeader {
    /// # Errors
    /// Returns an error if system call fails
    pub fn set_size(&self, term_size: &TermSize) -> io::Result<i32> {
        cerr(unsafe {
            ioctl(
                self.file.as_raw_fd(),
                TIOCSWINSZ,
                std::ptr::from_ref::<TermSize>(term_size).cast::<libc::winsize>(),
            )
        })
    }

    /// # Errors
    /// Returns an error if system call fails
    pub fn set_nonblocking(&self) -> io::Result<()> {
        let fd = self.file.as_fd();
        // SAFETY: fcntl
        unsafe {
            let flags = cerr(libc::fcntl(fd.as_raw_fd(), libc::F_GETFL))?;
            cerr(libc::fcntl(
                fd.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            ))?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if system call fails
    pub fn resize(&self, rows: u16, cols: u16) -> io::Result<i32> {
        let sz = TermSize::new(rows, cols);
        self.set_size(&sz)
    }
}

impl io::Read for PtyLeader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl io::Write for PtyLeader {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl AsFd for PtyLeader {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
}

pub struct PtyFollower {
    file: File,
}

impl PtyFollower {
    /// # Errors
    /// Returns an error if cloning the file fails
    pub fn try_clone(&self) -> io::Result<Self> {
        self.file.try_clone().map(|file| Self { file })
    }
}

impl AsFd for PtyFollower {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl From<PtyFollower> for std::process::Stdio {
    fn from(follower: PtyFollower) -> Self {
        follower.file.into()
    }
}

#[cfg(test)]
mod tests {
    use crate::pty::Pty;
    use crate::terminal;
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
}
