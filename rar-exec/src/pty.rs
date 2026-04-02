use std::{
    ffi::{CString, c_uchar},
    fs::File,
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};

use libc::{TIOCSWINSZ, ioctl};

use super::terminal::{self, TermSize};

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

impl terminal::sealed::SafeTty for PtyLeader {}

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

impl terminal::sealed::SafeTty for PtyFollower {}

impl From<PtyFollower> for std::process::Stdio {
    fn from(follower: PtyFollower) -> Self {
        follower.file.into()
    }
}
