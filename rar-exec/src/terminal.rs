#![allow(dead_code)]

use std::{
    ffi::{OsString, c_char, c_int, c_void},
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    sync::atomic::{AtomicBool, Ordering},
};

use libc::{
    CS7, CS8, ECHO, ECHOCTL, ECHOE, ECHOK, ECHOKE, ECHONL, ICANON, ICRNL, IEXTEN, IGNCR, IGNPAR,
    IMAXBEL, INLCR, INPCK, ISIG, ISTRIP, IXANY, IXOFF, IXON, NOFLSH, OCRNL, ONLCR, ONLRET, ONOCR,
    OPOST, PARENB, PARMRK, PARODD, PENDIN, SIGTTOU, TCSADRAIN, TCSAFLUSH, TIOCGWINSZ, TIOCSWINSZ,
    TOSTOP, cfgetispeed, cfgetospeed, cfmakeraw, cfsetispeed, cfsetospeed, ioctl, sigaction,
    sigemptyset, sighandler_t, siginfo_t, tcflag_t, tcgetattr, tcsetattr, termios, winsize,
};

#[cfg(target_os = "linux")]
use libc::{IUTF8, OLCUC};

#[cfg(not(target_os = "linux"))]
const IUTF8: libc::tcflag_t = 0;
#[cfg(not(target_os = "linux"))]
const OLCUC: libc::tcflag_t = 0;

// helpers
#[inline]
pub(crate) fn cerr(res: libc::c_int) -> io::Result<libc::c_int> {
    if res == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res)
    }
}

pub fn safe_isatty<F: AsFd>(fd: F) -> bool {
    // SAFETY: libc call
    unsafe { libc::isatty(fd.as_fd().as_raw_fd()) == 1 }
}

pub(crate) fn os_string_from_ptr(ptr: *const c_char) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    // SAFETY: valid C string
    let bytes = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_bytes();
    OsString::from_vec(bytes.to_vec())
}

pub(crate) fn is_fifo_or_sock<F: AsFd>(fd: F) -> bool {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid fd
    if unsafe { libc::fstat(fd.as_fd().as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: checked
    let stat = unsafe { stat.assume_init() };
    (stat.st_mode & libc::S_IFMT) == libc::S_IFIFO
        || (stat.st_mode & libc::S_IFMT) == libc::S_IFSOCK
}

// pid
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(libc::pid_t);

impl ProcessId {
    #[must_use]
    pub const fn new(pid: libc::pid_t) -> Self {
        Self(pid)
    }

    #[must_use]
    pub const fn inner(&self) -> libc::pid_t {
        self.0
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// size
#[repr(transparent)]
pub struct TermSize {
    pub(crate) raw: winsize,
}

impl TermSize {
    #[must_use]
    pub const fn new(rows: u16, cols: u16) -> Self {
        Self {
            raw: winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        }
    }
}

impl PartialEq for TermSize {
    fn eq(&self, other: &Self) -> bool {
        self.raw.ws_col == other.raw.ws_col && self.raw.ws_row == other.raw.ws_row
    }
}

impl From<winsize> for TermSize {
    fn from(raw: winsize) -> Self {
        Self { raw }
    }
}

impl fmt::Display for TermSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} x {}", self.raw.ws_row, self.raw.ws_col)
    }
}

// trait
pub mod sealed {
    use std::os::fd::AsFd;

    pub trait Sealed {}

    impl<F: AsFd> Sealed for F {}
}

pub struct TtyFd<'a, F: AsFd + ?Sized> {
    fd: &'a F,
}

impl<F: AsFd + ?Sized> TtyFd<'_, F> {
    /// # Errors
    /// Returns an error if system call fails.
    pub fn tcgetpgrp(&self) -> io::Result<ProcessId> {
        // SAFETY: valid tty
        let id = cerr(unsafe { libc::tcgetpgrp(self.fd.as_fd().as_raw_fd()) })?;
        Ok(ProcessId::new(id))
    }

    /// # Errors
    /// Returns an error if system call fails.
    pub fn tcsetpgrp(&self, pgrp: ProcessId) -> io::Result<()> {
        // SAFETY: valid tty
        cerr(unsafe { libc::tcsetpgrp(self.fd.as_fd().as_raw_fd(), pgrp.inner()) }).map(|_| ())
    }

    /// # Errors
    /// Returns an error if system call fails.
    pub fn make_controlling_terminal(&self) -> io::Result<()> {
        // SAFETY: valid tty
        cerr(unsafe { libc::ioctl(self.fd.as_fd().as_raw_fd(), libc::TIOCSCTTY, 0) })?;
        Ok(())
    }

    /// # Errors
    /// Returns an error if system call fails.
    pub fn tcgetsid(&self) -> io::Result<ProcessId> {
        // SAFETY: valid tty
        let id = cerr(unsafe { libc::tcgetsid(self.fd.as_fd().as_raw_fd()) })?;
        Ok(ProcessId::new(id))
    }
}

pub trait TerminalExt: sealed::Sealed + AsFd {
    /// # Errors
    /// Returns [`io::ErrorKind::Unsupported`] when the file descriptor is not a TTY.
    fn as_tty(&self) -> io::Result<TtyFd<'_, Self>>
    where
        Self: Sized,
    {
        if safe_isatty(self.as_fd()) {
            Ok(TtyFd { fd: self })
        } else {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    #[must_use]
    fn is_terminal_for_pgrp(&self, pgrp: ProcessId) -> bool;
    /// # Errors
    /// Returns an error if system call fails.
    fn ttyname(&self) -> io::Result<OsString>;
    #[must_use]
    fn is_pipe_or_socket(&self) -> bool;
}

impl<F: AsFd> TerminalExt for F {
    fn is_terminal_for_pgrp(&self, pgrp: ProcessId) -> bool {
        let Ok(tty) = self.as_tty() else {
            return false;
        };
        let Ok(id) = tty.tcgetpgrp() else {
            return false;
        };
        id == pgrp
    }

    fn ttyname(&self) -> io::Result<OsString> {
        let mut buf: [c_char; 1024] = [0; 1024];

        self.as_tty()?;

        // SAFETY: buffer size OK
        cerr(unsafe { libc::ttyname_r(self.as_fd().as_raw_fd(), buf.as_mut_ptr(), buf.len()) })?;
        Ok(os_string_from_ptr(buf.as_ptr()))
    }

    fn is_pipe_or_socket(&self) -> bool {
        is_fifo_or_sock(self.as_fd())
    }
}

// logic

const INPUT_FLAGS: tcflag_t = IGNPAR
    | PARMRK
    | INPCK
    | ISTRIP
    | INLCR
    | IGNCR
    | ICRNL
    | IXON
    | IXANY
    | IXOFF
    | IMAXBEL
    | IUTF8;
const OUTPUT_FLAGS: tcflag_t = OPOST | OLCUC | ONLCR | OCRNL | ONOCR | ONLRET;
const CONTROL_FLAGS: tcflag_t = CS7 | CS8 | PARENB | PARODD;
const LOCAL_FLAGS: tcflag_t = ISIG
    | ICANON
    | ECHO
    | ECHOE
    | ECHOK
    | ECHONL
    | NOFLSH
    | TOSTOP
    | IEXTEN
    | ECHOCTL
    | ECHOKE
    | PENDIN;

static GOT_SIGTTOU: AtomicBool = AtomicBool::new(false);

unsafe fn tcsetattr_nobg(fd: c_int, flags: c_int, tp: *const termios) -> io::Result<()> {
    // SAFETY: valid args
    let setattr = || cerr(unsafe { tcsetattr(fd, flags, tp) }).map(|_| ());
    catching_sigttou(setattr)
}

fn catching_sigttou(mut function: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    extern "C" fn on_sigttou(_signal: c_int, _info: *mut siginfo_t, _: *mut c_void) {
        GOT_SIGTTOU.store(true, Ordering::SeqCst);
    }

    let action = {
        let mut raw = MaybeUninit::<libc::sigaction>::uninit();
        unsafe {
            let p = raw.as_mut_ptr();
            // SAFETY: zeroed
            std::ptr::write_bytes(p, 0, 1);

            (*p).sa_sigaction = on_sigttou as *const () as sighandler_t;

            // SAFETY: init mask
            sigemptyset(&raw mut (*p).sa_mask);

            (*p).sa_flags = 0;

            // SAFETY: initialized
            raw.assume_init()
        }
    };

    GOT_SIGTTOU.store(false, Ordering::SeqCst);

    let original_action = unsafe {
        let mut original_action = MaybeUninit::<sigaction>::uninit();
        // SAFETY: sigaction
        sigaction(SIGTTOU, &raw const action, original_action.as_mut_ptr());
        original_action.assume_init()
    };

    let result = loop {
        match function() {
            Ok(()) => break Ok(()),
            Err(err) => {
                let got_sigttou = GOT_SIGTTOU.load(Ordering::SeqCst);
                if got_sigttou || err.kind() != io::ErrorKind::Interrupted {
                    break Err(err);
                }
            }
        }
    };

    // SAFETY: restore handler
    unsafe { sigaction(SIGTTOU, &raw const original_action, std::ptr::null_mut()) };

    result
}

pub struct UserTerm {
    tty: File,
    original_termios: Option<termios>,
}

impl UserTerm {
    /// # Errors
    /// Returns an error if opening `/dev/tty` fails (read/write permissions)
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            tty: OpenOptions::new().read(true).write(true).open("/dev/tty")?,
            original_termios: None,
        })
    }

    /// # Errors
    /// Returns an error if system call fails.
    pub fn get_size(&self) -> io::Result<TermSize> {
        let mut term_size = MaybeUninit::<TermSize>::uninit();
        // SAFETY: ioctl
        cerr(unsafe {
            ioctl(
                self.tty.as_raw_fd(),
                TIOCGWINSZ,
                term_size.as_mut_ptr().cast::<winsize>(),
            )
        })?;
        // SAFETY: initialized
        Ok(unsafe { term_size.assume_init() })
    }

    /// # Errors
    /// Returns an error if system call fails.
    pub fn copy_to<D: AsFd>(&self, dst: &D) -> io::Result<()> {
        let src = self.tty.as_raw_fd();
        let dst = dst.as_fd().as_raw_fd();

        let (tt_src, mut tt_dst) = unsafe {
            let mut tt_src = MaybeUninit::<termios>::uninit();
            let mut tt_dst = MaybeUninit::<termios>::uninit();

            // SAFETY: tcgetattr
            cerr(tcgetattr(src, tt_src.as_mut_ptr()))?;
            cerr(tcgetattr(dst, tt_dst.as_mut_ptr()))?;

            (tt_src.assume_init(), tt_dst.assume_init())
        };

        tt_dst.c_iflag &= !INPUT_FLAGS;
        tt_dst.c_oflag &= !OUTPUT_FLAGS;
        tt_dst.c_cflag &= !CONTROL_FLAGS;
        tt_dst.c_lflag &= !LOCAL_FLAGS;

        tt_dst.c_iflag |= tt_src.c_iflag & INPUT_FLAGS;
        tt_dst.c_oflag |= tt_src.c_oflag & OUTPUT_FLAGS;
        tt_dst.c_cflag |= tt_src.c_cflag & CONTROL_FLAGS;
        tt_dst.c_lflag |= tt_src.c_lflag & LOCAL_FLAGS;

        tt_dst.c_cc = tt_src.c_cc;

        unsafe {
            let mut speed = cfgetospeed(&raw const tt_src);
            if speed == libc::B0 {
                speed = libc::B38400;
            }
            cfsetospeed(&raw mut tt_dst, speed);
            speed = cfgetispeed(&raw const tt_src);
            cfsetispeed(&raw mut tt_dst, speed);
        }

        // SAFETY: tcsetattr
        unsafe { tcsetattr_nobg(dst, TCSAFLUSH, &raw const tt_dst) }?;

        let mut wsize = MaybeUninit::<winsize>::uninit();
        // SAFETY: ioctl
        cerr(unsafe { ioctl(src, TIOCGWINSZ, wsize.as_mut_ptr()) })?;
        cerr(unsafe { ioctl(dst, TIOCSWINSZ, wsize.as_ptr()) })?;

        Ok(())
    }

    /// # Errors
    /// Returns an error if system call fails.
    pub fn set_raw_mode(&mut self, with_signals: bool, preserve_oflag: bool) -> io::Result<()> {
        let fd = self.tty.as_raw_fd();
        let mut term = if let Some(termios) = self.original_termios {
            termios
        } else {
            *self.original_termios.insert(unsafe {
                let mut termios = MaybeUninit::uninit();
                cerr(tcgetattr(fd, termios.as_mut_ptr()))?;
                termios.assume_init()
            })
        };
        let original_oflag = term.c_oflag;
        unsafe { cfmakeraw(&raw mut term) };
        if preserve_oflag {
            term.c_oflag = original_oflag;
        } else {
            term.c_oflag = 0;
        }
        if with_signals {
            term.c_cflag |= ISIG;
        }

        unsafe { tcsetattr_nobg(fd, TCSADRAIN, &raw const term) }?;
        Ok(())
    }

    /// # Errors
    /// Returns an error if system call fails.
    pub fn restore(&mut self, flush: bool) -> io::Result<()> {
        if let Some(termios) = self.original_termios.take() {
            let fd = self.tty.as_raw_fd();
            let flags = if flush { TCSAFLUSH } else { TCSADRAIN };
            unsafe { tcsetattr_nobg(fd, flags, &raw const termios) }?;
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if system call fails or if the process is put in background and receives `SIGTTOU`.
    pub fn tcsetpgrp_nobg(&self, pgrp: ProcessId) -> io::Result<()> {
        catching_sigttou(|| self.as_tty().and_then(|tty| tty.tcsetpgrp(pgrp)))
    }
}

impl AsFd for UserTerm {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.tty.as_fd()
    }
}

impl Read for UserTerm {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tty.read(buf)
    }
}

impl Write for UserTerm {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tty.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tty.flush()
    }
}

impl Drop for UserTerm {
    fn drop(&mut self) {
        let _ = self.restore(false);
    }
}

#[cfg(test)]
mod tests {
    use crate::terminal::{self, ProcessId, TermSize, TerminalExt, UserTerm};
    use std::fs::File;

    #[test]
    fn test_terminal_trait_on_file() {
        // A regular file is not a terminal
        let file = File::open("Cargo.toml").expect("Failed to open file");

        // safe_isatty should be false
        assert!(!terminal::safe_isatty(&file));

        // is_terminal_for_pgrp should be false
        assert!(!file.is_terminal_for_pgrp(ProcessId::new(1)));

        // ttyname should fail
        assert!(file.ttyname().is_err());
    }

    #[test]
    fn test_safe_isatty_stdout() {
        let stdout = std::io::stdout();
        let _ = terminal::safe_isatty(stdout);
    }

    #[test]
    fn test_process_id() {
        let pid_val = 1234;
        let pid = ProcessId::new(pid_val);
        assert_eq!(pid.inner(), pid_val);
        assert_eq!(format!("{pid}"), "1234");
    }

    #[test]
    fn test_term_size() {
        let ts = TermSize::new(24, 80);
        assert_eq!(format!("{ts}"), "24 x 80");
    }

    #[test]
    fn test_user_term_open() {
        // This test might fail if there is no /dev/tty (e.g. in some CI environments or non-interactive shells)
        // We handle the result gracefully.
        match UserTerm::open() {
            Ok(mut term) => {
                assert!(terminal::safe_isatty(&term));

                // Try enabling raw mode
                let res = term.set_raw_mode(false, false);
                assert!(res.is_ok());

                // Restore
                let res = term.restore(false);
                assert!(res.is_ok());
            }
            Err(e) => {
                println!("Skipping UserTerm test as /dev/tty cannot be opened: {e}");
            }
        }
    }

    #[test]
    fn test_is_pipe_or_socket() {
        use std::os::unix::net::UnixStream;

        let file = File::open("Cargo.toml").expect("Failed to open file");
        assert!(!file.is_pipe_or_socket());

        let (s1, _s2) = UnixStream::pair().expect("Failed to create socket pair");
        assert!(s1.is_pipe_or_socket());
    }
}
