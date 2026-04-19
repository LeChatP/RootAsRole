use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    sync::{
        OnceLock,
        atomic::{AtomicI32, Ordering},
    },
};

static STREAM: OnceLock<SignalStream> = OnceLock::new();
static WRITE_FD: AtomicI32 = AtomicI32::new(-1);

pub type SignalNumber = libc::c_int;

/// RAII wrapper for creating pipes with specified flags.
///
/// This struct ensures that file descriptors are properly managed and cleaned up via RAII.
pub struct PipeFactory {
    reader: OwnedFd,
    writer: OwnedFd,
}

impl PipeFactory {
    /// Creates a new pipe with the specified flags.
    ///
    /// # Errors
    /// Returns an IO error if pipe creation fails.
    ///
    /// # Example
    /// ```ignore
    /// let pipe = PipeFactory::new(libc::O_CLOEXEC | libc::O_NONBLOCK)?;
    /// let (reader, writer) = pipe.split();
    /// ```
    pub fn new(flags: i32) -> io::Result<Self> {
        let mut fds = [-1; 2];
        // SAFETY: valid pointer to 2 fds, libc::pipe2 is safe to call here
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), flags) };

        if ret == -1 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            // SAFETY: pipe2 succeeded, fds[0] and fds[1] are valid file descriptors
            reader: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            writer: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        })
    }

    /// Consumes the pipe and returns the reader and writer file descriptors.
    #[must_use]
    pub fn split(self) -> (OwnedFd, OwnedFd) {
        (self.reader, self.writer)
    }

    /// Returns a reference to the reader file descriptor.
    #[must_use]
    pub const fn reader(&self) -> &OwnedFd {
        &self.reader
    }

    /// Returns a reference to the writer file descriptor.
    #[must_use]
    pub const fn writer(&self) -> &OwnedFd {
        &self.writer
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalInfo {
    pub signal: SignalNumber,
    pub pid: libc::pid_t,
    pub uid: libc::uid_t,
    pub status: libc::c_int,
}

impl SignalInfo {
    pub const SIZE: usize = std::mem::size_of::<SignalNumber>();

    #[must_use]
    pub const fn new(signal: SignalNumber) -> Self {
        Self {
            signal,
            pid: 0,
            uid: 0,
            status: 0,
        }
    }
}

pub struct SignalStream {
    rx: OwnedFd,
    tx: OwnedFd,
}

impl Drop for SignalStream {
    fn drop(&mut self) {
        // Mark write_fd as invalid before dropping to prevent use-after-free in signal handlers
        WRITE_FD.store(-1, Ordering::Release);
    }
}

impl SignalStream {
    /// # Errors
    /// Returns an error if the signal stream cannot be initialized, which can happen due to failure
    /// in creating the pipe or if the write file descriptor cannot be set.
    /// # Panics
    /// Panics if :
    /// - ``WRITE_FD`` order is ``Release`` or ``AcqRel``. (a dev error, not a runtime error)
    /// - the `STREAM` is already initialized but the `WRITE_FD` is not set.
    pub fn init() -> io::Result<&'static Self> {
        if let Some(s) = STREAM.get() {
            if WRITE_FD.load(Ordering::Acquire) < 0 {
                WRITE_FD.store(s.tx.as_raw_fd(), Ordering::Release);
            }
            return Ok(s);
        }

        // Use RAII PipeFactory to safely create pipe
        let pipe = PipeFactory::new(libc::O_CLOEXEC | libc::O_NONBLOCK)?;
        let (rx, tx) = pipe.split();

        let stream = Self { rx, tx };
        let _ = STREAM.set(stream);

        let s = STREAM
            .get()
            .expect("signal stream must be initialized after set");
        WRITE_FD.store(s.tx.as_raw_fd(), Ordering::Release);
        Ok(s)
    }

    /// # Errors
    /// Returns an error if reading from the signal stream fails
    pub fn recv(&self) -> io::Result<SignalInfo> {
        let mut signal: SignalNumber = 0;
        loop {
            // SAFETY: valid pointer and size to read one signal number.
            let n = unsafe {
                libc::read(
                    self.rx.as_raw_fd(),
                    (&raw mut signal).cast(),
                    SignalInfo::SIZE,
                )
            };

            if n == SignalInfo::SIZE.cast_signed() {
                return Ok(SignalInfo::new(signal));
            } else if n == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            } else if n == -1 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }

            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short signal frame",
            ));
        }
    }
}

impl AsFd for SignalStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.rx.as_fd()
    }
}

// C handler
// IMPORTANT: This handler writes signal numbers to a pipe. If the pipe buffer fills up (typically 64KB),
// subsequent writes will fail silently. This could lead to signal loss if:
// - Multiple signals arrive faster than they can be consumed by event loop
// - Event loop is blocked processing other events
// - The receiver (SignalStream::recv) isn't called frequently enough
extern "C" fn handler(signal: SignalNumber) {
    // Use Acquire ordering to ensure we see the most recent value written by init()
    let fd = WRITE_FD.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }

    let value = signal;
    // SAFETY: `write(2)` is async-signal-safe and the pointer is valid for `SignalInfo::SIZE` bytes.
    // Note to myself in the future: Errors (including EAGAIN if buffer full) are silently ignored.
    // This is acceptable since the kernel queues pending signals and re-notifies when the queue is consumed.
    unsafe {
        let _ = libc::write(fd, (&raw const value).cast(), SignalInfo::SIZE);
    }
}

/// # Errors
/// Returns an error if :
/// - invalid signal number is provided
/// - system call to set signal handler fails
pub fn register_signal_handler(signal: SignalNumber) -> io::Result<()> {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler as *const () as usize;
    // Use SA_RESTART to avoid interrupting system calls
    sa.sa_flags = libc::SA_RESTART;

    // Block all signals during signal handler execution to prevent re-entrancy issues
    // SAFETY: valid sigset pointer.
    unsafe {
        libc::sigfillset(&raw mut sa.sa_mask);
    }

    // SAFETY: valid sigaction call with initialized struct
    unsafe {
        if libc::sigaction(signal, &raw const sa, std::ptr::null_mut()) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::signal::{self, SignalStream};
    use serial_test::serial;

    #[serial]
    #[test]
    fn test_signals_combined() {
        let stream = SignalStream::init().expect("Failed to init SignalStream");

        signal::register_signal_handler(libc::SIGUSR1).expect("Failed to register SIGUSR1");
        super::handler(libc::SIGUSR1);

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
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("Error receiving SIGUSR1: {e}"),
            }
        }
        assert!(found, "Failed to receive SIGUSR1");

        // Verification that we can handle multiple different signals
        signal::register_signal_handler(libc::SIGUSR2).expect("Failed to register SIGTRAP");
        super::handler(libc::SIGUSR2);

        found = false;
        for _ in 0..50 {
            match stream.recv() {
                Ok(info) => {
                    if info.signal == libc::SIGUSR2 {
                        found = true;
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("Error receiving SIGUSR2: {e}"),
            }
        }
        assert!(found, "Failed to receive SIGUSR2");
    }
}
