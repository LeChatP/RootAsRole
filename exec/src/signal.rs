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
            // SAFETY: pipe2 succeeded, fds[0] is a valid file descriptor owned by nobody else
            reader: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            // SAFETY: pipe2 succeeded, fds[1] is a valid file descriptor owned by nobody else
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
#[derive(Clone, Copy, Debug)]
pub struct SignalInfo {
    pub signal: SignalNumber,
    pub pid: libc::pid_t,
    pub uid: libc::uid_t,
    pub status: libc::c_int,
}

impl SignalInfo {
    pub const SIZE: usize = std::mem::size_of::<Self>();
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
        let mut info = SignalInfo {
            signal: 0,
            pid: 0,
            uid: 0,
            status: 0,
        };
        loop {
            // SAFETY: valid pointer and size to read one signal number.
            let n = unsafe {
                libc::read(
                    self.rx.as_raw_fd(),
                    (&raw mut info).cast(),
                    SignalInfo::SIZE,
                )
            };

            if n == SignalInfo::SIZE.cast_signed() {
                return Ok(info);
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
extern "C" fn handler(signal: SignalNumber, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    // Use Acquire ordering to ensure we see the most recent value written by init()
    let fd = WRITE_FD.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }

    let (pid, uid, status) = if info.is_null() {
        (0, 0, 0)
    } else {
        // SAFETY: info is provided by the kernel for SA_SIGINFO handlers.
        let info = unsafe { &*info };
        // SAFETY: accessors rely on the kernel-populated siginfo_t.
        unsafe { (info.si_pid(), info.si_uid(), info.si_status()) }
    };

    let value = SignalInfo {
        signal,
        pid,
        uid,
        status,
    };
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
    // SAFETY: sigaction is a plain C struct, for which all zeroes is a valid value
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler as *const () as usize;
    // Use SA_RESTART to avoid interrupting system calls and SA_SIGINFO for metadata.
    sa.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;

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

/// Send `signal` to `pid`, a child of this process that is not reaped yet, or to its process
/// group (whose id is `pid`) with `process_group`.
///
/// The runner may run with the uids of its caller and file capabilities, as dosr does: a command
/// that runs as root or as another user does not take its signals (`EPERM`), where the monitor of
/// sudo runs as root. `CAP_KILL` is then raised for this call only, when it is permitted, and
/// dropped after. Only for a child that is not reaped: until then its pid, and the id of its
/// group, cannot be another process's.
///
/// # Errors
/// The error of `kill(2)`, or `EINVAL` for a pid that is not positive (`kill(0)` would signal
/// the group of the runner, `kill(-1)` every process it may signal).
pub fn signal_child(pid: libc::pid_t, signal: libc::c_int, process_group: bool) -> io::Result<()> {
    if pid <= 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let send = || {
        // SAFETY: kill and killpg do not access memory, they only send a signal
        let sent = unsafe {
            if process_group {
                libc::killpg(pid, signal)
            } else {
                libc::kill(pid, signal)
            }
        };
        if sent == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    match send() {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => with_cap_kill(send).unwrap_or(Err(e)),
        sent => sent,
    }
}

/// Run `send` with `CAP_KILL` in the effective set, `None` when it is not permitted. The effective
/// set is given back after it, or the process aborts: it never goes on with `CAP_KILL`.
fn with_cap_kill(send: impl FnOnce() -> io::Result<()>) -> Option<io::Result<()>> {
    use capctl::{Cap, CapState};
    let mut state = CapState::get_current().ok()?;
    if !state.permitted.has(Cap::KILL) {
        return None;
    }
    let effective = state.effective;
    state.effective.add(Cap::KILL);
    state.set_current().ok()?;
    let sent = send();
    state.effective = effective;
    if let Err(e) = state.set_current() {
        log::error!("cannot drop CAP_KILL after a signal to the command: {e}");
        std::process::abort();
    }
    Some(sent)
}

/// How long a command is given to end after `SIGHUP` and `SIGTERM`, before `SIGKILL`, like sudo.
pub const TERMINATION_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// Stop a command with increasing urgency, like sudo's `terminate_command`.
///
/// `SIGHUP`, `SIGTERM`, then `SIGKILL` once [`TERMINATION_DELAY`] has passed, so that the command
/// can clean up first. With `process_group`, the signals go to the process group `pid` instead of
/// the process.
pub fn terminate_process(pid: libc::pid_t, process_group: bool) {
    // kill(0) and killpg(0) would signal dosr's own group, kill(-1) every process it may signal
    if pid <= 0 {
        return;
    }
    terminate(|signal| {
        // SAFETY: kill and killpg do not access memory, they only send a signal
        unsafe {
            if process_group {
                libc::killpg(pid, signal);
            } else {
                libc::kill(pid, signal);
            }
        }
    });
}

/// [`terminate_process`] for a child that is not reaped yet, with the signals of
/// [`signal_child`]: a command that runs as another user is ended too.
pub fn terminate_child(pid: libc::pid_t, process_group: bool) {
    if pid <= 0 {
        return;
    }
    terminate(|signal| {
        if let Err(e) = signal_child(pid, signal, process_group) {
            log::debug!("cannot send signal {signal} to the command {pid}: {e}");
        }
    });
}

/// `SIGHUP`, `SIGTERM`, then `SIGKILL` once [`TERMINATION_DELAY`] has passed.
fn terminate(send: impl Fn(libc::c_int)) {
    send(libc::SIGHUP);
    send(libc::SIGTERM);
    std::thread::sleep(TERMINATION_DELAY);
    send(libc::SIGKILL);
}

#[allow(clippy::undocumented_unsafe_blocks)]
#[cfg(test)]
mod tests {
    use crate::{
        MUTEX,
        signal::{self, SignalStream},
    };
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;
    use std::time::{Duration, Instant};

    /// A shell in its own process group, given time to set its traps up.
    fn spawn_shell(script: &str) -> (std::process::Child, libc::pid_t) {
        let child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .process_group(0)
            .spawn()
            .expect("spawn the shell");
        std::thread::sleep(Duration::from_millis(300));
        let pid = libc::pid_t::try_from(child.id()).expect("pid in range");
        (child, pid)
    }

    // A command that handles SIGHUP or SIGTERM cleans up and ends before SIGKILL.
    #[test]
    fn terminate_process_lets_the_command_clean_up() {
        let _guard = MUTEX.lock().unwrap();
        let marker =
            std::env::temp_dir().join(format!("rar-terminate-cleanup-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let (mut child, pid) = spawn_shell(&format!(
            "trap 'echo done > {}; exit 3' HUP TERM; while :; do sleep 0.1; done",
            marker.display()
        ));

        signal::terminate_process(pid, true);
        let status = child.wait().expect("wait for the shell");
        let cleaned = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert_eq!(
            status.code(),
            Some(3),
            "the shell ended on its own: {status:?}"
        );
        assert!(cleaned, "the shell cleaned up");
    }

    // a process of another user (init) takes no signal from the runner without CAP_KILL; with it
    // permitted, the signal goes, and the effective set is given back after (signal 0 only checks)
    #[test]
    fn signal_child_raises_cap_kill_for_the_call_only() {
        use capctl::{Cap, CapState};
        // the effective set empty, as dosr runs: with CAP_KILL only permitted (a VM, as a user
        // with the ambient capability kill), the call has to raise it
        let mut state = CapState::get_current().unwrap();
        state.effective.clear();
        state.set_current().unwrap();
        let before = CapState::get_current().unwrap();
        let sent = signal::signal_child(1, 0, false);
        if before.permitted.has(Cap::KILL) {
            sent.unwrap();
        } else {
            assert_eq!(sent.unwrap_err().raw_os_error(), Some(libc::EPERM));
        }
        assert_eq!(CapState::get_current().unwrap(), before);
        assert_eq!(
            signal::signal_child(0, libc::SIGTERM, false)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            signal::signal_child(-1, libc::SIGTERM, true)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    // A command that ignores SIGHUP and SIGTERM is killed once the delay has passed.
    #[test]
    fn terminate_process_kills_a_command_that_ignores_the_signals() {
        let _guard = MUTEX.lock().unwrap();
        let (mut child, pid) = spawn_shell("trap '' HUP TERM; while :; do sleep 0.1; done");

        let start = Instant::now();
        signal::terminate_process(pid, true);
        let status = child.wait().expect("wait for the shell");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(start.elapsed() >= signal::TERMINATION_DELAY);
    }

    #[test]
    fn test_signals_combined() {
        let _guard = MUTEX.lock().unwrap();
        let stream = SignalStream::init().expect("Failed to init SignalStream");

        signal::register_signal_handler(libc::SIGUSR1).expect("Failed to register SIGUSR1");
        unsafe {
            libc::raise(libc::SIGUSR1);
        }

        let mut found = false;
        for _ in 0..50 {
            match stream.recv() {
                Ok(info) => {
                    // Verify we received the correct data
                    if info.signal == libc::SIGUSR1 {
                        found = true;
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
        unsafe {
            libc::raise(libc::SIGUSR2);
        }

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
