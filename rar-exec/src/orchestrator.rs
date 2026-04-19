//! orchestrator.rs
//!
//! Zero-alloc, strictly ordered pre-exec pipeline for `std::process::Command`

#![cfg(unix)]
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(transparent)]
pub struct Stage(u8);

impl Stage {
    pub const SESSION: Self = Self(0);
    pub const NAMESPACE: Self = Self(5);
    pub const PTY: Self = Self(20);
    pub const FILESYSTEM: Self = Self(30);
    pub const LIMITS: Self = Self(40);
    pub const UMASK: Self = Self(45);
    pub const PRIV_DROP: Self = Self(50);
    pub const CAPS: Self = Self(55);
    pub const FD_CLEANUP: Self = Self(65);
    pub const SIGNALS: Self = Self(68);
    pub const LOCKDOWN: Self = Self(70);

    /// Custom user-defined stage
    #[must_use]
    pub const fn custom(v: u8) -> Self {
        Self(v)
    }

    #[must_use]
    pub const fn order(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy)]
pub struct PreExecContext {
    pub tty_fd: Option<std::os::fd::RawFd>,
}

impl PreExecContext {
    #[must_use]
    pub const fn empty() -> Self {
        Self { tty_fd: None }
    }

    #[must_use]
    pub const fn with_tty(fd: std::os::fd::RawFd) -> Self {
        Self { tty_fd: Some(fd) }
    }
}

#[derive(Clone, Copy)]
pub struct PreExecStep {
    pub stage: Stage,
    pub run: unsafe fn(PreExecContext) -> io::Result<()>,
}

const fn assert_ordered(steps: &[PreExecStep]) {
    let mut i = 1;
    while i < steps.len() {
        assert!(
            steps[i - 1].stage.order() <= steps[i].stage.order(),
            "PreExecSteps must be ordered by stage"
        );
        i += 1;
    }
}

#[derive(Clone, Copy)]
pub struct Orchestrator {
    steps: &'static [PreExecStep],
}

impl Orchestrator {
    #[must_use]
    pub const fn new(steps: &'static [PreExecStep]) -> Self {
        assert_ordered(steps);
        Self { steps }
    }

    /// Must only be called inside `pre_exec`
    /// # Errors
    /// Returns an error if any of the `pre-exec` steps fails.
    /// # Safety
    /// The caller must check `pre_exec` safety.
    pub unsafe fn run(&self, ctx: &PreExecContext) -> io::Result<()> {
        let mut i = 0;
        while i < self.steps.len() {
            (unsafe { (self.steps[i].run)(*ctx) })?;
            i += 1;
        }
        Ok(())
    }
}

#[must_use]
pub fn with_pre_exec_orchestrator(
    mut cmd: Command,
    orch: &'static Orchestrator,
    ctx: Option<PreExecContext>,
) -> Command {
    let ctx = ctx.unwrap_or(PreExecContext::empty());
    unsafe {
        cmd.pre_exec(move || orch.run(&ctx));
    }
    cmd
}

pub mod steps {
    use super::{PreExecContext, PreExecStep, Stage, io};
    use crate::terminal::TerminalExt;
    use libc::setsid;
    use std::os::fd::BorrowedFd;

    /// # Errors
    /// Returns an error if the setsid system call fails.
    /// # Safety
    /// The caller must ensure that the process is not already a session leader
    pub unsafe fn create_session(_: PreExecContext) -> io::Result<()> {
        if unsafe { setsid() } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// # Errors
    /// Returns an error if the file descriptor is not a TTY, if the TTY fd is not provided, or if the controlling-terminal setup fails.
    /// # Safety
    /// The caller must ensure that the provided file descriptor is valid and refers to a terminal.
    pub unsafe fn set_controlling_terminal(ctx: PreExecContext) -> io::Result<()> {
        let fd = ctx.tty_fd.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "tty_fd must be provided for set_controlling_terminal",
            )
        })?;
        // SAFETY: the caller promises the raw fd is valid for the duration of this call.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        borrowed.as_tty()?.make_controlling_terminal()
    }

    pub const SESSION: PreExecStep = PreExecStep {
        stage: Stage::SESSION,
        run: create_session,
    };

    pub const SET_CTTY: PreExecStep = PreExecStep {
        stage: Stage::PTY,
        run: set_controlling_terminal,
    };
}

#[cfg(test)]
#[allow(clippy::unnecessary_wraps)]
mod tests {
    use super::*;
    use crate::pty::Pty;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use serial_test::serial;

    static STATE: AtomicUsize = AtomicUsize::new(0);

    unsafe fn step_first(ctx: PreExecContext) -> io::Result<()> {
        assert_eq!(ctx.tty_fd, Some(42));
        assert_eq!(STATE.load(Ordering::SeqCst), 0);
        STATE.store(1, Ordering::SeqCst);
        Ok(())
    }

    unsafe fn step_second(ctx: PreExecContext) -> io::Result<()> {
        assert_eq!(ctx.tty_fd, Some(42));
        assert_eq!(STATE.load(Ordering::SeqCst), 1);
        STATE.store(2, Ordering::SeqCst);
        Ok(())
    }

    unsafe fn step_ok(_: PreExecContext) -> io::Result<()> {
        STATE.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    unsafe fn step_err(_: PreExecContext) -> io::Result<()> {
        STATE.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("failing step"))
    }

    unsafe fn step_never(_: PreExecContext) -> io::Result<()> {
        STATE.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    unsafe fn ensure_ctx_none(ctx: PreExecContext) -> io::Result<()> {
        if ctx.tty_fd.is_some() {
            return Err(io::Error::other("tty fd should not be set"));
        }
        Ok(())
    }

    unsafe fn ensure_ctx_7(ctx: PreExecContext) -> io::Result<()> {
        if ctx.tty_fd != Some(7) {
            return Err(io::Error::other("tty fd should be set to 7"));
        }
        Ok(())
    }

    static ORDERED_STEPS: &[PreExecStep] = &[
        PreExecStep {
            stage: Stage::SESSION,
            run: step_first,
        },
        PreExecStep {
            stage: Stage::PRIV_DROP,
            run: step_second,
        },
    ];

    static FAILING_STEPS: &[PreExecStep] = &[
        PreExecStep {
            stage: Stage::SESSION,
            run: step_ok,
        },
        PreExecStep {
            stage: Stage::PRIV_DROP,
            run: step_err,
        },
        PreExecStep {
            stage: Stage::LOCKDOWN,
            run: step_never,
        },
    ];

    static UNSORTED_STEPS: &[PreExecStep] = &[
        PreExecStep {
            stage: Stage::PRIV_DROP,
            run: step_ok,
        },
        PreExecStep {
            stage: Stage::SESSION,
            run: step_ok,
        },
    ];

    static NONE_CTX_STEP: &[PreExecStep] = &[PreExecStep {
        stage: Stage::SESSION,
        run: ensure_ctx_none,
    }];

    static SOME_CTX_STEP: &[PreExecStep] = &[PreExecStep {
        stage: Stage::SESSION,
        run: ensure_ctx_7,
    }];

    #[test]
    fn stage_and_context_helpers() {
        assert_eq!(Stage::custom(9).order(), 9);
        assert_eq!(PreExecContext::empty().tty_fd, None);
        assert_eq!(PreExecContext::with_tty(99).tty_fd, Some(99));
    }

    #[test]
    #[serial]
    fn orchestrator_runs_steps_in_order() {
        STATE.store(0, Ordering::SeqCst);
        let orch = Orchestrator::new(ORDERED_STEPS);
        let ctx = PreExecContext::with_tty(42);
        unsafe {
            orch.run(&ctx).expect("ordered steps should succeed");
        }
        assert_eq!(STATE.load(Ordering::SeqCst), 2);
    }

    #[test]
    #[serial]
    fn orchestrator_stops_on_first_error() {
        STATE.store(0, Ordering::SeqCst);
        let orch = Orchestrator::new(FAILING_STEPS);
        let ctx = PreExecContext::empty();
        let res = unsafe { orch.run(&ctx) };
        assert!(res.is_err());
        assert_eq!(STATE.load(Ordering::SeqCst), 2);
    }

    #[test]
    #[should_panic(expected = "PreExecSteps must be ordered by stage")]
    fn orchestrator_rejects_unsorted_steps() {
        let _ = Orchestrator::new(UNSORTED_STEPS);
    }

    #[test]
    fn with_pre_exec_orchestrator_uses_default_context() {
        let orch = Box::leak(Box::new(Orchestrator::new(NONE_CTX_STEP)));
        let cmd = Command::new("true");
        let mut cmd = with_pre_exec_orchestrator(cmd, orch, None);
        let status = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("child should start and exit successfully");
        assert!(status.success());
    }

    #[test]
    fn with_pre_exec_orchestrator_uses_provided_context() {
        let orch = Box::leak(Box::new(Orchestrator::new(SOME_CTX_STEP)));
        let cmd = Command::new("true");
        let mut cmd = with_pre_exec_orchestrator(cmd, orch, Some(PreExecContext::with_tty(7)));
        let status = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("child should start and exit successfully");
        assert!(status.success());
    }

    #[test]
    fn set_controlling_terminal_rejects_non_tty_fd() {
        let (sock_a, _sock_b) = UnixStream::pair().expect("socket pair should be created");
        let ctx = PreExecContext::with_tty(sock_a.as_raw_fd());
        let res = unsafe { steps::set_controlling_terminal(ctx) };
        assert!(res.is_err());
        assert_eq!(
            res.expect_err("must fail on non-tty fd").kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn set_controlling_terminal_accepts_pty_in_child_session() {
        let pty = Pty::open().expect("pty should open");
        let follower_fd = pty.follower.as_fd().as_raw_fd();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork must succeed");

        if pid == 0 {
            if unsafe { libc::setsid() } == -1 {
                unsafe { libc::_exit(2) };
            }
            let ctx = PreExecContext::with_tty(follower_fd);
            let code = if unsafe { steps::set_controlling_terminal(ctx) }.is_ok() {
                0
            } else {
                3
            };
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        assert_eq!(waited, pid, "waitpid should return the child pid");
        assert!(libc::WIFEXITED(status), "child should exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child should successfully set controlling terminal"
        );
    }
}
