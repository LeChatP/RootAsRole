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
    /// Returns an error if the file descriptor is not a TTY or if the controlling-terminal setup fails.
    /// # Safety
    /// The caller must ensure that the provided file descriptor is valid and refers to a terminal.
    pub unsafe fn set_controlling_terminal(ctx: PreExecContext) -> io::Result<()> {
        let fd = ctx.tty_fd.unwrap_or(0);
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
mod example {
    use super::*;
    use libc::*;

    unsafe fn _create_session(_: PreExecContext) -> io::Result<()> {
        if unsafe { setsid() } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    unsafe fn _drop_privileges(_: PreExecContext) -> io::Result<()> {
        if unsafe { setuid(1000) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub static _STEPS: &[PreExecStep] = &[
        PreExecStep {
            stage: Stage::SESSION,
            run: _create_session,
        },
        PreExecStep {
            stage: Stage::PRIV_DROP,
            run: _drop_privileges,
        },
    ];

    pub static _ORCH: Orchestrator = Orchestrator::new(_STEPS);
}
