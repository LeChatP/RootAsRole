//! Type-safe wrappers for common primitives using the Newtype pattern.
//! See <https://doc.rust-lang.org/rust-by-example/generics/new_types.html>

use std::fmt;
use std::os::fd::RawFd;

/// A process identifier - a semantic wrapper around ``libc::pid_t``.
///
/// This type ensures that PIDs are not accidentally confused with other integer types
/// and provides methods for common PID operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessId(libc::pid_t);

impl ProcessId {
    /// Creates a new ``ProcessId`` from a raw pid.
    ///
    /// # Errors
    /// Returns `None` if the pid is not positive (invalid).
    #[must_use]
    pub const fn new(pid: libc::pid_t) -> Option<Self> {
        if pid > 0 {
            Some(Self(pid))
        } else {
            None
        }
    }

    /// Creates a ``ProcessId`` from a raw value without validation.
    ///
    /// # Safety
    /// The caller must ensure the pid is valid and positive.
    #[must_use]
    pub const unsafe fn new_unchecked(pid: libc::pid_t) -> Self {
        Self(pid)
    }

    #[must_use]
    pub const fn as_raw(self) -> libc::pid_t {
        self.0
    }

    #[must_use]
    pub fn current() -> Self {
        Self(unsafe { libc::getpid() })
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 > 0
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ProcessId> for libc::pid_t {
    fn from(pid: ProcessId) -> Self {
        pid.0
    }
}

/// A signal number - a semantic wrapper around ``libc::c_int`` for signal handling.
///
/// This type ensures that signal numbers are not confused with other integer types
/// and validates that they are within the valid range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignalNumber(libc::c_int);

// Standard maximum number of signals on POSIX systems
const MAX_SIGNAL: libc::c_int = 32;

impl SignalNumber {
    /// Creates a new ``SignalNumber`` from a raw signal value.
    /// Returns `None` if the signal number is not within the valid range (0 < sig <= ``MAX_SIGNAL``).
    #[must_use]
    pub const fn new(sig: libc::c_int) -> Option<Self> {
        if sig > 0 && sig <= MAX_SIGNAL {
            Some(Self(sig))
        } else {
            None
        }
    }

    /// Creates a ``SignalNumber`` from a raw value without validation.
    ///
    /// # Safety
    /// The caller must ensure the signal number is valid (0 < sig <= ``MAX_SIGNAL``).
    #[must_use]
    pub const unsafe fn new_unchecked(sig: libc::c_int) -> Self {
        Self(sig)
    }

    #[must_use]
    pub const fn as_raw(self) -> libc::c_int {
        self.0
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 > 0 && self.0 <= MAX_SIGNAL
    }
}

impl fmt::Display for SignalNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<SignalNumber> for libc::c_int {
    fn from(sig: SignalNumber) -> Self {
        sig.0
    }
}

/// A raw file descriptor - a semantic wrapper around ``RawFd``.
///
/// This provides validation and safety checks for raw file descriptor values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RawFileDescriptor(RawFd);

impl RawFileDescriptor {
    /// Creates a new ``RawFileDescriptor`` from a raw fd value.
    ///
    /// # Errors
    /// Returns `None` if the fd is negative (invalid).
    #[must_use]
    pub const fn new(fd: RawFd) -> Option<Self> {
        if fd >= 0 {
            Some(Self(fd))
        } else {
            None
        }
    }

    /// Creates a ``RawFileDescriptor`` without validation.
    ///
    /// # Safety
    /// The caller must ensure the fd is valid (>= 0).
    #[must_use]
    pub const unsafe fn new_unchecked(fd: RawFd) -> Self {
        Self(fd)
    }

    #[must_use]
    pub const fn as_raw(self) -> RawFd {
        self.0
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 >= 0
    }
}

impl fmt::Display for RawFileDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<RawFileDescriptor> for RawFd {
    fn from(fd: RawFileDescriptor) -> Self {
        fd.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_id_validation() {
        assert!(ProcessId::new(1).is_some());
        assert!(ProcessId::new(0).is_none());
        assert!(ProcessId::new(-1).is_none());
    }

    #[test]
    fn signal_number_validation() {
        assert!(SignalNumber::new(1).is_some());
        assert!(SignalNumber::new(libc::SIGTERM).is_some());
        assert!(SignalNumber::new(0).is_none());
        assert!(SignalNumber::new(-1).is_none());
    }

    #[test]
    fn raw_fd_validation() {
        assert!(RawFileDescriptor::new(0).is_some());
        assert!(RawFileDescriptor::new(3).is_some());
        assert!(RawFileDescriptor::new(-1).is_none());
    }
}
