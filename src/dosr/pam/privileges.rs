//! The identity of dosr while PAM runs in its process.
//!
//! The password and the account of the caller are checked with the effective uid of root, like
//! under sudo: `pam_faillock` creates and updates the tally of the caller, and libpam sends its
//! audit records. Root gives dosr no capability there: the only effective one is
//! `CAP_AUDIT_WRITE`, and the real uid stays the caller's (`pam_rootok` checks it). A program that
//! a module runs, such as `unix_chkpwd`, gets the capabilities of root, as under sudo: with
//! `SECBIT_NOROOT`, `unix_chkpwd` refused every password (the kernel refuses its audit record,
//! which it does not forgive to root) and could not read a shadow file of mode 0000 (Fedora,
//! RHEL). The session steps run as the caller, with `CAP_AUDIT_WRITE` only.

use std::io;

use capctl::{Cap, CapState, prctl::Secbits};
use libc::c_ulong;
use log::{debug, error};
use nix::unistd::{ResUid, Uid, getresuid};
use rootasrole_core::util::{drop_effective, initialize_capabilities, with_privileges};

use crate::error::{SrError, SrResult};

/// The securebits added while the effective uid is root: the change of the effective uid between
/// the caller and root neither copies the permitted set into the effective one nor empties the
/// permitted set (`NO_SETUID_FIXUP`).
const ROOT_WITHOUT_CAPABILITIES: c_ulong = Secbits::NO_SETUID_FIXUP.bits();

/// The securebits of this thread, all of them: capctl leaves out the bits it does not know,
/// which a restore would clear.
fn securebits() -> io::Result<c_ulong> {
    // SAFETY: PR_GET_SECUREBITS takes no pointer and writes no memory of the process
    let bits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
    c_ulong::try_from(bits).map_err(|_| io::Error::last_os_error())
}

fn set_securebits(bits: c_ulong) -> io::Result<()> {
    with_privileges(&[Cap::SETPCAP], || {
        // SAFETY: PR_SET_SECUREBITS takes the bits by value and writes no memory of the process
        if unsafe { libc::prctl(libc::PR_SET_SECUREBITS, bits, 0, 0, 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })
}

/// The system call that sets the uids with 32 bits: the call named `setresuid` takes 16-bit uids
/// on these architectures.
#[cfg(any(target_arch = "x86", target_arch = "arm", target_arch = "sparc"))]
const SYS_SETRESUID: libc::c_long = libc::SYS_setresuid32;
#[cfg(not(any(target_arch = "x86", target_arch = "arm", target_arch = "sparc")))]
const SYS_SETRESUID: libc::c_long = libc::SYS_setresuid;

/// The uids of this thread only, like its securebits and its capability sets: `setresuid(3)` of
/// glibc changes the uids of every thread, which would give another thread the permitted set as
/// effective one, then empty its permitted set.
fn set_uids(real: Uid, effective: Uid, saved: Uid) -> io::Result<()> {
    with_privileges(&[Cap::SETUID], || {
        // SAFETY: setresuid takes the three uids by value and writes no memory of the process
        let result = unsafe {
            libc::syscall(
                SYS_SETRESUID,
                real.as_raw(),
                effective.as_raw(),
                saved.as_raw(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })
}

/// `CAP_AUDIT_WRITE` in the effective set, when dosr has it: without it (a bounding set without
/// it), the audit records of PAM are lost, as when PAM ran as the caller.
fn raise_audit_write() {
    if let Err(e) = initialize_capabilities(&[Cap::AUDIT_WRITE]) {
        debug!("The audit records of PAM are lost, CAP_AUDIT_WRITE is not permitted: {e}");
    }
}

/// The effective and saved uids of root without its capabilities, until it is dropped: the uids
/// and the securebits of the caller are given back, with an empty effective set.
///
/// The saved uid is root too: `pam_unix` (Linux-PAM 1.6 and later) checks the password and the
/// account with `unix_chkpwd`, from a child that first calls `setuid(0)` when its effective uid
/// is root, and stops if it fails. Without `CAP_SETUID`, it only succeeds when the real or the
/// saved uid is root, and then changes the effective uid only: `unix_chkpwd` still runs with the
/// real uid of the caller, so it only checks the password of the caller.
struct RootWithoutCapabilities {
    caller: ResUid,
    securebits: c_ulong,
}

impl RootWithoutCapabilities {
    fn enter() -> SrResult<Self> {
        let permitted = CapState::get_current()?.permitted;
        if !permitted.has(Cap::SETUID) || !permitted.has(Cap::SETPCAP) {
            error!(
                "dosr cannot check the password and the account as root: setuid and setpcap are not permitted"
            );
            return Err(SrError::InsufficientPrivileges);
        }
        let failed = |e: io::Error| {
            error!("dosr cannot take the identity of root to check the password: {e}");
            SrError::SystemError
        };
        let caller = getresuid().map_err(|e| failed(e.into()))?;
        let securebits = securebits().map_err(failed)?;
        // before the effective uid of root, or the effective set would get the permitted one
        set_securebits(securebits | ROOT_WITHOUT_CAPABILITIES).map_err(failed)?;
        // from here, an error gives the caller back when the window is dropped
        let window = Self { caller, securebits };
        set_uids(caller.real, Uid::from_raw(0), Uid::from_raw(0)).map_err(failed)?;
        raise_audit_write();
        Ok(window)
    }

    /// The uids first: `NO_SETUID_FIXUP` keeps the permitted set when no uid is root anymore.
    fn leave(&self) -> io::Result<()> {
        set_uids(self.caller.real, self.caller.effective, self.caller.saved)?;
        set_securebits(self.securebits)?;
        drop_effective().map_err(io::Error::from)
    }
}

impl Drop for RootWithoutCapabilities {
    fn drop(&mut self) {
        if let Err(e) = self.leave() {
            error!("dosr cannot give the identity of the caller back after PAM: {e}");
            // never go on as root, nor with the securebits of the window
            std::process::abort();
        }
    }
}

/// Run `check`, the authentication and the account steps of PAM, with the effective uid of root
/// and `CAP_AUDIT_WRITE` only; the identity of the caller is back after it, even when it fails
/// or panics. Without `CAP_SETUID` and `CAP_SETPCAP`, dosr does not check the password at all.
pub(super) fn as_root_without_capabilities<R>(check: impl FnOnce() -> SrResult<R>) -> SrResult<R> {
    let _window = RootWithoutCapabilities::enter()?;
    check()
}

/// Run `step`, a step of the PAM session, as the caller with `CAP_AUDIT_WRITE` only, for the
/// audit records of libpam.
pub(super) fn with_audit_write<R>(step: impl FnOnce() -> R) -> R {
    raise_audit_write();
    let result = step();
    if let Err(e) = drop_effective() {
        error!("dosr cannot drop CAP_AUDIT_WRITE after a step of the PAM session: {e}");
        std::process::abort();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use capctl::CapSet;

    /// The uids, the securebits and the capability sets of this thread.
    fn identity() -> (ResUid, c_ulong, CapState) {
        (
            getresuid().unwrap(),
            securebits().unwrap(),
            CapState::get_current().unwrap(),
        )
    }

    fn same(a: &(ResUid, c_ulong, CapState), b: &(ResUid, c_ulong, CapState)) -> bool {
        (a.0.real, a.0.effective, a.0.saved, a.1, a.2)
            == (b.0.real, b.0.effective, b.0.saved, b.1, b.2)
    }

    fn can_take_root() -> bool {
        let permitted = CapState::get_current().unwrap().permitted;
        permitted.has(Cap::SETUID) && permitted.has(Cap::SETPCAP)
    }

    // Without the capabilities, the window is refused and nothing changes; with them (a VM, as a
    // user with ambient setuid, setpcap and audit_write), the check runs with the effective uid
    // of root and CAP_AUDIT_WRITE only, and the caller is back after it, also after an error
    // and a panic
    #[test]
    fn test_the_caller_is_back_after_the_check() {
        drop_effective().unwrap();
        let caller = identity();
        if !can_take_root() {
            assert_eq!(
                as_root_without_capabilities(|| -> SrResult<()> {
                    panic!("checked as the caller")
                }),
                Err(SrError::InsufficientPrivileges)
            );
            assert!(same(&identity(), &caller));
            eprintln!("Skipping the window: setuid and setpcap are not permitted");
            return;
        }
        let inside = as_root_without_capabilities(|| Ok(identity())).unwrap();
        assert_eq!(inside.0.real, caller.0.real);
        assert_eq!(inside.0.effective, Uid::from_raw(0));
        assert_eq!(inside.0.saved, Uid::from_raw(0));
        assert_eq!(inside.1, caller.1 | ROOT_WITHOUT_CAPABILITIES);
        assert_eq!(inside.2.permitted, caller.2.permitted);
        let audit = if caller.2.permitted.has(Cap::AUDIT_WRITE) {
            CapSet::from_iter([Cap::AUDIT_WRITE])
        } else {
            CapSet::empty()
        };
        assert_eq!(inside.2.effective, audit);
        assert!(same(&identity(), &caller));

        assert_eq!(
            as_root_without_capabilities(|| -> SrResult<()> { Err(SrError::AuthenticationFailed) }),
            Err(SrError::AuthenticationFailed)
        );
        assert!(same(&identity(), &caller));

        let panicked = std::panic::catch_unwind(|| {
            as_root_without_capabilities(|| -> SrResult<()> { panic!("a module panicked") })
        });
        assert!(panicked.is_err());
        assert!(same(&identity(), &caller));
    }

    #[test]
    fn test_audit_write_is_dropped_after_the_step() {
        drop_effective().unwrap();
        let caller = identity();
        let inside = with_audit_write(|| CapState::get_current().unwrap().effective);
        assert!(inside.iter().all(|cap| cap == Cap::AUDIT_WRITE));
        assert_eq!(
            inside.has(Cap::AUDIT_WRITE),
            caller.2.permitted.has(Cap::AUDIT_WRITE)
        );
        assert!(same(&identity(), &caller));
    }
}
