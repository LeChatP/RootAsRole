//! dosr dumps no core. Its memory holds the policy (a root file), the PAM handle (the password
//! once checked) and the cookies, and the caller can send it any signal, since its real uid is
//! the caller's: ^\ at the prompt, or `kill -QUIT` at any time, also while PAM runs with the
//! effective uid of root. Like sudo (`disable_coredump`), whatever `fs.suid_dumpable` and
//! `kernel.core_pattern` say:
//!
//! - `RLIMIT_CORE` is 0, the hard limit too: outside the PAM window the uids of dosr are the
//!   caller's, who could raise a soft limit with prlimit(2);
//! - dosr is not dumpable: the kernel ignores `RLIMIT_CORE` for a `core_pattern` pipe, and only
//!   this flag stops it there. The kernel sets the flag back to `fs.suid_dumpable` at each change
//!   of the uids or of the filesystem ids: [`keep_undumpable`] follows each one.
//!
//! The command gets the core limit of the caller back (`pre_exec`), and its own dumpable flag
//! from its execve.

use log::error;
use nix::sys::{
    prctl,
    resource::{Resource, getrlimit, setrlimit},
};

/// A soft and a hard `RLIMIT_CORE`.
pub type CoreLimit = (libc::rlim_t, libc::rlim_t);

/// No core dump of dosr from here. Returns the core limit of the caller, for the command.
pub fn disable() -> Option<CoreLimit> {
    let caller = getrlimit(Resource::RLIMIT_CORE)
        .inspect_err(|e| error!("Cannot read the core limit of the caller: {e}"))
        .ok();
    if let Err(e) = setrlimit(Resource::RLIMIT_CORE, 0, 0) {
        error!("Cannot disable the core dumps of dosr: {e}");
    }
    keep_undumpable();
    caller
}

/// Not dumpable again, after a change of the uids or of the filesystem ids, which gives the
/// flag the value of `fs.suid_dumpable`.
pub fn keep_undumpable() {
    if let Err(e) = prctl::set_dumpable(false) {
        error!("Cannot make dosr undumpable: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // the limit cannot be raised back without CAP_SYS_RESOURCE: the test process keeps it, which
    // only takes the core dumps of the tests away
    #[test]
    fn test_no_core_dump_after_disable() {
        let caller = disable();
        assert!(caller.is_some());
        assert_eq!(getrlimit(Resource::RLIMIT_CORE).unwrap(), (0, 0));
        assert!(!prctl::get_dumpable().unwrap());
        // as after a change of the uids with fs.suid_dumpable = 1
        prctl::set_dumpable(true).unwrap();
        keep_undumpable();
        assert!(!prctl::get_dumpable().unwrap());
    }
}
