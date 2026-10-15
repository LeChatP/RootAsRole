use std::{cell::RefCell, ffi::CString, io};

use nix::sys::stat::{Mode, umask};
use rootasrole_core::{database::options::SBounding, util::activates_no_new_privs};
use rootasrole_exec::orchestrator::{Orchestrator, PreExecContext, PreExecStep, Stage};

use crate::finder::de::cred::CredOwnedData;

struct PreExecConfig {
    umask: u16,
    cred: CredOwnedData,
    bounding: SBounding,
    set_no_new_privs: bool,
    /// Prepared before the fork, so that the child does not allocate.
    workdir: Option<CString>,
}

thread_local! {
    static PRE_EXEC_CONFIG: RefCell<Option<PreExecConfig>> = const { RefCell::new(None) };
}

pub fn configure_pre_exec(
    umask: u16,
    cred: CredOwnedData,
    bounding: SBounding,
    set_no_new_privs: bool,
    workdir: Option<CString>,
) {
    PRE_EXEC_CONFIG.with(|cfg| {
        *cfg.borrow_mut() = Some(PreExecConfig {
            umask,
            cred,
            bounding,
            set_no_new_privs,
            workdir,
        });
    });
}

pub unsafe fn set_umask_step(_: PreExecContext) -> io::Result<()> {
    PRE_EXEC_CONFIG.with(|cfg| {
        if let Some(cfg) = cfg.borrow().as_ref() {
            umask(Mode::from_bits_truncate(u32::from(cfg.umask)));
        }
        Ok(())
    })
}

pub unsafe fn set_credentials_step(_: PreExecContext) -> io::Result<()> {
    PRE_EXEC_CONFIG.with(|cfg| {
        if let Some(cfg) = cfg.borrow().as_ref() {
            crate::setuid_setgid(&cfg.cred)
                .map_err(|e| io::Error::other(format!("Failed to set uid/gid: {e}")))?;
        }
        Ok(())
    })
}

pub unsafe fn set_capabilities_step(_: PreExecContext) -> io::Result<()> {
    PRE_EXEC_CONFIG.with(|cfg| {
        if let Some(cfg) = cfg.borrow().as_ref() {
            crate::set_capabilities(&cfg.cred, cfg.bounding)
                .map_err(|e| io::Error::other(format!("Failed to set capabilities: {e}")))?;
        }
        Ok(())
    })
}

/// Enter the working directory as the target user: a directory that the target cannot enter is
/// an error, like with sudo.
pub unsafe fn set_workdir_step(_: PreExecContext) -> io::Result<()> {
    PRE_EXEC_CONFIG.with(|cfg| {
        if let Some(workdir) = cfg.borrow().as_ref().and_then(|cfg| cfg.workdir.as_ref()) {
            nix::unistd::chdir(workdir.as_c_str()).map_err(io::Error::from)?;
        }
        Ok(())
    })
}

pub unsafe fn set_no_new_privs_step(_: PreExecContext) -> io::Result<()> {
    PRE_EXEC_CONFIG.with(|cfg| {
        if cfg
            .borrow()
            .as_ref()
            .is_some_and(|cfg| cfg.set_no_new_privs)
        {
            activates_no_new_privs()
                .map_err(|e| io::Error::other(format!("Failed to set no_new_privs: {e}")))?;
        }
        Ok(())
    })
}

pub unsafe fn close_fds_step(_: PreExecContext) -> io::Result<()> {
    crate::close_restrictive_fds()
}

pub const SET_UMASK_STEP: PreExecStep = PreExecStep {
    stage: Stage::UMASK,
    run: set_umask_step,
};

pub const SET_CREDENTIALS_STEP: PreExecStep = PreExecStep {
    stage: Stage::PRIV_DROP,
    run: set_credentials_step,
};

pub const SET_CAPABILITIES_STEP: PreExecStep = PreExecStep {
    stage: Stage::CAPS,
    run: set_capabilities_step,
};

pub const SET_WORKDIR_STEP: PreExecStep = PreExecStep {
    stage: Stage::WORKDIR,
    run: set_workdir_step,
};

pub const CLOSE_FDS_STEP: PreExecStep = PreExecStep {
    stage: Stage::FD_CLEANUP,
    run: close_fds_step,
};

pub const SET_NO_NEW_PRIVS_STEP: PreExecStep = PreExecStep {
    stage: Stage::LOCKDOWN,
    run: set_no_new_privs_step,
};

pub static PRE_EXEC_STEPS: &[PreExecStep] = &[
    SET_UMASK_STEP,
    SET_CREDENTIALS_STEP,
    SET_CAPABILITIES_STEP,
    SET_WORKDIR_STEP,
    CLOSE_FDS_STEP,
    SET_NO_NEW_PRIVS_STEP,
    #[cfg(feature = "landlock")]
    crate::finder::api::landlock::LANDLOCK_STEP,
];

pub static PRE_EXEC_ORCHESTRATOR: Orchestrator = Orchestrator::new(PRE_EXEC_STEPS);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finder::de::cred::CredOwnedData;
    use rootasrole_core::database::options::SBounding;

    #[test]
    fn pre_exec_steps_are_ordered_and_stable() {
        configure_pre_exec(
            0o022,
            CredOwnedData::default(),
            SBounding::Ignore,
            false,
            None,
        );

        assert_eq!(SET_UMASK_STEP.stage, Stage::UMASK);
        assert_eq!(SET_CREDENTIALS_STEP.stage, Stage::PRIV_DROP);
        assert_eq!(SET_CAPABILITIES_STEP.stage, Stage::CAPS);
        // the working directory is entered as the target user
        assert_eq!(SET_WORKDIR_STEP.stage, Stage::WORKDIR);
        assert!(Stage::WORKDIR > Stage::PRIV_DROP && Stage::WORKDIR > Stage::CAPS);
        assert_eq!(CLOSE_FDS_STEP.stage, Stage::FD_CLEANUP);
        assert_eq!(SET_NO_NEW_PRIVS_STEP.stage, Stage::LOCKDOWN);

        let stages: Vec<_> = PRE_EXEC_STEPS
            .iter()
            .map(|step| step.stage.order())
            .collect();
        assert!(stages.windows(2).all(|pair| pair[0] <= pair[1]));

        #[cfg(feature = "landlock")]
        assert_eq!(stages.last().copied(), Some(Stage::LOCKDOWN.order()));

        #[cfg(not(feature = "landlock"))]
        assert_eq!(stages, vec![45, 50, 55, 60, 65, 70]);
    }
}
