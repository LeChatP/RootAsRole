use std::{cell::RefCell, io};

use nix::sys::stat::{Mode, umask};
use rar_common::{database::options::SBounding, util::activates_no_new_privs};
use rar_exec::orchestrator::{Orchestrator, PreExecContext, PreExecStep, Stage};

use crate::finder::de::CredOwnedData;

struct PreExecConfig {
    umask: u16,
    cred: CredOwnedData,
    bounding: SBounding,
    set_no_new_privs: bool,
}

thread_local! {
    static PRE_EXEC_CONFIG: RefCell<Option<PreExecConfig>> = const { RefCell::new(None) };
}

pub fn configure_pre_exec(
    umask: u16,
    cred: CredOwnedData,
    bounding: SBounding,
    set_no_new_privs: bool,
) {
    PRE_EXEC_CONFIG.with(|cfg| {
        *cfg.borrow_mut() = Some(PreExecConfig {
            umask,
            cred,
            bounding,
            set_no_new_privs,
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

#[allow(clippy::unnecessary_wraps)]
pub unsafe fn close_fds_step(_: PreExecContext) -> io::Result<()> {
    let _ = crate::close_restrictive_fds();
    Ok(())
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
    CLOSE_FDS_STEP,
    SET_NO_NEW_PRIVS_STEP,
    #[cfg(feature = "landlock")]
    crate::finder::api::landlock::LANDLOCK_STEP,
];

pub static PRE_EXEC_ORCHESTRATOR: Orchestrator = Orchestrator::new(PRE_EXEC_STEPS);
