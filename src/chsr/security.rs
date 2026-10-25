use std::path::PathBuf;

/// Security module, provides Landlock and Seccomp locking
/// This way, the administrator cannot edit files that should not be edited
use landlock::{
    ABI, Access, AccessFs, BitFlags, Compatible, PathBeneath, PathFd, RestrictionStatus, Ruleset,
    RulesetAttr, RulesetCreatedAttr,
};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use log::debug;

use crate::{cli::editor::SYSTEM_EDITOR_LIST, util::RAR_CFG_PATH};

pub fn full_program_lock(
    folder: &PathBuf,
    rar_cfg_data_path: &str,
) -> Result<RestrictionStatus, Box<dyn std::error::Error>> {
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V6))?
        .create()?
        .add_rule(PathBeneath::new(
            PathFd::new(RAR_CFG_PATH)?,
            AccessFs::IoctlDev
                | AccessFs::ReadFile
                | AccessFs::WriteFile
                | AccessFs::Truncate
                | AccessFs::Refer,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new(rar_cfg_data_path)?,
            AccessFs::from_all(ABI::V6),
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new(folder)?,
            AccessFs::from_all(ABI::V6),
        ))?;

    // what the editor needs to run, where it exists
    let read = AccessFs::from_read(ABI::V6);
    let data = read & !AccessFs::Execute;
    let optional = SYSTEM_EDITOR_LIST
        .iter()
        .filter(|editor| !editor.is_empty())
        .map(|&editor| (editor, read))
        .chain([
            ("/usr/share/locale", data),
            ("/usr/share/terminfo", data),
            ("/usr/share/vim", data),
            ("/etc/vimrc", data),
            ("/lib", read),
            ("/usr/lib", read),
        ]);
    for (path, access) in optional {
        if let Some(rule) = optional_rule(path, access) {
            ruleset = ruleset.add_rule(rule)?;
        }
    }

    Ok(ruleset
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .no_new_privs(true)
        .restrict_self()?)
}

/// The rule for a path that the editor may need, or `None` when it does not exist on this
/// system: one missing path, like `/etc/vimrc` on Debian or an editor that is not installed, made
/// the whole ruleset fail, and chsr then ran without Landlock. Leaving it out only allows less.
fn optional_rule(path: &str, access: BitFlags<AccessFs>) -> Option<PathBeneath<PathFd>> {
    match PathFd::new(path) {
        Ok(fd) => Some(PathBeneath::new(fd, access)),
        Err(e) => {
            debug!("Landlock: {path} is left out: {e}");
            None
        }
    }
}

#[cfg(debug_assertions)]
const SECCOMP: ScmpAction = ScmpAction::Log;
#[cfg(not(debug_assertions))]
const SECCOMP: ScmpAction = ScmpAction::Log;

/// Applies a seccomp filter that blocks process creation and execution syscalls,
/// as well as some other potentially dangerous syscalls.
/// This was originally to has a allowlist of syscalls,
/// but it turns out that some editors (like vim) use a lot of syscalls,
/// and it's hard to maintain an allowlist without breaking functionality.
pub fn seccomp_lock() -> std::io::Result<()> {
    // Allow all by default; explicitly kill process creation/execution.
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow).map_err(|e| {
        std::io::Error::other(format!("Failed to create seccomp filter context: {e}"))
    })?;

    let blocked_syscalls = [
        // Blocking forking
        "fork",
        "vfork",
        // Not used by an editor, so they don't need to be allowed.
        "ptrace",
        "bpf",
        "perf_event_open",
        "keyctl",
        "add_key",
        "request_key",
        "mount",
        "umount2",
        "pivot_root",
        "setns",
        "unshare",
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "init_module",
        "finit_module",
        "delete_module",
        "iopl",
        "ioperm",
        "syslog",
        "acct",
        "quotactl",
        "swapon",
        "swapoff",
        "userfaultfd",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "process_vm_readv",
        "process_vm_writev",
    ];
    for &name in &blocked_syscalls {
        ctx.add_rule(
            SECCOMP,
            ScmpSyscall::from_name(name).map_err(|e| {
                std::io::Error::other(format!("Failed to resolve syscall {name}: {e}"))
            })?,
        )
        .map_err(|e| {
            std::io::Error::other(format!("Failed to add seccomp rule for {name}: {e}"))
        })?;
    }

    ctx.load()
        .map_err(|e| std::io::Error::other(format!("Failed to load seccomp filter: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_missing_path_is_left_out() {
        let read = AccessFs::from_read(ABI::V6);
        assert!(optional_rule("/nonexistent/rar-editor", read).is_none());
        assert!(optional_rule("/", read).is_some());
    }
}
