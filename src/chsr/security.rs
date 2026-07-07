use std::path::PathBuf;

/// Security module, provides Landlock and Seccomp locking
/// This way, the administrator cannot edit files that should not be edited
use landlock::{
    ABI, Access, AccessFs, Compatible, PathBeneath, PathFd, RestrictionStatus, Ruleset,
    RulesetAttr, RulesetCreatedAttr,
};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

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

    //TODO: Add rule allowing the path of the policy
    for &editor in SYSTEM_EDITOR_LIST {
        if !editor.is_empty() {
            ruleset = ruleset.add_rule(PathBeneath::new(
                PathFd::new(editor)?,
                AccessFs::from_read(ABI::V6),
            ))?;
        }
    }

    Ok(ruleset
        // Allow locale + terminfo
        .add_rule(PathBeneath::new(
            PathFd::new("/usr/share/locale")?,
            AccessFs::from_read(ABI::V6) & !AccessFs::Execute,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/usr/share/terminfo")?,
            AccessFs::from_read(ABI::V6) & !AccessFs::Execute,
        ))?
        // Allow vim runtime files
        .add_rule(PathBeneath::new(
            PathFd::new("/usr/share/vim")?,
            AccessFs::from_read(ABI::V6) & !AccessFs::Execute,
        ))?
        // Allow /etc/vimrc
        .add_rule(PathBeneath::new(
            PathFd::new("/etc/vimrc")?,
            AccessFs::from_read(ABI::V6) & !AccessFs::Execute,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/lib")?,
            AccessFs::from_read(ABI::V6),
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/usr/lib")?,
            AccessFs::from_read(ABI::V6),
        ))?
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .no_new_privs(true)
        .restrict_self()?)
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
