use std::path::PathBuf;

/// Security module, provides Landlock and Seccomp locking
/// This way, the administrator cannot edit files that should not be edited
use landlock::{
    Access, AccessFs, Compatible, PathBeneath, PathFd, RestrictionStatus, Ruleset, RulesetAttr,
    RulesetCreatedAttr, ABI,
};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

use crate::{cli::editor::SYSTEM_EDITOR, ROOTASROLE};

pub(crate) fn full_program_lock(
    folder: &PathBuf,
) -> Result<RestrictionStatus, Box<dyn std::error::Error>> {
    Ok(Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V6))?
        .create()?
        .add_rule(PathBeneath::new(
            PathFd::new(ROOTASROLE)?,
            AccessFs::IoctlDev
                | AccessFs::ReadFile
                | AccessFs::WriteFile
                | AccessFs::Truncate
                | AccessFs::Refer,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new(folder)?,
            AccessFs::from_all(ABI::V6),
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new(SYSTEM_EDITOR)?,
            AccessFs::from_read(ABI::V6),
        ))?
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
        .set_no_new_privs(true)
        .restrict_self()?)
}

pub fn seccomp_lock() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the seccomp filter with the default action to kill the process
    let mut ctx = ScmpFilterContext::new_filter(ScmpAction::KillProcess)?;

    let syscalls = [
        "statx",
        "openat",
        "geteuid",
        "getegid",
        "capget",
        "capset",
        "flock",
        "ioctl",
        "read",
        "write",
        "lseek",
        "pselect6",
        "newfstatat",
        "timer_settime",
        "fcntl",
        "close",
        "rt_sigaction",
        "rt_sigprocmask",
        "mmap",
        "getrandom",
        "mkdir",
        "fstat",
        "getuid",
        "getgid",
        "umask",
        "unlink",
        "clone3",
        "execve",
        "munmap",
        "wait4",
        "brk",
        "access",
        "pread64",
        "arch_prctl",
        "set_robust_list",
        "rseq",
        "mprotect",
        "rename",
        "exit_group",
        "getdents64",
        "unlinkat",
        "sigaltstack",
        "prlimit64",
        "getcwd",
        "chdir",
        "sysinfo",
        "readlink",
        "fchdir",
        "setfsuid",
        "setfsgid",
        "futex",
        "uname",
        "getpid",
        "chmod",
        "fchmod",
        "madvise",
        "timer_create",
        "rt_sigtimedwait",
        "set_tid_address",
        "clock_nanosleep",
        "fsync",
        "getxattr",
        "setxattr",
        "lsetxattr",
        "fsetxattr",
        "listxattr",
        "ftruncate",
        "truncate",
        "waitid"

    ];
    for &name in &syscalls {
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name(name)?)?;
    }

    ctx.load()?;

    Ok(())
}
