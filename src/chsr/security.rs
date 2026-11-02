use std::fs;
use std::path::{Path, PathBuf};

/// Security module, provides Landlock and Seccomp locking
/// This way, the administrator cannot edit files that should not be edited
use landlock::{
    ABI, Access, AccessFs, BitFlags, Compatible, PathBeneath, PathFd, RestrictionStatus, Ruleset,
    RulesetAttr, RulesetCreatedAttr,
};
use libseccomp::{ScmpAction, ScmpArch, ScmpFilterContext, ScmpSyscall};
use log::debug;

use crate::{
    cli::editor::SYSTEM_EDITOR_LIST,
    util::{CHSR_RUN_DIR, RAR_CFG_PATH},
};

/// The ELF interpreter of the editor, read from the binary itself: the exact loader keeps execute
/// (the kernel checks `MAY_EXEC` on it when the editor starts), without guessing its path.
fn editor_interpreter(editor: &str) -> Option<String> {
    let buffer = fs::read(editor).ok()?;
    goblin::elf::Elf::parse(&buffer)
        .ok()?
        .interpreter
        .map(str::to_string)
}

/// What the editors read, and never write nor run: their data, the terminal descriptions, the
/// locales. A path missing on this system is left out ([`optional_rule`]).
const EDITOR_DATA: &[&str] = &[
    "/usr/share/locale",
    "/usr/share/terminfo",
    "/usr/share/vim",
    "/etc/vimrc",
    // emacs: its Lisp, and its dump file, under /usr/libexec on Debian, /usr/lib elsewhere
    "/usr/share/emacs",
    "/usr/libexec/emacs",
    // the locale aliases of X11, which emacs reads at start where they are installed: refused,
    // emacs stopped there and never opened the file
    "/usr/share/X11/locale",
];

/// The controlling terminal, which emacs opens again instead of the one it inherits: the editor
/// already holds that terminal as its standard input and output, so this gives it nothing more.
const TERMINAL: &str = "/dev/tty";

fn terminal_access() -> BitFlags<AccessFs> {
    AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::IoctlDev
}

/// Landlock on the whole chsr process: it may write only the policy files and the temporary folder
/// of the editor, and read and run what the editor needs. The editor child gets a second, stricter
/// domain of its own ([`editor_lock`]); since Landlock intersects nested domains, broad execute
/// here only concerns chsr, which spawns nothing but the editor.
pub fn full_program_lock(
    folder: &PathBuf,
    rar_cfg_data_path: &str,
) -> Result<RestrictionStatus, Box<dyn std::error::Error>> {
    let read = AccessFs::from_read(ABI::V6);
    let data = read & !AccessFs::Execute;
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
        ))?
        // the folder itself is removed at the end, which is the right to remove a directory of
        // its parent: /run/chsr holds only the folders of chsr, where /tmp holds every user's
        .add_rule(PathBeneath::new(
            PathFd::new(CHSR_RUN_DIR)?,
            AccessFs::RemoveDir,
        ))?;
    let optional = SYSTEM_EDITOR_LIST
        .iter()
        .filter(|editor| !editor.is_empty())
        .map(|&editor| (editor, read))
        .chain(EDITOR_DATA.iter().map(|&path| (path, data)))
        .chain([
            (TERMINAL, terminal_access()),
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

/// Landlock on the editor child, nested under [`full_program_lock`]. The editor may write only the
/// temporary folder, read and run only its own binary and interpreter, and read its assets. It
/// cannot write nor read the policy files (so no `:w` of the policy, bypassing chsr), nor execute
/// another program such as a shell under `/usr/lib` (a shell escape). Applied in the editor's
/// `pre_exec`, after `no_new_privs` is already set by [`full_program_lock`].
pub fn editor_lock(folder: &Path, editor: &str) -> std::io::Result<()> {
    build_editor_domain(folder, editor).map_err(|e| std::io::Error::other(e.to_string()))
}

fn build_editor_domain(folder: &Path, editor: &str) -> Result<(), Box<dyn std::error::Error>> {
    let read = AccessFs::from_read(ABI::V6);
    let data = read & !AccessFs::Execute;
    // the one writable place: the file being edited and the editor's swap files
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V6))?
        .create()?
        .add_rule(PathBeneath::new(
            PathFd::new(folder)?,
            AccessFs::from_all(ABI::V6),
        ))?;
    // the editor binary and its interpreter keep execute; everything else is read-only, so no
    // other program under /lib or /usr/lib (e.g. /usr/lib/klibc/bin/sh) can be run
    let mut optional: Vec<(&str, BitFlags<AccessFs>)> = vec![(editor, read)];
    let interpreter = editor_interpreter(editor);
    if let Some(interpreter) = interpreter.as_deref() {
        optional.push((interpreter, read));
    }
    optional.extend(EDITOR_DATA.iter().map(|&path| (path, data)));
    optional.extend([
        (TERMINAL, terminal_access()),
        ("/lib", data),
        ("/usr/lib", data),
    ]);
    for (path, access) in optional {
        if let Some(rule) = optional_rule(path, access) {
            ruleset = ruleset.add_rule(rule)?;
        }
    }
    ruleset
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .no_new_privs(true)
        .restrict_self()?;
    Ok(())
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

/// The privileged syscalls that no editor needs to edit a file, refused with `EPERM` to the
/// editor and its children. This is defense-in-depth, not a boundary: whoever runs `chsr editor`
/// is root-equivalent, and the filter cannot allow everything an editor needs and still stop a
/// shell escape (vim alone makes hundreds of syscalls, which is why sudo has `noexec`). `execve`
/// stays allowed, or the editor could not start; where it may run a program is Landlock's job
/// ([`full_program_lock`] grants execute on the editor paths only). The list refuses the syscalls
/// that reconfigure the machine or read another process, which an edit never uses.
const BLOCKED_SYSCALLS: &[&str] = &[
    // process creation: glibc uses clone, so these are rarely reached, but harmless to refuse;
    // clone and clone3 stay allowed, the editor may need them, and Landlock gates the execve
    "fork",
    "vfork",
    // reading or tracing another process
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    // loading code into the kernel, or asking it to run it
    "bpf",
    "perf_event_open",
    "init_module",
    "finit_module",
    "delete_module",
    "kexec_load",
    "kexec_file_load",
    // the kernel keyring
    "keyctl",
    "add_key",
    "request_key",
    // mounts and namespaces
    "mount",
    "umount2",
    "pivot_root",
    "setns",
    "unshare",
    // machine-wide state
    "reboot",
    "iopl",
    "ioperm",
    "syslog",
    "acct",
    "quotactl",
    "swapon",
    "swapoff",
    // userfaultfd and io_uring give ways to run work the filter cannot see
    "userfaultfd",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];

/// The architectures the filter covers besides the native one: a 64-bit process could otherwise
/// call a blocked syscall through the 32-bit compat ABI, which has its own syscall numbers
/// (sudo-rs #1230). `add_rule` is fuzzy, so a syscall that an architecture does not define is
/// skipped there, not an error.
#[cfg(target_arch = "x86_64")]
const COMPAT_ARCHS: &[ScmpArch] = &[ScmpArch::X86, ScmpArch::X32];
#[cfg(target_arch = "aarch64")]
const COMPAT_ARCHS: &[ScmpArch] = &[ScmpArch::Arm];
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const COMPAT_ARCHS: &[ScmpArch] = &[];

/// Build the seccomp filter: everything allowed, [`BLOCKED_SYSCALLS`] refused with `EPERM` on the
/// native and the compat architectures.
fn seccomp_filter() -> std::io::Result<ScmpFilterContext> {
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow).map_err(|e| {
        std::io::Error::other(format!("Failed to create seccomp filter context: {e}"))
    })?;
    // before the rules, so that each rule resolves for every architecture of the filter
    for &arch in COMPAT_ARCHS {
        if let Err(e) = ctx.add_arch(arch) {
            debug!("seccomp: cannot cover the architecture {arch:?}: {e}");
        }
    }
    let deny = ScmpAction::Errno(libc::EPERM);
    for &name in BLOCKED_SYSCALLS {
        let syscall = ScmpSyscall::from_name(name)
            .map_err(|e| std::io::Error::other(format!("Failed to resolve syscall {name}: {e}")))?;
        ctx.add_rule(deny, syscall).map_err(|e| {
            std::io::Error::other(format!("Failed to add seccomp rule for {name}: {e}"))
        })?;
    }
    Ok(ctx)
}

/// Load the seccomp filter into the calling process, until it exits. Needs `no_new_privs`, which
/// Landlock sets on the chsr process before the editor is forked.
pub fn seccomp_lock() -> std::io::Result<()> {
    seccomp_filter()?
        .load()
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

    #[test]
    fn test_the_seccomp_filter_builds() {
        // every blocked syscall resolves and every architecture is added without error
        assert!(seccomp_filter().is_ok());
    }

    // a blocked syscall returns EPERM once the filter is loaded, an ordinary one still works; the
    // filter is permanent, so it is loaded in a forked child
    #[test]
    fn test_seccomp_denies_a_blocked_syscall_with_eperm() {
        // built before the fork, so the child, which must stay simple, only loads it
        let filter = seccomp_filter().expect("build the filter");
        // SAFETY: the test thread forks; the child only makes the calls below and _exit
        match unsafe { libc::fork() } {
            -1 => panic!("fork failed"),
            0 => {
                // seccomp without CAP_SYS_ADMIN needs no_new_privs
                // SAFETY: prctl with these arguments only sets a flag of the calling thread
                let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
                let code = if nnp != 0 {
                    70
                } else if filter.load().is_err() {
                    71
                } else {
                    // unshare(0) is a no-op when allowed, EPERM when the filter denies it
                    // SAFETY: unshare with no flags changes nothing of the process
                    let denied = unsafe { libc::unshare(0) } == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
                    // SAFETY: getpid never fails and changes nothing
                    let allowed = unsafe { libc::getpid() } > 0;
                    u8::from(!(denied && allowed)) * 72
                };
                // SAFETY: _exit does not run any destructor or atexit handler of the test process
                unsafe { libc::_exit(i32::from(code)) };
            }
            pid => {
                let mut status = 0;
                // SAFETY: waitpid writes the status through a pointer to a local integer
                unsafe { libc::waitpid(pid, &raw mut status, 0) };
                assert!(libc::WIFEXITED(status), "the child did not exit normally");
                assert_eq!(libc::WEXITSTATUS(status), 0, "the child reported a problem");
            }
        }
    }
}
