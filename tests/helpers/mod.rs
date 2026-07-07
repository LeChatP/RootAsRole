pub mod test_runner;

use std::error::Error;
use std::ffi::CString;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::os::unix::process::parent_id;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::{env, fs};

use capctl::Cap;
use nix::unistd::User;
use nix::unistd::getuid;
use nix::unistd::setgid;
use nix::unistd::setgroups;
use nix::unistd::setuid;
use rar_common::util::StorageMethod;

const TEMP_LIFETIME_BUILD_STATE: &str = "target/tmp/dosr_integration_test_build";
const RAR_CFG_PATH: &str = "target/rootasrole.json";
const RAR_CFG_DATA_PATH: &str = "target/rootasrole.json";

pub struct FileLock {
    file: File,
}

impl FileLock {
    pub fn new<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        // Open or create the lock file without truncating it
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        let fd = file.as_raw_fd();

        let result = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let fd = self.file.as_raw_fd();
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
    }
}

fn ensure_binary_built(
    rar_cfg_path: &str,
    rar_cfg_data_path: &str,
    rar_cfg_type: StorageMethod,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let pid = parent_id();

    let temp_file = PathBuf::from(TEMP_LIFETIME_BUILD_STATE);

    // Check if we need to build based on the temp file
    let needs_build = if temp_file.exists() {
        // Read the stored PID and compare
        fs::read_to_string(&temp_file)
            .map_or(true, |stored_pid| stored_pid.trim() != pid.to_string())
    } else {
        true // File doesn't exist, we need to build
    };

    if needs_build && option_env!("SKIP_BUILD").is_none() {
        print!("Building dosr .... ");
        if let Err(e) = build_dosr_binary(
            pid,
            &temp_file,
            rar_cfg_path,
            rar_cfg_data_path,
            rar_cfg_type,
        ) {
            return Err(format!("Build failed: {e}").into());
        }
    } else {
        print!("Reusing binary ... ");
        std::io::stdout().flush().expect("Failed to flush stdout");
    }

    Ok("target/debug/dosr".into())
}

fn build_dosr_binary(
    pid: u32,
    temp_file: &PathBuf,
    rar_cfg_path: &str,
    rar_cfg_data_path: &str,
    rar_cfg_type: StorageMethod,
) -> Result<(), Box<dyn Error>> {
    let user: User = std::env::var("RAR_USER")
        .ok()
        .and_then(|s| User::from_name(&s).ok().flatten())
        .or_else(|| {
            std::env::var("SUDO_USER")
                .ok()
                .and_then(|s| User::from_name(&s).ok().flatten())
        })
        .unwrap_or_else(|| {
            nix::unistd::User::from_uid(getuid())
                .expect("Failed to get current user")
                .expect("Current user not found")
        });

    let user_name_cstr = CString::new(user.name.clone())
        .inspect_err(|e| eprintln!("Failed to create CString: {e}"))?;
    let groups = nix::unistd::getgrouplist(user_name_cstr.as_c_str(), user.gid)
        .unwrap_or_else(|_| vec![user.gid]);
    let uid = user.uid;
    let gid = user.gid;
    let home_dir = user.dir;
    let mut command = Command::new("cargo");
    command
        .args(["build", "--bin", "dosr", "--features", "finder"])
        .env("RAR_CFG_PATH", rar_cfg_path)
        .env("RAR_CFG_DATA_PATH", rar_cfg_data_path)
        .env("RAR_CFG_TYPE", rar_cfg_type.to_string())
        .env("RAR_AUTHENTICATION", "skip")
        .env(
            "PATH",
            format!("{}:{}/bin", env::var("PATH")?, env!("CARGO_HOME")),
        )
        .env("HOME", &home_dir);
    unsafe {
        command.pre_exec(move || {
            let map_err = |e: nix::Error| std::io::Error::from_raw_os_error(e as i32);
            if let Ok(mut current) = capctl::caps::CapState::get_current()
                && current.permitted.has(Cap::SETUID)
                && current.permitted.has(Cap::SETGID)
            {
                current.effective.add(Cap::SETUID);
                current.effective.add(Cap::SETGID);
                setgroups(&groups).map_err(map_err)?;
                setgid(gid).map_err(map_err)?;
                setuid(uid).map_err(map_err)?;
            }

            Ok(())
        });
    }
    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .inspect_err(|e| eprintln!("Failed to execute cargo build: {e}"));
    let output = output?;
    if !output.status.success() {
        std::io::stderr().write_all(&output.stderr).ok();
        return Err("Failed to compile dosr binary".into());
    }
    fs::write(temp_file, pid.to_string())?;
    print!("compiled binary ... ");
    Ok(())
}
