pub mod config_manager;
pub mod test_runner;

use std::error::Error;
use std::ffi::CString;
use std::io::Write;
use std::os::unix::process::parent_id;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, Once, OnceLock};
use std::{env, fs};

use nix::sys::wait::WaitStatus;
use nix::unistd::{fork, setgid, setgroups, setuid, unlink, User};

use crate::helpers::test_runner::TestRunner;

const TEMP_LIFETIME_BUILD_STATE: &'static str = "target/tmp/dosr_integration_test_build";
const RAR_CFG_PATH: &'static str = "target/rootasrole.json";
static CLEANUP_REGISTERED: Once = Once::new();

fn register_cleanup() {
    CLEANUP_REGISTERED.call_once(|| {
        // Register cleanup to happen at program exit
        let _ = std::panic::set_hook(Box::new(|_| {
            cleanup_temp_files();
        }));

        // Also register for normal exit
        extern "C" fn cleanup_handler() {
            cleanup_temp_files();
        }
        unsafe {
            libc::atexit(cleanup_handler);
        }
    });
}

fn cleanup_temp_files() {
    let temp_file = PathBuf::from(TEMP_LIFETIME_BUILD_STATE);
    if temp_file.exists() {
        if let Err(e) = unlink(&temp_file) {
            eprintln!(
                "Warning: Failed to clean up temp file {}: {}",
                temp_file.display(),
                e
            );
        }
    }
}

static GLOBAL_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn ensure_binary_built() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let pid = parent_id();

    let temp_file = PathBuf::from(TEMP_LIFETIME_BUILD_STATE);

    // Check if we need to build based on the temp file
    let needs_build = if temp_file.exists() {
        // Read the stored PID and compare
        match fs::read_to_string(&temp_file) {
            Ok(stored_pid) => stored_pid.trim() != pid.to_string(),
            Err(_) => true, // If we can't read, assume we need to build
        }
    } else {
        true // File doesn't exist, we need to build
    };

    if needs_build && option_env!("SKIP_BUILD").is_none() {
        print!("Building dosr .... ");

        match unsafe { fork() } {
            Ok(nix::unistd::ForkResult::Parent { child }) => {
                // Parent process: wait for the child to finish
                loop {
                    let wait_status = nix::sys::wait::waitpid(child, None)
                        .expect("Failed to wait for child process");
                    if let WaitStatus::Exited(_, code) = wait_status {
                        if code != 0 {
                            return Err("Child process failed to build dosr binary".into());
                        } else {
                            break;
                        }
                    }
                }
            }
            Ok(nix::unistd::ForkResult::Child) => {
                if let Err(e) = build_dosr_binary(pid, &temp_file) {
                    eprintln!("Error during build: {}", e);
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
            Err(e) => {
                return Err(format!("Fork failed: {}", e).into());
            }
        }
    } else {
        print!("Reusing binary ... ");
        std::io::stdout().flush().unwrap();
    }

    Ok("target/debug/dosr".into())
}

fn build_dosr_binary(pid: u32, temp_file: &PathBuf) -> Result<(), Box<dyn Error>> {
    let user = User::from_name(
        &std::env::var("RAR_USER")
            .or_else(|_| std::env::var("SUDO_USER"))
            .expect("RAR_USER not set"),
    )
    .unwrap_or(None)
    .ok_or("User not found")?;
    let user_name_cstr = CString::new(user.name.clone())
        .inspect_err(|e| eprintln!("Failed to create CString: {}", e))?;
    let groups = nix::unistd::getgrouplist(user_name_cstr.as_c_str(), user.gid)
        .unwrap_or_else(|_| vec![user.gid]);
    setgroups(&groups).inspect_err(|e| eprintln!("Failed to setgroups: {}", e))?;
    setgid(user.gid).inspect_err(|e| eprintln!("Failed to setegid: {}", e))?;
    setuid(user.uid).inspect_err(|e| eprintln!("Failed to seteuid: {}", e))?;
    env::set_var(
        "PATH",
        format!("{}:{}/bin", env::var("PATH")?, env!("CARGO_HOME")),
    );
    env::set_var("HOME", &user.dir);
    let cfg_path = PathBuf::from(RAR_CFG_PATH);
    let output = Command::new("cargo")
        .args(["build", "--bin", "dosr", "--features", "finder"])
        .env(
            "RAR_CFG_PATH",
            cfg_path.to_str().ok_or("Invalid RAR_CFG_PATH")?,
        )
        .env("RAR_AUTHENTICATION", "skip")
        .output()
        .inspect_err(|e| eprintln!("Failed to execute cargo build: {}", e))?;
    if !output.status.success() {
        std::io::stderr().write_all(&output.stderr).ok();
        return Err("Failed to compile dosr binary".into());
    }
    fs::write(&temp_file, pid.to_string())?;
    print!("compiled binary ... ");
    Ok(())
}

pub fn get_test_runner() -> Result<TestRunner, Box<dyn std::error::Error>> {
    let _lock = GLOBAL_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let binary_path = ensure_binary_built()?;

    register_cleanup();

    TestRunner::new(binary_path, PathBuf::from(RAR_CFG_PATH))
}
