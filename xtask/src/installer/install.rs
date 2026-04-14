use std::env::{self, current_exe, set_current_dir};
use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use capctl::{Cap, CapSet};
use log::{debug, error, info, warn};
use nix::NixPath;
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{Gid, Uid};
use strum::EnumIs;

use crate::installer::Profile;
use crate::util::{BOLD, RED, RST, change_dir_to_project_root, detect_priv_bin, is_run0_command, is_su_command, run_checked};
use anyhow::{Context, anyhow};

use super::{CHSR_DEST, RAR_BIN_PATH, SR_DEST};
use crate::util::cap_clear;


fn shell_quote(arg: &str) -> String {
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "@%_+=:,./-".contains(c))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

fn copy_executables(profile: Profile) -> Result<(), anyhow::Error> {
    let chsr_dest = Path::new(RAR_BIN_PATH).join(CHSR_DEST);
    let sr_dest = Path::new(RAR_BIN_PATH).join(SR_DEST);
    let binding = std::env::current_dir()?;
    let cwd = binding
        .to_str()
        .context("unable to get current dir as string")?;
    info!("Current working directory: {cwd}");
    info!(
        "Copying files {}/target/{}/dosr to {} and {}",
        cwd,
        profile,
        sr_dest
            .to_str()
            .expect("Failed to convert sr_dest to string"),
        chsr_dest
            .to_str()
            .expect("Failed to convert chsr_dest to string")
    );
    let s_sr = format!("{cwd}/target/{profile}/dosr");
    let sr = Path::new(&s_sr);
    let s_chsr = format!("{cwd}/target/{profile}/chsr");
    let chsr = Path::new(&s_chsr);
    if !sr.exists() || !chsr.exists() {
        return Err(anyhow!("sr or chsr does not exist in the target directory.
        \nYou may need first to do `sudo cargo clean`.\n{BOLD}{RED}Please build the project first using `cargo xtask build`{RST}"));
    }
    // We can't use fs::copy directly because it will overwrite the destination file
    // and it is possible that the destination file is currently under execution.
    debug!("Copying sr to sr.tmp");
    fs::copy(sr, format!("{s_sr}.tmp"))?;
    debug!("Copying chsr to chsr.tmp");
    fs::copy(chsr, format!("{s_chsr}.tmp"))?;
    debug!("Moving sr to /usr/bin/dosr");
    match fs::rename(sr, &sr_dest) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(18) => {
            // EXDEV (errno 18): Invalid cross-device link
            // Fall back to copy + remove for cross-filesystem operations
            debug!("Cross-device link detected, using copy+remove instead");
            fs::copy(sr, &sr_dest)?;
            fs::remove_file(sr)?;
        }
        Err(e) => return Err(e.into()),
    }
    debug!("Moving chsr to /usr/bin/chsr");
    match fs::rename(chsr, &chsr_dest) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(18) => {
            // EXDEV (errno 18): Invalid cross-device link
            // Fall back to copy + remove for cross-filesystem operations
            debug!("Cross-device link detected, using copy+remove instead");
            fs::copy(chsr, &chsr_dest)?;
            fs::remove_file(chsr)?;
        }
        Err(e) => return Err(e.into()),
    }
    debug!("Renaming sr.tmp to sr");
    fs::rename(format!("{s_sr}.tmp"), sr)?;
    debug!("Renaming chsr.tmp to chsr");
    fs::rename(format!("{s_chsr}.tmp"), chsr)?;

    Ok(())
}

fn copy_docs() -> Result<(), anyhow::Error> {
    fn exit_directory() -> io::Result<()> {
        set_current_dir("../..")
    }
    fn enter_directory() -> io::Result<()> {
        set_current_dir("target/man/")
    }
    enter_directory()?;

    for file in glob::glob("**/*")
        .map_err(|_| exit_directory())
        .expect("Failed to read glob pattern")
    {
        let file = file.inspect_err(|_| {
            exit_directory().expect("Failed to exit directory");
        })?;
        if file.is_dir() {
            continue;
        }

        let file_name = &file
            .file_name()
            .ok_or_else(|| {
                exit_directory().expect("Failed to exit directory");
                anyhow!("Failed to get the file name")
            })?
            .to_str()
            .ok_or_else(|| {
                exit_directory().expect("Failed to exit directory");
                anyhow!("Failed to get the file name")
            })?;
        let lang = file.parent();
        if lang.is_some_and(|p| !NixPath::is_empty(p)) {
            let lang = lang.expect("Failed to get Lang path");
            //println!("lang: {:?}", lang);
            let lang = lang.file_name().ok_or_else(|| {
                exit_directory().expect("Failed to exit directory");
                anyhow!("Failed to get the language")
            })?;
            let lang = lang.to_str().ok_or_else(|| {
                exit_directory().expect("Failed to exit directory");
                anyhow!("Failed to get the language")
            })?;
            let dest = format!("/usr/share/man/{lang}/man8/{file_name}");
            debug!("Copying file: {} to {dest}", file.display());
            fs::copy(&file, &dest)
                .inspect_err(|_| {
                    exit_directory().expect("Failed to exit directory");
                })
                .context(format!("Unable to copy {} to {dest}", file.display()))?;
        } else {
            let dest = format!("/usr/share/man/man8/{file_name}");
            debug!("Copying file: {} to {dest}", file.display());
            fs::copy(&file, &dest)
                .inspect_err(|_| {
                    exit_directory().expect("Failed to exit directory");
                })
                .context(format!("Unable to copy {} to {dest}", file.display()))?;
        }
    }
    exit_directory()?;
    Ok(())
}

fn chmod() -> Result<(), anyhow::Error> {
    let chsr_dest = Path::new(RAR_BIN_PATH).join(CHSR_DEST);
    let sr_dest = Path::new(RAR_BIN_PATH).join(SR_DEST);
    let sr_file = File::open(sr_dest)?;
    let chsr_file = File::open(chsr_dest)?;
    let mode = Mode::from_bits(0o555).expect("Invalid mode bits");
    fchmod(sr_file.as_raw_fd(), mode)?;
    fchmod(chsr_file.as_raw_fd(), mode)?;
    sr_file.sync_all()?;
    chsr_file.sync_all()?;
    Ok(())
}

fn chown() -> Result<(), anyhow::Error> {
    let chsr_dest = Path::new(RAR_BIN_PATH).join(CHSR_DEST);
    let sr_dest = Path::new(RAR_BIN_PATH).join(SR_DEST);
    let uid_owner = Uid::from_raw(0);
    let gid_owner = Gid::from_raw(0);
    nix::unistd::chown(&sr_dest, Some(uid_owner), Some(gid_owner))?;
    nix::unistd::chown(&chsr_dest, Some(uid_owner), Some(gid_owner))?;
    Ok(())
}

fn setfcap() -> Result<(), anyhow::Error> {
    let sr_dest = Path::new(RAR_BIN_PATH).join(SR_DEST);
    let mut file_caps = capctl::caps::FileCaps::empty();
    file_caps.permitted = !CapSet::empty();
    file_caps.set_for_file(sr_dest)?;
    Ok(())
}

#[derive(Debug, EnumIs)]
pub enum Elevated {
    Yes,
    No,
}

fn cap_effective(state: &mut capctl::CapState, cap: Cap) -> Result<(), anyhow::Error> {
    state.effective.clear();
    state.effective.add(cap);
    state.set_current()?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn install(
    priv_exe: Option<&Path>,
    profile: Profile,
    clean_after: bool,
    copy: bool,
) -> Result<Elevated, anyhow::Error> {
    // test if current process has CAP_DAC_OVERRIDE,CAP_CHOWN capabilities
    let mut state = capctl::CapState::get_current()?;
    if !state.permitted.has(Cap::DAC_OVERRIDE)
        || !state.permitted.has(Cap::CHOWN)
        || !state.permitted.has(Cap::SETFCAP)
    {
        let bounding = capctl::bounding::probe();
        // get parent process
        if !bounding.has(Cap::DAC_OVERRIDE)
            || !bounding.has(Cap::CHOWN)
            || !bounding.has(Cap::SETFCAP)
        {
            return Err(anyhow!(
                "The bounding set misses DAC_OVERRIDE, CHOWN or SETFCAP capabilities"
            ));
        } else if env::var("ROOTASROLE_INSTALLER_NESTED").is_ok_and(|v| v == "1") {
            unsafe { env::remove_var("ROOTASROLE_INSTALLER_NESTED") };
            return Err(anyhow!(
                "Unable to elevate required capabilities, is LSM blocking installation?"
            ));
        }

        let priv_bin = detect_priv_bin();
        let priv_exe = priv_exe
            .or(priv_bin.as_deref())
            .context("Privileged binary is required")
            .map_err(|_| {
                anyhow::Error::msg(format!(
                    "Please run {} as an administrator.",
                    current_exe()
                        .unwrap_or_else(|_| PathBuf::from_str("the command").unwrap())
                        .to_str()
                        .expect("Failed to convert current exe path to string")
                ))
            })?;
        change_dir_to_project_root()?; // change to the root of the project before elevating privileges
        unsafe { env::set_var("ROOTASROLE_INSTALLER_NESTED", "1") };
        log::warn!("Elevating privileges...");
        let current_exe_path = current_exe()?;
        let current_exe_str = current_exe_path
            .to_str()
            .context("Failed to get current exe path")?
            .to_string();
        let mut command = std::process::Command::new(priv_exe);
        if is_su_command(priv_exe) {
            let mut shell_cmd_args = vec![
                shell_quote(&current_exe_str),
                "install".to_string(),
                "--nested-install".to_string(),
            ];
            if profile.is_debug() {
                shell_cmd_args.push("--debug".to_string());
            }
            let shell_cmd = shell_cmd_args.join(" ");
            command.arg("-c").arg(shell_cmd);
        } else if is_run0_command(priv_exe) {
            let mut shell_cmd_args = vec![
                shell_quote(&current_exe_str),
                "install".to_string(),
                "--nested-install".to_string(),
            ];
            if profile.is_debug() {
                shell_cmd_args.push("--debug".to_string());
            }
            let shell_cmd = shell_cmd_args.join(" ");
            command.arg("--pipe").arg("sh").arg("-c").arg(shell_cmd);
        } else {
            command
                .arg(&current_exe_str)
                .arg("install")
                .arg("--nested-install");
            if profile.is_debug() {
                command.arg("--debug");
            }
        }
        run_checked(
            &mut command,
            "run privileged installer",
        )
        .context("Failed to run privileged binary")
        .map_err(|e| {
            error!("{e}");
            anyhow::Error::msg(format!(
                "Failed to run privileged binary. Please run {} as an administrator.",
                current_exe()
                    .unwrap_or_else(|_| PathBuf::from_str("the command")
                        .expect("Failed to get current exe path"))
                    .to_str()
                    .expect("Failed to convert current exe path to string")
            ))
        })?;
        return Ok(Elevated::Yes);
    }
    unsafe { env::remove_var("ROOTASROLE_INSTALLER_NESTED") };
    if copy {
        //raise dac_override to copy files
        cap_effective(&mut state, Cap::DAC_OVERRIDE).context("Failed to raise DAC_OVERRIDE")?;

        // cp target/{release}/dosr,chsr,capable /usr/bin
        copy_executables(profile).context("Failed to copy sr and chsr files")?;

        if let Err(e) = copy_docs() {
            warn!("Unable to copy docs : {e}");
        }

        // drop dac_override
        cap_clear(&mut state).context("Failed to drop effective DAC_OVERRIDE")?;
    }

    cap_effective(&mut state, Cap::FOWNER).context("Failed to raise CHOWN")?;

    // set file mode to 555 for sr and chsr
    chmod().context("Failed to set file mode for sr and chsr")?;

    // raise chown and setfcap to set owner
    cap_effective(&mut state, Cap::CHOWN).context("Failed to raise CHOWN")?;

    // chown sr and chsr to root:root
    chown().context("Failed to chown sr and chsr")?;

    // drop chown, raise setfcap capabilities
    cap_effective(&mut state, Cap::SETFCAP).context("Failed to raise SETFCAP")?;

    // set file capabilities for sr only
    setfcap().context("Failed to set file capabilities on /usr/bin/dosr")?;

    // drop all capabilities
    cap_clear(&mut state).context("Failed to drop effective capabilities")?;

    if clean_after {
        run_checked(
            std::process::Command::new("cargo").args(["clean"]),
            "clean project",
        )
        .context("Failed to clean the project")?;
    }
    Ok(Elevated::No)
}
