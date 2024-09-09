use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::path::Path;

use capctl::{Cap, CapSet};
use clap::Command;
use nix::sys::stat::{fchmod, Mode};
use nix::unistd::{Gid, Uid};
use tracing::{debug, error, info};

use crate::install::Profile;
use crate::util::{BOLD, RED, RST};
use anyhow::{anyhow, Context};

use super::util::{cap_clear, cap_effective};
use super::{CHSR_DEST, SR_DEST};

fn copy_files(profile: &Profile) -> Result<(), anyhow::Error> {
    let binding = std::env::current_dir()?;
    let cwd = binding
        .to_str()
        .context("unable to get current dir as string")?;
    info!("Current working directory: {}", cwd);
    info!(
        "Copying files {}/target/{}/sr to {} and {}",
        cwd, profile, SR_DEST, CHSR_DEST
    );
    let s_sr = format!("{}/target/{}/sr", cwd, profile);
    let sr = Path::new(&s_sr);
    let s_chsr = format!("{}/target/{}/chsr", cwd, profile);
    let chsr = Path::new(&s_chsr);
    if !sr.exists() || !chsr.exists() {
        return Err(anyhow!("sr or chsr does not exist in the target directory.
        \nYou may need first to do `sudo cargo clean`.\n{}{}Please build the project first using `cargo xtask build`{}", BOLD, RED, RST));
    }
    // We can't use fs::copy directly because it will overwrite the destination file
    // and it is possible that the destination file is currently under execution.
    debug!("Copying sr to sr.tmp");
    fs::copy(sr, format!("{}.tmp", s_sr))?;
    debug!("Copying chsr to chsr.tmp");
    fs::copy(chsr, format!("{}.tmp", s_chsr))?;
    debug!("Renaming sr to /usr/bin/sr");
    fs::rename(sr, SR_DEST)?;
    debug!("Renaming chsr to /usr/bin/chsr");
    fs::rename(chsr, CHSR_DEST)?;
    debug!("Renaming sr.tmp to sr");
    fs::rename(format!("{}.tmp", s_sr), sr)?;
    debug!("Renaming chsr.tmp to chsr");
    fs::rename(format!("{}.tmp", s_chsr), chsr)?;

    Ok(())
}

fn chmod() -> Result<(), anyhow::Error> {
    let sr_file = File::open(SR_DEST)?;
    let chsr_file = File::open(CHSR_DEST)?;
    let mode = Mode::from_bits(0o555).expect("Invalid mode bits");
    fchmod(sr_file.as_raw_fd(), mode)?;
    fchmod(chsr_file.as_raw_fd(), mode)?;
    sr_file.sync_all()?;
    chsr_file.sync_all()?;
    Ok(())
}

fn chown() -> Result<(), anyhow::Error> {
    let uid_owner = Uid::from_raw(0);
    let gid_owner = Gid::from_raw(0);
    nix::unistd::chown(SR_DEST, Some(uid_owner), Some(gid_owner))?;
    nix::unistd::chown(CHSR_DEST, Some(uid_owner), Some(gid_owner))?;
    Ok(())
}

fn setfcap() -> Result<(), anyhow::Error> {
    let mut file_caps = capctl::caps::FileCaps::empty();
    file_caps.permitted = !CapSet::empty();
    file_caps.set_for_file(SR_DEST)?;
    file_caps.set_for_file(CHSR_DEST)?;
    Ok(())
}

pub fn install(profile: Profile, clean_after: bool, copy: bool) -> Result<(), anyhow::Error> {
    // test if current process has CAP_DAC_OVERRIDE,CAP_CHOWN capabilities
    let mut state = capctl::CapState::get_current()?;
    if !state.permitted.has(Cap::DAC_OVERRIDE)
        || !state.permitted.has(Cap::CHOWN)
        || !state.permitted.has(Cap::SETFCAP)
    {
        return Err(anyhow!(
            "You need CAP_DAC_OVERRIDE, CAP_CHOWN and CAP_CHOWN capabilities to install rootasrole.
            \nConsider using `sr cargo xtask install` or use sudo if sr is currently not installed."
        ));
    }
    if copy {
        //raise dac_override to copy files
        cap_effective(&mut state, Cap::DAC_OVERRIDE).context("Failed to raise DAC_OVERRIDE")?;

        // cp target/{release}/sr,chsr,capable /usr/bin
        copy_files(&profile).context("Failed to copy sr and chsr files")?;

        // drop dac_override
        cap_clear(&mut state).context("Failed to drop effective DAC_OVERRIDE")?;
    }

    cap_effective(&mut state, Cap::DAC_OVERRIDE).context("Failed to raise CHOWN")?;

    // set file mode to 555 for sr and chsr
    chmod().context("Failed to set file mode for sr and chsr")?;

    // raise chown and setfcap to set owner
    cap_effective(&mut state, Cap::CHOWN).context("Failed to raise CHOWN")?;

    // chown sr and chsr to root:root
    chown().context("Failed to chown sr and chsr")?;

    // drop chown, raise setfcap capabilities
    cap_effective(&mut state, Cap::SETFCAP).context("Failed to raise SETFCAP")?;

    // set file capabilities for sr only
    setfcap().context("Failed to set file capabilities on /usr/bin/sr")?;

    // drop all capabilities
    cap_clear(&mut state).context("Failed to drop effective capabilities")?;

    if clean_after {
        std::process::Command::new("cargo")
            .args(&["clean"])
            .status()
            .context("Failed to clean the project")?;
    }
    Ok(())
}
