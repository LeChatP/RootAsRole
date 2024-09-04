use std::fs::{self, File};
use std::os::fd::AsRawFd;

use capctl::{Cap, CapSet};
use nix::sys::stat::{fchmod, Mode};
use nix::unistd::{Gid, Uid};

use crate::ebpf::build::EbpfArchitecture;
use crate::install::Profile;
use anyhow::Context;

use super::util::{cap_clear, cap_effective};
use super::{InstallOptions, CAPABLE_DEST, CHSR_DEST, SR_DEST};

fn copy_files(profile: &Profile, ebpf: Option<EbpfArchitecture>) -> Result<(), anyhow::Error> {
    let binding = std::env::current_dir()?;
    let cwd = binding.to_str().context("unable to get current dir as string")?;
    println!("Current working directory: {}", cwd);
    println!("Copying files {}/target/{}/sr to {} and {}", cwd, profile, SR_DEST, CHSR_DEST);
    fs::rename(format!("{}/target/{}/sr", cwd, profile), SR_DEST)?;
    fs::rename(format!("{}/target/{}/chsr", cwd, profile), CHSR_DEST)?;
    if let Some(ebpf) = ebpf {
        println!("Copying file {}/target/{}/capable to {}", cwd, ebpf, CAPABLE_DEST);
        fs::rename(format!("{}/target/{}/capable", cwd, ebpf), CAPABLE_DEST)?;
    }

    chmod()?;

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

pub fn install(options: &InstallOptions) -> Result<(), anyhow::Error> {
    // test if current process has CAP_DAC_OVERRIDE,CAP_CHOWN capabilities
    let mut state = capctl::CapState::get_current()?;
    if state.permitted.has(Cap::DAC_OVERRIDE)
        && state.permitted.has(Cap::CHOWN)
        && state.permitted.has(Cap::SETFCAP)
    {
        //raise dac_override to copy files
        cap_effective(&mut state, Cap::DAC_OVERRIDE).context("Failed to raise DAC_OVERRIDE")?;

        // cp target/{release}/sr,chsr,capable /usr/bin
        copy_files(
            &options.build.profile,
            options.build.ebpf,
        )
        .context("Failed to copy sr and chsr files")?;

        // drop dac_override
        cap_clear(&mut state).context("Failed to drop effective DAC_OVERRIDE")?;

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

        if options.clean_after {
            fs::remove_dir_all(format!("{:?}/target", std::env::current_dir()?))
                .context("Failed to remove target directory")?;
        }
    } else {
        eprintln!(
            "You need to have CAP_DAC_OVERRIDE and CAP_CHOWN capabilities to install rootasrole"
        );
        std::process::exit(1);
    }
    Ok(())
}
