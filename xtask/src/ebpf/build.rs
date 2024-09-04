use std::{path::PathBuf, process::Command};

use clap::ValueEnum;
use strum::{Display, EnumString};

use crate::install::{BuildOptions, Profile};

#[derive(Debug, Copy, Clone, Display, EnumString, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum EbpfArchitecture {
    BpfelUnknownNone,
    BpfebUnknownNone,
}

impl Default for EbpfArchitecture {
    fn default() -> Self {
        EbpfArchitecture::BpfelUnknownNone
    }
}

// execute aya-tool generate task_struct
fn generate_task_struct() -> Result<(), anyhow::Error> {
    let output = Command::new("aya-tool")
        .args(&["generate", "task_struct"])
        .output()?;
    let string = String::from_utf8(output.stdout)?.replace("aya_bpf::", "aya_ebpf::");
    // write to file
    std::fs::write("capable-ebpf/src/vmlinux.rs", string)?;
    Ok(())
}

/// Build the user-space binary
pub fn build(opts: &BuildOptions) -> Result<(), anyhow::Error> {
    let toolchain = format!("+{}", opts.toolchain.to_string());
    let mut args = vec![ toolchain.as_str(), "build", "--package", "capable"];
    if opts.profile.is_release() {
        args.push("--release")
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}



pub fn build_ebpf(ebpf_target: &EbpfArchitecture, profile: &Profile) -> Result<(), anyhow::Error> {

    generate_task_struct()?;
    let dir = PathBuf::from("capable-ebpf");
    let target = format!("--target={}", ebpf_target);
    let mut args = vec![
        "build",
        "--verbose",
        target.as_str(),
        "-Z",
        "build-std=core",
    ];
    if profile.is_release() {
        args.push("--release")
    }

    // Command::new creates a child process which inherits all env variables. This means env
    // vars set by the cargo xtask command are also inherited. RUSTUP_TOOLCHAIN is removed
    // so the rust-toolchain.toml file in the -ebpf folder is honored.

    let status = Command::new("cargo")
        .current_dir(dir)
        .env_remove("RUSTUP_TOOLCHAIN")
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}


