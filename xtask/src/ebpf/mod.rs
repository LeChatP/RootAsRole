use anyhow::Context;
use build::{build_ebpf, build};
use run::RunOptions;

use crate::install::BuildOptions;

pub mod build;
pub mod run;



pub fn build_all(opts: &BuildOptions) -> Result<(), anyhow::Error> {
    build_ebpf(&opts.ebpf_toolchain, &opts.profile).context("Error while building eBPF program")?;
    build(opts).context("Error while building userspace application")
}

pub fn run(opts: &RunOptions) -> Result<(), anyhow::Error> {
    build_all(&opts.build)?;
    run::run(opts)?;
    Ok(())
}