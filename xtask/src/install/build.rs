use std::process::Command;


use super::BuildOptions;

pub fn build(options: &BuildOptions) -> Result<(), anyhow::Error> {
    let toolchain = format!("+{}", options.toolchain.to_string());
    let mut args = vec![toolchain.as_str(), "build", "--bin", "sr", "--bin", "chsr"];
    if options.profile.is_release() {
        args.push("--release");
    }
    Command::new("cargo")
        .args(args)
        .status()
        .expect("failed to install rootasrole");

    Ok(())
}