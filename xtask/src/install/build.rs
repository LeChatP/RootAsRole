use std::process::Command;


use super::BuildOptions;

fn build_binary(name: &str, options: &BuildOptions, additionnal_args: Vec<&str>) {
    let toolchain = format!("+{}", options.toolchain.to_string());
    let mut args = vec![&toolchain, "build", "--bin", name];
    if options.profile.is_release() {
        args.push("--release");
    }
    if options.clean_before {
        args.push("--clean");
    }
    args.extend(additionnal_args);
    Command::new("cargo")
        .args(args)
        .status()
        .expect(format!("failed to build {} binary", name).as_str());
}

pub fn build(options: &BuildOptions) -> Result<(), anyhow::Error> {
    
    build_binary("sr", options, vec!["--features", "rar-common/pcre2"]);
    build_binary("chsr", options, vec![]);

    Ok(())
}