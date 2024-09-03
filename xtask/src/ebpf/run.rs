use std::process::Command;

use clap::Parser;

use crate::install::BuildOptions;

#[derive(Debug, Parser)]
pub struct RunOptions {
    /// Build options
    #[clap(flatten)]
    pub build: BuildOptions,
    /// The command used to wrap capable, sr by default (sudo or doas are not recommended)
    #[clap(short, long, default_value = "sr")]
    pub runner: String,
    /// Arguments to pass to your application
    #[clap(name = "args", last = true)]
    pub run_args: Vec<String>,
}

/// Build and run the project
pub fn run(opts: &RunOptions) -> Result<(), anyhow::Error> {

    // profile we are building (release or debug)
    let bin_path = format!("target/{}/capable",opts.build.profile);

    // arguments to pass to the application
    let mut run_args: Vec<_> = opts.run_args.iter().map(String::as_str).collect();

    // configure args
    let mut args: Vec<_> = opts.runner.trim().split_terminator(' ').collect();
    args.push(bin_path.as_str());
    args.append(&mut run_args);

    // run the command
    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .status()
        .expect("failed to run the command");

    if !status.success() {
        anyhow::bail!("Failed to run `{}`", args.join(" "));
    }
    Ok(())
}
