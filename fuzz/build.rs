use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../src");
    println!("cargo:rerun-if-changed=../resources");
    println!("cargo:rerun-if-changed=../tests/fixtures");

    let fuzz_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let project_dir = fuzz_dir
        .parent()
        .expect("fuzz must be below the project root");
    let target_dir = project_dir.join("target");
    let out_dir = target_dir.join("fuzz_bins");
    fs::create_dir_all(&out_dir).expect("failed to create the fuzz binary directory");

    let targets = [
        ("command_match", "resources/rootasrole.json"),
        ("password_input", "tests/fixtures/perform_auth.json"),
        ("cli_args", "resources/rootasrole.json"),
        ("environment", "tests/fixtures/env_override.json"),
        ("setup_environment", "tests/fixtures/env_override.json"),
    ];

    for (fuzzer_name, cfg_path) in targets {
        let config_path = project_dir.join(cfg_path);
        assert!(
            config_path.is_file(),
            "missing fuzz configuration: {}",
            config_path.display()
        );
        let isolated_target = target_dir.join(format!("fuzz_cache_{fuzzer_name}"));

        let mut cmd = Command::new("cargo");
        cmd.current_dir(project_dir)
            .args([
                "+stable",
                "build",
                "--release",
                "--bin",
                "dosr",
                "--features",
                "finder",
            ])
            .env("CARGO_TARGET_DIR", &isolated_target)
            .env("RAR_CFG_PATH", &config_path)
            .env("RAR_CFG_DATA_PATH", &config_path)
            .env("RAR_CFG_TYPE", "json")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS");

        let status = cmd.status().expect("failed to launch the binary build");
        if !status.success() {
            panic!("building dosr for {fuzzer_name} failed");
        }

        let src = isolated_target.join("release/dosr");
        let dst = out_dir.join(format!("rootasrole_{fuzzer_name}"));

        fs::copy(&src, &dst).unwrap_or_else(|error| {
            panic!(
                "failed to copy {} to {}: {error}",
                src.display(),
                dst.display()
            )
        });
    }
}
