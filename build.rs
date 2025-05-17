use std::{
    error::Error,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::Path,
};

use toml::Table;

fn package_version<P: AsRef<Path>>(path: P) -> Result<String, Box<dyn Error>> {
    let cargo_toml = fs::read_to_string(path)?;
    let value: Table = cargo_toml.parse::<Table>()?;
    Ok(value["package"]["version"]
        .as_str()
        .map(|s| s.to_string())
        .expect("Failed to get package version"))
}

fn set_cargo_version(package_version: &str, file: &str) -> Result<(), Box<dyn Error>> {
    let cargo_toml = File::open(std::path::Path::new(file)).expect("Cargo.toml not found");
    let reader = BufReader::new(cargo_toml);
    let lines = reader.lines().map(|l| l.unwrap()).collect::<Vec<String>>();
    let mut cargo_toml = File::create(std::path::Path::new(file)).expect("Cargo.toml not found");
    for line in lines {
        if line.starts_with("version") {
            writeln!(cargo_toml, "version = \"{}\"", package_version)?;
        } else if line.starts_with("rar-common =") {
            writeln!(cargo_toml, "rar-common = {{ path = \"rar-common\", version = \"{}\", package = \"rootasrole-core\" }}", package_version)?;
        } else {
            writeln!(cargo_toml, "{}", line)?;
        }
    }
    cargo_toml.sync_all()?;
    Ok(())
}

fn set_readme_version(package_version: &str, file: &str) -> Result<(), Box<dyn Error>> {
    let readme = File::open(std::path::Path::new(file)).expect("README.md not found");
    let reader = BufReader::new(readme);
    let lines = reader.lines().map(|l| l.unwrap()).collect::<Vec<String>>();
    let mut readme = File::create(std::path::Path::new(file)).expect("README.md not found");
    for line in lines {
        if line.starts_with("# RootAsRole (V") {
            let mut s = line.split("(V").next().unwrap().to_string();
            let end = line.split(')').nth(1).unwrap();
            s.push_str(&format!("(V{}){}", package_version, end));
            writeln!(readme, "{}", s)?;
        } else {
            writeln!(readme, "{}", line)?;
        }
    }
    readme.sync_all()?;
    Ok(())
}

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");

    let is_install = std::env::var("CARGO_INSTALL_ROOT").is_ok();
    if is_install {
        panic!("This crate is not meant to be installed with cargo install, please download .deb or .rpm and install it with your package manager.\nSee: https://lechatp.github.io/RootAsRole/faq.html");
    }
    if !std::path::Path::new("rar-common").exists() {
        return;
    }
    let package_version = package_version("Cargo.toml").expect("Failed to get package version");

    if let Err(err) = set_cargo_version(&package_version, "rar-common/Cargo.toml") {
        eprintln!("cargo:warning={}", err);
    }

    if let Err(err) = set_cargo_version(&package_version, "xtask/Cargo.toml") {
        eprintln!("cargo:warning={}", err);
    }

    if let Err(err) = set_readme_version(&package_version, "README.md") {
        eprintln!("cargo:warning={}", err);
    }
}
