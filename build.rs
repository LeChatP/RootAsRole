use std::{
    error::Error,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::Path,
};

use toml::Table;

enum Locale {
    EnUs,
    FrFr,
}

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

fn set_man_version(package_version: &str, file: &str, lang: Locale) -> std::io::Result<()> {
    let man = File::open(std::path::Path::new(file)).expect("man page not found");
    let reader = BufReader::new(man);
    let lines = reader.lines().map(|l| l.unwrap()).collect::<Vec<String>>();
    let mut man = File::create(std::path::Path::new(file)).expect("man page not found");
    match lang {
        Locale::EnUs => {
            man.write_all(
                format!(
                    "% RootAsRole(8) RootAsRole {} | System Manager's Manual\n",
                    package_version
                )
                .as_bytes(),
            )?;
        }
        Locale::FrFr => {
            man.write_all(
                format!(
                    "% RootAsRole(8) RootAsRole {} | Manuel de l'administrateur système\n",
                    package_version
                )
                .as_bytes(),
            )?;
        }
    }
    for line in lines.iter().skip(1) {
        man.write_all(format!("{}\n", line).as_bytes())?;
    }
    man.sync_all()?;
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

    if let Err(err) = set_cargo_version(&package_version, "Cargo.toml") {
        eprintln!("cargo:warning={}", err);
    }

    if let Err(err) = set_man_version(&package_version, "resources/man/en_US.md", Locale::EnUs) {
        eprintln!("cargo:warning={}", err);
    }

    if let Err(err) = set_man_version(&package_version, "resources/man/fr_FR.md", Locale::FrFr) {
        eprintln!("cargo:warning={}", err);
    }
}
