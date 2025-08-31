use std::{
    error::Error,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::Path,
};

use chrono::Locale;
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
            let end = line
                .split(')')
                .skip(1)
                .fold(String::new(), |acc, x| acc + ")" + x);
            s.push_str(&format!("(V{}{}", package_version, end));
            writeln!(readme, "{}", s)?;
        } else {
            writeln!(readme, "{}", line)?;
        }
    }
    readme.sync_all()?;
    Ok(())
}

fn some_kind_of_uppercase_first_letter(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

fn set_man_version(package_version: &str, file: &str, lang:Locale) -> std::io::Result<()> {
    let man = File::open(std::path::Path::new(file)).expect("man page not found");
    let reader = BufReader::new(man);
    let lines = reader.lines().map(|l| l.unwrap()).collect::<Vec<String>>();
    let mut man = File::create(std::path::Path::new(file)).expect("man page not found");
    match lang {
        Locale::en_US => {
            man.write_all(format!("% RootAsRole(8) RootAsRole {} | System Manager's Manual\n", package_version).as_bytes())?;
        },
        Locale::fr_FR => {
            man.write_all(format!("% RootAsRole(8) RootAsRole {} | Manuel de l'administrateur système\n", package_version).as_bytes())?;
        },
        _ => unreachable!(),
    }
    man.write_all(b"% Eddie Billoir <lechatp@outlook.fr>\n")?;
    man.write_all(format!("% {}\n", some_kind_of_uppercase_first_letter(&chrono::Utc::now().format_localized("%B %Y", lang).to_string())).as_bytes())?;
    for line in lines.iter().skip(3) {
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

    if let Err(err) = set_readme_version(&package_version, "README.md") {
        eprintln!("cargo:warning={}", err);
    }

    if let Err(err) = set_man_version(&package_version, "resources/man/en_US.md", Locale::en_US) {
        eprintln!("cargo:warning={}", err);
    }

    if let Err(err) = set_man_version(&package_version, "resources/man/fr_FR.md", Locale::fr_FR) {
        eprintln!("cargo:warning={}", err);
    }
}
