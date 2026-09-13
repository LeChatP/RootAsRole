use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
};

enum Locale {
    EnUs,
    FrFr,
}

fn set_man_version(package_version: &str, file: &str, lang: &Locale) -> std::io::Result<()> {
    let man = File::open(std::path::Path::new(file)).expect("man page not found");
    let reader = BufReader::new(man);
    let lines = reader
        .lines()
        .map(|l| l.expect("Unable to read lines"))
        .collect::<Vec<String>>();
    let mut man = File::create(std::path::Path::new(file)).expect("man page not found");
    match lang {
        Locale::EnUs => {
            man.write_all(
                format!("% RootAsRole(8) RootAsRole {package_version} | System Manager's Manual\n")
                    .as_bytes(),
            )?;
        }
        Locale::FrFr => {
            man.write_all(
                format!(
                    "% RootAsRole(8) RootAsRole {package_version} | Manuel de l'administrateur système\n"
                )
                .as_bytes(),
            )?;
        }
    }
    for line in lines.iter().skip(1) {
        man.write_all(format!("{line}\n").as_bytes())?;
    }
    man.sync_all()?;
    Ok(())
}
const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");

    let is_install = std::env::var("CARGO_INSTALL_ROOT").is_ok();
    assert!(
        !is_install,
        "This crate is not meant to be installed with cargo install, please download .deb or .rpm and install it with your package manager.\nSee: https://lechatp.github.io/RootAsRole/faq.html"
    );
    if !std::path::Path::new("resources").exists() {
        return;
    }

    if let Err(err) = set_man_version(PACKAGE_VERSION, "resources/man/en_US.md", &Locale::EnUs) {
        eprintln!("cargo:warning={err}");
    }

    if let Err(err) = set_man_version(PACKAGE_VERSION, "resources/man/fr_FR.md", &Locale::FrFr) {
        eprintln!("cargo:warning={err}");
    }
}
