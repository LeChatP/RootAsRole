use pcre2::bytes::RegexBuilder;
use serde_json::Value;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

use std::path::Path;
use std::process::Command;

fn write_version<'a>(f: &'a mut File, doc: &'a Value) -> Result<&'a str, Box<dyn Error>> {
    let package_version = doc
        .get("version")
        .ok_or("No version found")?
        .as_str()
        .unwrap();
    f.write_all(
        format!(
            "pub const PACKAGE_VERSION: &'static str = \"{}\";\n",
            package_version
        )
        .as_bytes(),
    )?;
    Ok(package_version)
}

fn set_cargo_version(package_version: &str, file: &str) -> Result<(), Box<dyn Error>> {
    let cargo_toml = File::open(std::path::Path::new(file)).expect("Cargo.toml not found");
    let reader = BufReader::new(cargo_toml);
    let lines = reader.lines().map(|l| l.unwrap()).collect::<Vec<String>>();
    let mut cargo_toml = File::create(std::path::Path::new(file)).expect("Cargo.toml not found");
    for line in lines {
        if line.starts_with("version") {
            writeln!(cargo_toml, "version = \"{}\"", package_version)?;
        } else {
            writeln!(cargo_toml, "{}", line)?;
        }
    }
    cargo_toml.sync_all()?;
    Ok(())
}

fn set_pkgbuild_version(package_version: &str, file: &str) -> Result<(), Box<dyn Error>> {
    let pkgbuild = File::open(std::path::Path::new(file)).expect("PKGBUILD not found");
    let reader = BufReader::new(pkgbuild);
    let lines = reader.lines().map(|l| l.unwrap()).collect::<Vec<String>>();
    let mut pkgbuild = File::create(std::path::Path::new(file)).expect("PKGBUILD not found");
    for line in lines {
        if line.starts_with("pkgver") {
            writeln!(pkgbuild, "pkgver={}", package_version)?;
        } else {
            writeln!(pkgbuild, "{}", line)?;
        }
    }
    pkgbuild.sync_all()?;
    Ok(())
}

fn write_doc(f: &mut File) -> Result<(), Box<dyn Error>> {
    let docresp = reqwest::blocking::get(
        "https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man7/capabilities.7",
    )
    .expect("request failed");
    let haystack = docresp.text()?;

    //write to new temporary file
    let temp = std::path::Path::new("temp.7");
    let mut tempf = File::create(temp)?;
    tempf.write_all(haystack.as_bytes())?;
    tempf.flush()?;
    //now execute man command to convert to ascii
    let res = String::from_utf8(
        Command::new("/usr/bin/man")
            .args(["--nh", "--nj", "-al", "-P", "/usr/bin/cat", "temp.7"])
            .output()?
            .stdout,
    )?;
    //delete temp file
    std::fs::remove_file(temp)?;
    //now parse the output
    let mut re = RegexBuilder::new();
    re.multi_line(true);
    let re = re.build(r"^       (CAP_[A-Z_]+)\K((?!^       CAP_[A-Z_]+|^   Past).|\R)+")?;
    let spacere = regex::Regex::new(r" +")?;
    f.write_all(
        r#"use capctl::Cap;
"#
        .as_bytes(),
    )?;
    f.write_all(
        r#"#[rustfmt::skip]
#[allow(clippy::all)] 
pub fn get_capability_description(cap : &Cap) -> &'static str {
    match *cap {
"#
        .as_bytes(),
    )?;
    let mut caplist = Vec::new();
    for cap in re.captures_iter(res.as_bytes()) {
        let cap = cap?;
        let name = std::str::from_utf8(cap.get(1).unwrap().as_bytes())?;
        if caplist.contains(&name) {
            continue;
        }
        caplist.push(name);
        let mut desc = std::string::String::from_utf8(cap.get(0).unwrap().as_bytes().to_vec())?;
        desc = spacere.replace_all(&desc, " ").to_string();
        let desc = desc.trim().to_string();
        f.write_all(
            format!(
                "        Cap::{} => r#{:#?}#,\n",
                name.replace("CAP_", ""),
                desc.replace('\n', "")
            )
            .as_bytes(),
        )?;
    }
    f.write_all(
        r#"       _ => "Unknown capability",
    }
}"#
        .as_bytes(),
    )?;
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
    println!("cargo:rerun-if-changed=resources/rootasrole.json");
    println!("cargo:rerun-if-changed=build.rs");

    let json: Value = include_str!("resources/rootasrole.json")
        .parse()
        .expect("Failed to parse rootasrole.json");
    let dest_path = std::path::Path::new("src").join("version.rs");
    let mut f = File::create(dest_path).unwrap();
    f.write_all(b"// This file is generated by build.rs\n")
        .unwrap();
    f.write_all(b"// Do not edit this file directly\n").unwrap();
    f.write_all(b"// Instead edit build.rs and run cargo build\n")
        .unwrap();
    match write_version(&mut f, &json) {
        Ok(package_version) => {
            if let Err(err) = set_cargo_version(package_version, "Cargo.toml") {
                eprintln!("cargo:warning={}", err);
            }
            //if folder capable/ exists
            if Path::new("capable/capable").is_dir() {
                if let Err(err) = set_cargo_version(package_version, "capable/capable/Cargo.toml") {
                    eprintln!("cargo:warning={}", err);
                }
                if let Err(err) = set_cargo_version(package_version, "capable/capable-ebpf/Cargo.toml") {
                    eprintln!("cargo:warning={}", err);
                }
                if let Err(err) = set_cargo_version(package_version, "capable/capable-common/Cargo.toml") {
                    eprintln!("cargo:warning={}", err);
                }
            }
            if let Err(err) = set_cargo_version(package_version, "xtask/Cargo.toml") {
                eprintln!("cargo:warning={}", err);
            }
            if let Err(err) = set_readme_version(package_version, "README.md") {
                eprintln!("cargo:warning={}", err);
            }
            if let Err(err) = set_pkgbuild_version(package_version, "PKGBUILD") {
                eprintln!("cargo:warning={}", err);
            }
        }
        Err(err) => {
            eprintln!("cargo:warning={}", err);
        }
    }

    // let xml = include_str!("resources/rootasrole.xml");
    // if let Err(err) = write_dtd(&mut f, xml) {
    //     eprintln!("cargo:warning={}", err);
    // }

    f.flush().unwrap();

    
}
