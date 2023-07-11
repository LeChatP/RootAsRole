use std::error::Error;
use std::fs::File;
use std::io::Write;

fn write_version(f: &mut File) -> Result<(), Box<dyn Error>> {
    let cargo_toml = include_str!("Cargo.toml");
    let package_version = cargo_toml
        .split("version = \"")
        .nth(1)
        .ok_or(Box::<dyn Error>::from("Version not found"))?
        .split('"')
        .next()
        .ok_or(Box::<dyn Error>::from("Version not found"))?;
    f.write_all(
        format!(
            "pub const PACKAGE_VERSION: &'static str = \"{}\";\n",
            package_version
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn write_dtd(f: &mut File) -> Result<(), Box<dyn Error>> {
    let cargo_toml = include_str!("../resources/rootasrole.xml");
    let mut dtd = cargo_toml
        .split("?>")
        .nth(1)
        .ok_or(Box::<dyn Error>::from("DTD not found"))?
        .split("]>")
        .next()
        .ok_or(Box::<dyn Error>::from("DTD not found"))?
        .to_string();
    dtd.push_str("]>");
    f.write_all(
        format!(
            "pub const DTD: &'static str = \"{}\n\";\n",
            dtd.replace('"', "\\\"")
        )
        .as_bytes(),
    )
    .map_err(|e| e.into())
}

fn main() {
    let dest_path = std::path::Path::new("src").join("version.rs");
    let mut f = File::create(dest_path).unwrap();
    if let Err(err) = write_version(&mut f) {
        eprintln!("cargo:warning={}", err);
    }
    if let Err(err) = write_dtd(&mut f) {
        eprintln!("cargo:warning={}", err);
    }
    f.flush().unwrap();
}
