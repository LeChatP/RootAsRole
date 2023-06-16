use std::fs::File;
use std::io::Write;

fn write_version(f: &mut File) {
    let cargo_toml = include_str!("Cargo.toml");
    let package_version = cargo_toml.split("version = \"")
        .nth(1).unwrap()
        .split("\"").nth(0).unwrap();
    f.write(format!("pub const PACKAGE_VERSION:&'static str = \"{}\";\n", package_version).as_bytes()).unwrap();
}

fn write_dtd(f: &mut File) {
    let cargo_toml = include_str!("../resources/rootasrole.xml");
    let mut dtd = cargo_toml.split("?>").nth(1).unwrap()
        .split("]>").nth(0).unwrap().to_string();
    dtd.push_str("]>");
    f.write(format!("pub const DTD:&'static str = \"{}\n\";\n", dtd.replace("\"", "\\\"")).as_bytes()).unwrap();
}

fn main() {
    let dest_path = std::path::Path::new("src").join("version.rs");
    let mut f = File::create(&dest_path).unwrap();
    write_version(&mut f);
    write_dtd(&mut f);
    f.flush().unwrap();

}