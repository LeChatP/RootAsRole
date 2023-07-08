use std::{error::Error, fs::File, io::Read};

use sxd_document::{
    dom::{ChildOfElement, ChildOfRoot, Document, Element},
    parser, Package,
};

use self::structs::Groups;

pub mod load;
pub mod save;
pub mod structs;

pub const FILENAME: &str = "/etc/security/rootasrole.xml";

pub(super) fn read_file(file_path: &str, contents: &mut String) -> Result<(), Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    file.read_to_string(contents)?;
    Ok(())
}

pub(super) fn read_xml_file(file_path: &str) -> Result<Package, Box<dyn Error>> {
    let mut contents = String::new();
    read_file(file_path, &mut contents)?;
    Ok(parser::parse(&contents)?)
}

pub(super) fn foreach_element<F>(element: Element, mut f: F) -> Result<(), Box<dyn Error>>
where
    F: FnMut(ChildOfElement) -> Result<(), Box<dyn Error>>,
{
    for child in element.children() {
        if child.element().is_some() {
            f(child)?;
        }
    }
    Ok(())
}

pub fn do_in_main_element<F>(doc: Document, name: &str, mut f: F) -> Result<(), Box<dyn Error>>
where
    F: FnMut(ChildOfRoot) -> Result<(), Box<dyn Error>>,
{
    for child in doc.root().children() {
        if let Some(element) = child.element() {
            if element.name().local_part() == name {
                f(child)?;
            }
        }
    }
    Ok(())
}

pub fn get_groups(node: Element) -> Groups {
    node.attribute("names")
        .expect("Unable to retrieve group names")
        .value()
        .split(',')
        .map(|s| s.to_string())
        .collect()
}
