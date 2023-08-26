pub mod load;
pub mod options;
pub mod save;
pub mod structs;

#[allow(dead_code)]
mod libxml2;
mod version;

use capctl::{Cap, CapSet, ParseCapError};

use std::{error::Error, fs::File, io::Read, path::Path};

use sxd_document::{
    dom::{ChildOfElement, ChildOfRoot, Document, Element},
    parser, Package,
};

use self::structs::Groups;

pub(crate) const FILENAME: &str = "/etc/security/rootasrole.xml";

pub(crate) fn read_file<P>(file_path: P, contents: &mut String) -> Result<(), Box<dyn Error>>
where
    P: AsRef<Path>,
{
    let mut file = File::open(file_path)?;
    file.read_to_string(contents)?;
    Ok(())
}

pub(crate) fn read_xml_file<P>(file_path: &P) -> Result<Package, Box<dyn Error>>
where
    P: AsRef<Path>,
{
    let mut contents = String::new();
    read_file(file_path, &mut contents)?;
    Ok(parser::parse(&contents)?)
}

pub(crate) fn foreach_child<F>(element: &Element, mut f: F) -> Result<(), Box<dyn Error>>
where
    F: FnMut(ChildOfElement) -> Result<(), Box<dyn Error>>,
{
    if !element.children().is_empty() {
        for child in element.children() {
            f(child)?;
        }
    }
    Ok(())
}

pub(crate) fn foreach_element_name<F>(element: &Element, element_name : &str, mut f: F) -> Result<(), Box<dyn Error>>
where
    F: FnMut(Element) -> Result<(), Box<dyn Error>>,
{
    if !element.children().is_empty() {
        for child in element.children() {
            if let Some(element) = child.element() {
                if element.name().local_part() == element_name {
                    f(element)?;
                }
            }
        }
    }
    Ok(())
}


pub(crate) fn foreach_inner_elements_names<F>(
    element: &Element,
    elements_structure: &mut Vec<&str>,
    mut f: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnMut(Element) -> Result<(), Box<dyn Error>>,
{
    if elements_structure.is_empty() {
        return Ok(());
    } else if elements_structure.len() == 1 {
        return foreach_element_name(element, elements_structure.first().unwrap(), f);
    } else if elements_structure.len() > 128 {
        return Err("elements_structure is too big".into());
    }
    for child in element.children() {
        if let Some(element) = child.element() {
            if element.name().local_part() == *elements_structure.first().unwrap() {
                elements_structure.remove(0);
                if elements_structure.is_empty() {
                    return f(element);
                } else {
                    return foreach_inner_elements_names(&element, elements_structure, f);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn do_in_main_child<F>(
    doc: &Document,
    name: &str,
    mut f: F,
) -> Result<(), Box<dyn Error>>
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

pub(crate) fn do_in_main_element<F>(
    doc: &Document,
    name: &str,
    mut f: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnMut(Element) -> Result<(), Box<dyn Error>>,
{
    do_in_main_child(doc, name, |child| {
        if let Some(element) = child.element() {
            f(element.into())?;
        }
        Ok(())
    })
}

pub(crate) fn get_groups(node: Element) -> Groups {
    node.attribute("names")
        .expect("Unable to retrieve group names")
        .value()
        .split(',')
        .map(|s| s.to_string())
        .collect()
}

pub fn capset_to_string(set: &CapSet) -> String {
    set.iter()
        .fold(String::new(), |mut acc, cap| {
            acc.push_str(&format!("CAP_{:?} ", cap));
            acc
        })
        .trim_end()
        .to_string()
}

pub fn parse_capset(s: &str) -> Result<CapSet, ParseCapError> {
    if s.is_empty() || s.eq_ignore_ascii_case("all") {
        return Ok(!CapSet::empty());
    }

    let mut res = CapSet::empty();

    for part in s.split(',') {
        match part.parse() {
            Ok(cap) => res.add(cap),
            Err(error) => {
                return Err(error);
            }
        }
    }

    Ok(res)
}

/// Reference every capabilities that lead to almost a direct privilege escalation
pub fn capabilities_are_exploitable(caps: &CapSet) -> bool {
    caps.has(Cap::SYS_ADMIN)
        || caps.has(Cap::SYS_PTRACE)
        || caps.has(Cap::SYS_MODULE)
        || caps.has(Cap::DAC_READ_SEARCH)
        || caps.has(Cap::DAC_OVERRIDE)
        || caps.has(Cap::FOWNER)
        || caps.has(Cap::CHOWN)
        || caps.has(Cap::SETUID)
        || caps.has(Cap::SETGID)
        || caps.has(Cap::SETFCAP)
        || caps.has(Cap::SYS_RAWIO)
        || caps.has(Cap::LINUX_IMMUTABLE)
        || caps.has(Cap::SYS_CHROOT)
        || caps.has(Cap::SYS_BOOT)
        || caps.has(Cap::MKNOD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use capctl::Cap;

    #[test]
    fn capset_to_string_test() {
        let mut set = CapSet::empty();
        set.add(Cap::CHOWN);
        set.add(Cap::DAC_OVERRIDE);
        set.add(Cap::DAC_READ_SEARCH);
        set.add(Cap::FOWNER);
        set.add(Cap::FSETID);
        set.add(Cap::KILL);
        set.add(Cap::SETGID);
        set.add(Cap::SETUID);
        set.add(Cap::SETPCAP);
        set.add(Cap::LINUX_IMMUTABLE);
        set.add(Cap::NET_BIND_SERVICE);
        set.add(Cap::NET_BROADCAST);
        set.add(Cap::NET_ADMIN);
        set.add(Cap::NET_RAW);
        set.add(Cap::IPC_LOCK);
        set.add(Cap::IPC_OWNER);
        set.add(Cap::SYS_MODULE);
        set.add(Cap::SYS_RAWIO);
        set.add(Cap::SYS_CHROOT);
        set.add(Cap::SYS_PTRACE);
        set.add(Cap::SYS_PACCT);
        set.add(Cap::SYS_ADMIN);
        set.add(Cap::SYS_BOOT);
        set.add(Cap::SYS_NICE);
        set.add(Cap::SYS_RESOURCE);
        set.add(Cap::SYS_TIME);
        set.add(Cap::SYS_TTY_CONFIG);
        set.add(Cap::MKNOD);
        set.add(Cap::LEASE);
        set.add(Cap::AUDIT_WRITE);
        set.add(Cap::AUDIT_CONTROL);
        set.add(Cap::SETFCAP);
        set.add(Cap::MAC_OVERRIDE);
        set.add(Cap::MAC_ADMIN);
        set.add(Cap::SYSLOG);
        set.add(Cap::WAKE_ALARM);
        set.add(Cap::BLOCK_SUSPEND);
        set.add(Cap::AUDIT_READ);

        assert_eq!(
            capset_to_string(&set),
            "CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_LINUX_IMMUTABLE CAP_NET_BIND_SERVICE CAP_NET_BROADCAST CAP_NET_ADMIN CAP_NET_RAW CAP_IPC_LOCK CAP_IPC_OWNER CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_CHROOT CAP_SYS_PTRACE CAP_SYS_PACCT CAP_SYS_ADMIN CAP_SYS_BOOT CAP_SYS_NICE CAP_SYS_RESOURCE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_MKNOD CAP_LEASE CAP_AUDIT_WRITE CAP_AUDIT_CONTROL CAP_SETFCAP CAP_MAC_OVERRIDE CAP_MAC_ADMIN CAP_SYSLOG CAP_WAKE_ALARM CAP_BLOCK_SUSPEND CAP_AUDIT_READ");
    }
}
