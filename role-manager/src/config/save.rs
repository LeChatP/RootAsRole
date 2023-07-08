use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashSet,
    error::Error,
    fs::File,
    io::Write,
    os::fd::AsRawFd,
};

use libc::{c_int, c_ulong, ioctl};
use sxd_document::{
    dom::{Document, Element},
    writer::Writer,
};

use crate::{capabilities::Caps, options::Opt, rolemanager::RoleContext, version::DTD};

use super::{
    foreach_element, read_xml_file,
    structs::{Groups, Role, Roles, Save, Task, ToXml},
};

const FS_IOC_GETFLAGS: c_ulong = 0x80086601;
const FS_IOC_SETFLAGS: c_ulong = 0x40086602;
const FS_IMMUTABLE_FL: c_int = 0x00000010;

fn toggle_lock_config(file: &str, lock: bool) -> Result<(), String> {
    let file = match File::open(file) {
        Err(e) => return Err(e.to_string()),
        Ok(f) => f,
    };
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if lock {
        val &= !(FS_IMMUTABLE_FL);
    } else {
        val |= FS_IMMUTABLE_FL;
    }
    if unsafe { ioctl(fd, FS_IOC_SETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub fn sxd_sanitize(element: &mut str) -> String {
    element
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\"', "&quot;")
        .replace('\'', "&apos;")
}

impl<'a> Save for Roles<'a> {
    fn save(
        &self,
        doc: Option<&Document>,
        element: Option<&Element>,
    ) -> Result<bool, Box<dyn Error>> {
        let doc = doc.ok_or::<Box<dyn Error>>("Unable to retrieve Document".into())?;
        let element = element.ok_or::<Box<dyn Error>>("Unable to retrieve Element".into())?;
        if element.name().local_part() != "rootasrole" {
            return Err("Unable to save roles".into());
        }
        let mut edited = false;
        foreach_element(element.to_owned(), |child| {
            if let Some(child) = child.element() {
                match child.name().local_part() {
                    "roles" => {
                        let mut rolesnames = self.get_roles_names();
                        foreach_element(child, |role_element| {
                            if let Some(role_element) = role_element.element() {
                                let rolename = role_element.attribute_value("name").unwrap();
                                if let Some(role) = self.get_role(rolename) {
                                    if role
                                        .as_ref()
                                        .borrow()
                                        .save(doc.into(), Some(&role_element))?
                                    {
                                        edited = true;
                                    }
                                } else {
                                    role_element.remove_from_parent();
                                }
                                rolesnames.remove(&rolename.to_string());
                            }
                            Ok(())
                        })?;
                        if !rolesnames.is_empty() {
                            edited = true;
                        }
                        for rolename in rolesnames {
                            let role = self.get_role(&rolename).unwrap();
                            let role_element = doc.create_element("role");
                            role_element.set_attribute_value("name", &rolename);
                            role.as_ref()
                                .borrow()
                                .save(doc.into(), Some(&role_element))?;
                            child.append_child(role_element);
                        }
                    }
                    "options" => {
                        if self
                            .to_owned()
                            .options
                            .unwrap()
                            .as_ref()
                            .borrow()
                            .save(doc.into(), Some(&child))?
                        {
                            edited = true;
                        }
                    }
                    _ => (),
                }
            }
            Ok(())
        })?;
        Ok(edited)
    }
}

impl<'a> Save for Role<'a> {
    fn save(
        &self,
        doc: Option<&Document>,
        element: Option<&Element>,
    ) -> Result<bool, Box<dyn Error>> {
        let doc = doc.ok_or::<Box<dyn Error>>("Unable to retrieve Document".into())?;
        let element = element.ok_or::<Box<dyn Error>>("Unable to retrieve Element".into())?;
        if element.name().local_part() != "role" {
            return Err("Unable to save role".into());
        }
        let mut edited = false;
        foreach_element(element.to_owned(), |child| {
            if let Some(child) = child.element() {
                match child.name().local_part() {
                    "actors" => {
                        let mut users = HashSet::new();
                        users.extend(self.users.clone());
                        let mut groups = HashSet::new();
                        groups.extend(self.groups.clone());
                        foreach_element(child, |actor_element| {
                            if let Some(actor_element) = actor_element.element() {
                                match actor_element.name().local_part() {
                                    "user" => {
                                        let username = actor_element
                                            .attribute_value("name")
                                            .unwrap()
                                            .to_string();
                                        if !users.contains(&username) {
                                            actor_element.remove_from_parent();
                                            edited = true;
                                        } else {
                                            users.remove(&username);
                                        }
                                    }
                                    "group" => {
                                        let groupnames = actor_element
                                            .attribute_value("names")
                                            .unwrap()
                                            .split(',')
                                            .map(|s| s.to_string())
                                            .collect::<Groups>();
                                        if !groups.contains(&groupnames) {
                                            actor_element.remove_from_parent();
                                            edited = true;
                                        } else {
                                            groups.remove(&groupnames);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Ok(())
                        })?;
                        if !users.is_empty() || !groups.is_empty() {
                            for user in users {
                                let actor_element = doc.create_element("user");
                                actor_element.set_attribute_value("name", &user);
                                child.append_child(actor_element);
                            }
                            for group in groups {
                                let actor_element = doc.create_element("group");
                                actor_element.set_attribute_value("names", &group.join(","));
                                child.append_child(actor_element);
                            }
                            edited = true;
                        }
                    }
                    "tasks" => {
                        for task in self.tasks.clone() {
                            if task.as_ref().borrow().save(doc.into(), Some(&child))? {
                                edited = true;
                            }
                        }
                    }
                    "options" => {
                        if self
                            .to_owned()
                            .options
                            .unwrap()
                            .as_ref()
                            .borrow()
                            .save(doc.into(), Some(&child))?
                        {
                            edited = true;
                        }
                    }
                    _ => (),
                }
            }
            Ok(())
        })?;
        Ok(edited)
    }
}

impl<'a> Save for Task<'a> {
    fn save(
        &self,
        doc: Option<&Document>,
        element: Option<&Element>,
    ) -> Result<bool, Box<dyn Error>> {
        let doc = doc.ok_or::<Box<dyn Error>>("Unable to retrieve Document".into())?;
        let element = element.ok_or::<Box<dyn Error>>("Unable to retrieve Element".into())?;
        if element.name().local_part() != "task" {
            return Err("Unable to save task".into());
        }
        let mut edited = false;
        if let Some(capabilities) = self.capabilities.to_owned() {
            if <Caps as Into<u64>>::into(capabilities.to_owned()) > 0 {
                element.set_attribute_value("capabilities", capabilities.to_string().as_str());
            } else if element.attribute_value("capabilities").is_some() {
                element.remove_attribute("capabilities");
            }
        }
        if let Some(setuid) = self.setuid.to_owned() {
            element.set_attribute_value("setuser", setuid.as_str());
        } else if element.attribute_value("setuser").is_some() {
            element.remove_attribute("setuser");
        }
        if let Some(setgid) = self.setgid.to_owned() {
            element.set_attribute_value("setgroups", setgid.join(",").as_str());
        } else if element.attribute_value("setgroups").is_some() {
            element.remove_attribute("setgroups");
        }

        let mut commands = HashSet::new();
        commands.extend(self.commands.clone());
        foreach_element(element.to_owned(), |child| {
            if let Some(child_element) = child.element() {
                match child_element.name().local_part() {
                    "command" => {
                        let command = child
                            .text()
                            .ok_or::<Box<dyn Error>>("Unable to retrieve command Text".into())?
                            .text()
                            .to_string();
                        if !commands.contains(&command) {
                            child_element.remove_from_parent();
                            edited = true;
                        } else {
                            commands.remove(&command);
                        }
                    }
                    "purpose" => {
                        if let Some(purpose) = self.purpose.to_owned() {
                            if child
                                .text()
                                .ok_or::<Box<dyn Error>>("Unable to retrieve command Text".into())?
                                .text()
                                != purpose
                            {
                                child_element.set_text(&purpose);
                                edited = true;
                            }
                        } else {
                            child_element.remove_from_parent();
                            edited = true;
                        }
                    }
                    "options" => {
                        if self
                            .to_owned()
                            .options
                            .map(|o| o.as_ref().borrow().save(doc.into(), Some(&child_element)))
                            .unwrap()?
                        {
                            edited = true;
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;
        if !commands.is_empty() {
            for command in commands {
                let command_element = doc.create_element("command");
                command_element.set_text(&command);
                element.append_child(command_element);
            }
            edited = true;
        }
        Ok(edited)
    }
}

impl Save for Opt {
    fn save(
        &self,
        _doc: Option<&Document>,
        element: Option<&Element>,
    ) -> Result<bool, Box<dyn Error>> {
        let element = element.ok_or::<Box<dyn Error>>("Unable to retrieve Element".into())?;
        if element.name().local_part() != "options" {
            return Err("Unable to save options".into());
        }
        let mut edited = false;
        foreach_element(element.to_owned(), |child| {
            if let Some(child_element) = child.element() {
                match child_element.name().local_part() {
                    "path" => {
                        if self.path.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if child_element
                            .children()
                            .iter()
                            .fold(String::new(), |acc, c| {
                                acc + match c.text() {
                                    Some(t) => t.text(),
                                    None => "",
                                }
                            })
                            != *self.path.as_ref().unwrap()
                        {
                            child_element.set_text(self.path.as_ref().unwrap());
                            edited = true;
                        }
                    }
                    "env_whitelist" => {
                        if self.env_whitelist.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if *child
                            .text()
                            .ok_or::<Box<dyn Error>>(
                                "Unable to retrieve env_whitelist Text".into(),
                            )?
                            .text()
                            != self.to_owned().env_whitelist.unwrap()
                        {
                            child_element.set_text(self.to_owned().env_whitelist.unwrap().as_str());
                            edited = true;
                        }
                    }
                    "env_checklist" => {
                        if self.env_checklist.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if *child
                            .text()
                            .ok_or::<Box<dyn Error>>(
                                "Unable to retrieve env_checklist Text".into(),
                            )?
                            .text()
                            != self.to_owned().env_checklist.unwrap()
                        {
                            child_element.set_text(self.to_owned().env_checklist.unwrap().as_str());
                            edited = true;
                        }
                    }
                    "no_root" => {
                        let noroot = child
                            .text()
                            .ok_or::<Box<dyn Error>>("Unable to retrieve no_root Text".into())?
                            .text()
                            == "true";
                        if self.no_root.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if noroot != self.no_root.unwrap() {
                            child_element.set_text(match self.no_root.unwrap() {
                                true => "true",
                                false => "false",
                            });
                            edited = true;
                        }
                    }
                    "bounding" => {
                        let bounding = child
                            .text()
                            .ok_or::<Box<dyn Error>>("Unable to retrieve no_root Text".into())?
                            .text()
                            == "true";
                        if self.bounding.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if bounding != self.bounding.unwrap() {
                            child_element.set_text(match self.bounding.unwrap() {
                                true => "true",
                                false => "false",
                            });
                            edited = true;
                        }
                    }
                    "wildcard_denied" => {
                        if self.wildcard_denied.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if *child.text().unwrap().text()
                            != self.to_owned().wildcard_denied.unwrap()
                        {
                            child_element
                                .set_text(self.to_owned().wildcard_denied.unwrap().as_str());
                            edited = true;
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;
        Ok(edited)
    }
}

impl Save for RoleContext {
    fn save(
        &self,
        _doc: Option<&Document>,
        _element: Option<&Element>,
    ) -> Result<bool, Box<dyn Error>> {
        let path = "/etc/security/rootasrole.xml";
        let package = read_xml_file(path)?;
        let doc = package.as_document();
        let element = doc.root().children().first().unwrap().element().unwrap();
        if self
            .roles
            .as_ref()
            .borrow()
            .save(Some(&doc), Some(&element))?
        {
            let mut content = Vec::new();
            let writer = Writer::new().set_single_quotes(false);
            writer
                .format_document(&element.document(), &mut content)
                .expect("Unable to write file");
            let mut content = String::from_utf8(content).expect("Unable to convert to string");
            content.insert_str(content.match_indices("?>").next().unwrap().0 + 2, DTD);
            toggle_lock_config(path, true).expect("Unable to remove immuable");
            let mut file = File::options()
                .write(true)
                .truncate(true)
                .open(path)
                .expect("Unable to create file");
            file.write_all(content.as_bytes())
                .expect("Unable to write file");
            toggle_lock_config(path, false).expect("Unable to set immuable");
        }

        Ok(true)
    }
}

impl<'a> ToXml for Task<'a> {
    fn to_xml_string(&self) -> String {
        let mut task = String::from("<task ");
        if self.id.is_name() {
            task.push_str(&format!("id=\"{}\" ", self.id.as_ref().unwrap()));
        }
        if self.capabilities.is_some() && self.capabilities.to_owned().unwrap().is_not_empty() {
            task.push_str(&format!(
                "capabilities=\"{}\" ",
                self.capabilities
                    .to_owned()
                    .unwrap()
                    .to_string()
                    .to_lowercase()
            ));
        }
        task.push('>');
        if self.purpose.is_some() {
            task.push_str(&format!(
                "<purpose>{}</purpose>",
                self.purpose.as_ref().unwrap()
            ));
        }
        task.push_str(
            &self
                .commands
                .iter().cloned()
                .map(|x| format!("<command>{}</command>", x))
                .collect::<Vec<String>>()
                .join(""),
        );
        task.push_str("</task>");
        task
    }
}

impl<'a> ToXml for Role<'a> {
    fn to_xml_string(&self) -> String {
        let mut role = String::from("<role ");
        role.push_str(&format!("name=\"{}\" ", self.name));
        role.push('>');
        if !self.users.is_empty() || !self.groups.is_empty() {
            role.push_str("<actors>\n");
            role.push_str(
                &self
                    .users
                    .iter().cloned()
                    .map(|x| format!("<user name=\"{}\"/>\n", x))
                    .collect::<Vec<String>>()
                    .join(""),
            );
            role.push_str(
                &self
                    .groups
                    .iter().cloned()
                    .map(|x| format!("<groups names=\"{}\"/>\n", x.join(",")))
                    .collect::<Vec<String>>()
                    .join(""),
            );
            role.push_str("</actors>\n");
        }

        role.push_str(
            &self
                .tasks
                .iter().cloned()
                .map(|x| x.as_ref().borrow().to_xml_string())
                .collect::<Vec<String>>()
                .join(""),
        );
        role.push_str("</role>");
        role
    }
}

impl<'a> ToXml for Roles<'a> {
    fn to_xml_string(&self) -> String {
        let mut roles = String::from("<rootasrole ");
        roles.push_str(&format!("version=\"{}\">", self.version));
        if let Some(options) = self.options.to_owned() {
            roles.push_str(&format!(
                "<options>{}</options>",
                options.as_ref().borrow().to_string()
            ));
        }
        roles.push_str("<roles>");
        roles.push_str(
            &self
                .roles
                .iter()
                .map(|x| x.as_ref().borrow().to_xml_string())
                .collect::<Vec<String>>()
                .join(""),
        );
        roles.push_str("</roles></rootasrole>");
        roles
    }
}

impl ToXml for Opt {
    fn to_xml_string(&self) -> String {
        let mut content = String::new();
        if let Some(path) = self.path.borrow().as_ref() {
            content.push_str(&format!(
                "<path>{}</path>",
                sxd_sanitize(path.to_owned().borrow_mut())
            ));
        }
        if let Some(env_whitelist) = self.env_whitelist.borrow().as_ref() {
            content.push_str(&format!(
                "<env-keep>{}</env-keep>",
                sxd_sanitize(env_whitelist.to_owned().borrow_mut())
            ));
        }
        if let Some(env_checklist) = self.env_checklist.borrow().as_ref() {
            content.push_str(&format!(
                "<env-check>{}</env-check>",
                sxd_sanitize(env_checklist.to_owned().borrow_mut())
            ));
        }
        if let Some(no_root) = self.no_root.borrow().as_ref() {
            if no_root == &false {
                content.push_str(&format!("<allow-root enforce=\"{}\"/>", !no_root));
            }
        }
        if let Some(bounding) = self.bounding.borrow().as_ref() {
            if bounding == &false {
                content.push_str(&format!("<allow-bounding enforce=\"{}\"/>", !bounding));
            }
        }
        format!("<options>{}</options>", content)
    }
}
