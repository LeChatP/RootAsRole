use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashSet,
    error::Error,
    fs::File,
    os::fd::AsRawFd,
};

use sxd_document::dom::{Document, Element};

use super::{capset_to_string, options::Opt};

use super::{
    foreach_element, read_xml_file,
    structs::{Config, Groups, IdTask, Role, Save, Task},
};

const FS_IMMUTABLE_FL: u32 = 0x00000010;
const FS_IOC_GETFLAGS: u64 = 0x80086601;
const FS_IOC_SETFLAGS: u64 = 0x40086602;

fn toggle_lock_config(file: &str, lock: bool) -> Result<(), String> {
    let file = match File::open(file) {
        Err(e) => return Err(e.to_string()),
        Ok(f) => f,
    };
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { nix::libc::ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if lock {
        val &= !(FS_IMMUTABLE_FL);
    } else {
        val |= FS_IMMUTABLE_FL;
    }
    if unsafe { nix::libc::ioctl(fd, FS_IOC_SETFLAGS, &mut val) } < 0 {
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

pub fn save_config(filename: &str, config: &Config) -> Result<(), Box<dyn Error>> {
    let package = read_xml_file(filename)?;
    let doc = package.as_document();
    toggle_lock_config(filename, false)?;
    config.save(Some(&doc), None)?;
    toggle_lock_config(filename, true)?;
    Ok(())
}

impl<'a> Save for Config<'a> {
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
        let mut hasroles = false;
        foreach_element(element, |child| {
            if let Some(child) = child.element() {
                match child.name().local_part() {
                    "roles" => {
                        hasroles = true;
                        let mut rolesnames = self.get_roles_names();
                        foreach_element(&child, |role_element| {
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
                            .options
                            .as_ref()
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
        if !hasroles {
            if let Some(options) = &self.options {
                let options = options.as_ref();
                let options_element = doc.create_element("options");
                options.borrow().save(doc.into(), Some(&options_element))?;
                element.append_child(options_element);
            }
            let roles_element = doc.create_element("roles");
            let rolesnames = self.get_roles_names();
            for rolename in rolesnames {
                let role = self.get_role(&rolename).unwrap();
                let role_element = doc.create_element("role");
                role_element.set_attribute_value("name", &rolename);

                role.as_ref()
                    .borrow()
                    .save(doc.into(), Some(&role_element))?;
                roles_element.append_child(role_element);
            }
            element.append_child(roles_element);
            edited = true;
        }
        Ok(edited)
    }
}

fn add_actors_to_child_element(
    doc: &Document,
    child: &Element,
    users: &HashSet<String>,
    groups: &HashSet<Groups>,
) -> bool {
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
        true
    } else {
        false
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
        if element.children().len() > 0 {
            let mut hasactors = false;
            let mut hasoptions = false;
            let mut hastasks = false;
            let mut taskid = 0;

            foreach_element(&element, |child| {
                if let Some(child) = child.element() {
                    match child.name().local_part() {
                        "actors" => {
                            hasactors = true;
                            let mut users = HashSet::new();
                            users.extend(self.users.clone());
                            let mut groups = HashSet::new();
                            groups.extend(self.groups.clone());
                            foreach_element(&child, |actor_element| {
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
                            edited = add_actors_to_child_element(&doc, &child, &users, &groups);
                        }
                        "task" => {
                            hastasks = true;
                            if let Some(task) = self.tasks.iter().find(|t| {
                                if let Some(id) = child.attribute("id") {
                                    t.as_ref().borrow().id == IdTask::Name(id.value().to_string())
                                } else {
                                    let ret = t.as_ref().borrow().id == IdTask::Number(taskid);
                                    taskid += 1;
                                    ret
                                }
                            }) {
                                if task.as_ref().borrow().save(doc.into(), Some(&child))? {
                                    edited = true;
                                }
                            } else {
                                child.remove_from_parent();
                                edited = true;
                            }
                        }
                        "options" => {
                            hasoptions = true;
                            if self
                                .options
                                .clone()
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
            if !hasactors && (!self.users.is_empty() || !self.groups.is_empty()) {
                let mut users = HashSet::new();
                users.extend(self.users.clone());
                let mut groups = HashSet::new();
                groups.extend(self.groups.clone());
                let actors_element = doc.create_element("actors");
                add_actors_to_child_element(&doc, &actors_element, &users, &groups);
                element.append_child(actors_element);
                edited = true;
            }
            if !hastasks && !self.tasks.is_empty() {
                for task in self.tasks.clone() {
                    let element = doc.create_element("task");
                    task.as_ref().borrow().save(doc.into(), Some(&element))?;
                }
                edited = true;
            }
            if !hasoptions && self.options.is_some() {
                let element = doc.create_element("options");
                self.options
                    .as_ref()
                    .unwrap()
                    .as_ref()
                    .borrow()
                    .save(doc.into(), Some(&element))?;
                edited = true;
            }
        } else {
            let actors_element = doc.create_element("actors");
            let mut users = HashSet::new();
            users.extend(self.users.clone());
            let mut groups = HashSet::new();
            groups.extend(self.groups.clone());
            add_actors_to_child_element(doc, &actors_element, &users, &groups);
            for task in self.tasks.clone() {
                let child = doc.create_element("task");
                task.as_ref().borrow().save(doc.into(), Some(&child))?;
                element.append_child(child);
            }
            if let Some(options) = &self.options {
                let options_element = doc.create_element("options");
                options
                    .as_ref()
                    .borrow()
                    .save(doc.into(), Some(&options_element))?;
                element.append_child(options_element);
            }
            edited = true;
        }
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
        if let IdTask::Name(id) = &self.id {
            if let Some(att) = element.attribute_value("id") {
                if att != id.as_str() {
                    element.set_attribute_value("id", id.as_str());
                    edited = true;
                }
            } else {
                element.set_attribute_value("id", id.as_str());
                edited = true;
            }
        }
        if let Some(capabilities) = &self.capabilities {
            if !capabilities.is_empty() {
                element.set_attribute_value("capabilities", &capset_to_string(capabilities));
            } else if element.attribute_value("capabilities").is_some() {
                element.remove_attribute("capabilities");
            }
        }
        if let Some(setuid) = &self.setuid {
            element.set_attribute_value("setuser", setuid.as_str());
        } else if element.attribute_value("setuser").is_some() {
            element.remove_attribute("setuser");
        }
        if let Some(setgid) = &self.setgid {
            element.set_attribute_value("setgroups", setgid.join(",").as_str());
        } else if element.attribute_value("setgroups").is_some() {
            element.remove_attribute("setgroups");
        }

        let mut commands = HashSet::new();
        commands.extend(self.commands.clone());
        let mut hasoptions = false;
        let mut haspurpose = false;
        foreach_element(&element, |child| {
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
                        haspurpose = true;
                        if let Some(purpose) = &self.purpose {
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
                        hasoptions = true;
                        if self
                            .options
                            .as_ref()
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

        if !haspurpose && self.purpose.is_some() {
            let purpose_element = doc.create_element("purpose");
            purpose_element.set_text(self.purpose.as_ref().unwrap().as_str());
            element.append_child(purpose_element);
            edited = true;
        }

        if !commands.is_empty() {
            for command in commands {
                let command_element = doc.create_element("command");
                command_element.set_text(&command);
                element.append_child(command_element);
            }
            edited = true;
        }

        if !hasoptions && self.options.is_some() {
            let options_element = doc.create_element("options");
            self.options
                .as_ref()
                .unwrap()
                .as_ref()
                .borrow()
                .save(doc.into(), Some(&options_element))?;
            element.append_child(options_element);
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
        let mut haspath = false;
        let mut hasenv_whitelist = false;
        let mut hasenv_checklist = false;
        let mut hasallow_root = false;
        let mut hasdisable_bounding = false;
        let mut haswildcard_denied = false;
        foreach_element(&element, |child| {
            if let Some(child_element) = child.element() {
                match child_element.name().local_part() {
                    "path" => {
                        haspath = true;
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
                        hasenv_whitelist = true;
                        if self.env_whitelist.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if *child
                            .text()
                            .ok_or::<Box<dyn Error>>(
                                "Unable to retrieve env_whitelist Text".into(),
                            )?
                            .text()
                            != self.env_whitelist.as_ref().unwrap().to_string()
                        {
                            child_element.set_text(self.env_whitelist.as_ref().unwrap().as_str());
                            edited = true;
                        }
                    }
                    "env_checklist" => {
                        hasenv_checklist = true;
                        if self.env_checklist.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if *child
                            .text()
                            .ok_or::<Box<dyn Error>>(
                                "Unable to retrieve env_checklist Text".into(),
                            )?
                            .text()
                            != self.env_checklist.as_ref().unwrap().to_string()
                        {
                            child_element.set_text(self.env_checklist.as_ref().unwrap().as_str());
                            edited = true;
                        }
                    }
                    "allow-root" => {
                        hasallow_root = true;
                        let noroot = child_element
                            .attribute("allow-root")
                            .ok_or::<Box<dyn Error>>("Unable to retrieve allow-root".into())?;
                        if self.allow_root.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if (noroot.value() == "true") != self.allow_root.unwrap() {
                            child_element.set_attribute_value(
                                "enforce",
                                match self.allow_root.unwrap() {
                                    true => "true",
                                    false => "false",
                                },
                            );
                            edited = true;
                        }
                    }
                    "allow-bounding" => {
                        hasdisable_bounding = true;
                        let noroot = child_element
                            .attribute("allow-bounding")
                            .ok_or::<Box<dyn Error>>("Unable to retrieve allow_bounding".into())?;
                        if self.allow_root.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if (noroot.value() == "true") != self.allow_root.unwrap() {
                            child_element.set_attribute_value(
                                "enforce",
                                match self.allow_root.unwrap() {
                                    true => "true",
                                    false => "false",
                                },
                            );
                            edited = true;
                        }
                    }
                    "wildcard_denied" => {
                        haswildcard_denied = true;
                        if self.wildcard_denied.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if *child.text().unwrap().text()
                            != self.wildcard_denied.as_ref().unwrap().to_string()
                        {
                            child_element.set_text(self.wildcard_denied.as_ref().unwrap().as_str());
                            edited = true;
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;
        if !haspath && self.path.is_some() {
            let path_element = _doc.unwrap().create_element("path");
            path_element.set_text(self.path.as_ref().unwrap());
            element.append_child(path_element);
            edited = true;
        }
        if !hasenv_whitelist && self.env_whitelist.is_some() {
            let env_whitelist_element = _doc.unwrap().create_element("env_whitelist");
            env_whitelist_element.set_text(self.env_whitelist.as_ref().unwrap().as_str());
            element.append_child(env_whitelist_element);
            edited = true;
        }
        if !hasenv_checklist && self.env_checklist.is_some() {
            let env_checklist_element = _doc.unwrap().create_element("env_checklist");
            env_checklist_element.set_text(self.env_checklist.as_ref().unwrap().as_str());
            element.append_child(env_checklist_element);
            edited = true;
        }
        if !hasallow_root && self.allow_root.is_some() {
            let allow_root_element = _doc.unwrap().create_element("allow-root");
            allow_root_element.set_attribute_value(
                "enforce",
                match self.allow_root.unwrap() {
                    true => "true",
                    false => "false",
                },
            );
            element.append_child(allow_root_element);
            edited = true;
        }
        if !hasdisable_bounding && self.disable_bounding.is_some() {
            let disable_bounding_element = _doc.unwrap().create_element("disable-bounding");
            disable_bounding_element.set_attribute_value(
                "enforce",
                match self.disable_bounding.unwrap() {
                    true => "true",
                    false => "false",
                },
            );
            element.append_child(disable_bounding_element);
            edited = true;
        }
        if self.wildcard_denied.is_some() {
            let wildcard_denied_element = _doc.unwrap().create_element("wildcard_denied");
            wildcard_denied_element.set_text(self.wildcard_denied.as_ref().unwrap().as_str());
            element.append_child(wildcard_denied_element);
            edited = true;
        }

        Ok(edited)
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;
    use test_log::test;

    use super::super::options::*;
    use super::super::structs::*;
    use super::*;
    use capctl::{Cap, CapSet};

    #[test]
    fn test_save() {
        let roles = Config::new("vtest");
        let binding = "role_test".to_string();
        let role = Role::new(binding, Some(Rc::downgrade(&roles)));
        let task = Task::new(IdTask::Name("task_test".to_string()), Rc::downgrade(&role));
        {
            let mut task_mut = task.as_ref().borrow_mut();
            task_mut.commands.push("test_command1".to_string());
            task_mut.commands.push("test_command2".to_string());
            task_mut.purpose = Some("test_purpose".to_string());
            let mut capset = CapSet::empty();
            capset.add(Cap::BPF);
            task_mut.capabilities = Some(capset);
            task_mut.setuid = Some("test_setuid".to_string());
            task_mut.setgid =
                Some(vec!["test_setgidA1".to_string(), "test_setgidB1".to_string()].into());
            let mut options = Opt::new(Level::Task);
            options.path = Some("task_test_path".to_string().into());
            options.env_whitelist = Some("task_test_env_whitelist".to_string().into());
            options.env_checklist = Some("task_test_env_checklist".to_string().into());
            options.allow_root = Some(false.into());
            options.disable_bounding = Some(false.into());
            options.wildcard_denied = Some("task_test_wildcard_denied".into());
            task_mut.options = Some(Rc::new(options.into()));
        }
        {
            let mut role_mut = role.as_ref().borrow_mut();
            role_mut.users.push("test_user1".to_string());
            role_mut.users.push("test_user2".to_string());
            role_mut
                .groups
                .push(vec!["test_groupA1".to_string()].into());
            role_mut
                .groups
                .push(vec!["test_groupB1".to_string(), "test_groupB2".to_string()].into());
            role_mut.tasks.push(task);
            let mut options = Opt::new(Level::Role);
            options.path = Some("role_test_path".to_string().into());
            options.env_whitelist = Some("role_test_env_whitelist".to_string().into());
            options.env_checklist = Some("role_test_env_checklist".to_string().into());
            options.allow_root = Some(false.into());
            options.disable_bounding = Some(false.into());
            options.wildcard_denied = Some("role_test_wildcard_denied".into());
            role_mut.options = Some(Rc::new(options.into()));
        }
        let mut roles_mut = roles.as_ref().borrow_mut();
        let mut options = Opt::new(Level::Global);
        options.path = Some("global_test_path".to_string().into());
        options.env_whitelist = Some("global_test_env_whitelist".to_string().into());
        options.env_checklist = Some("global_test_env_checklist".to_string().into());
        options.allow_root = Some(false.into());
        options.disable_bounding = Some(false.into());
        options.wildcard_denied = Some("global_test_wildcard_denied".into());
        roles_mut.options = Some(Rc::new(options.into()));
        roles_mut.roles.push(role);
        let package = sxd_document::Package::new();
        let doc = package.as_document();
        let root = doc.create_element("rootasrole");
        root.set_attribute_value("version", "vtest");
        roles_mut.save(Some(&doc), Some(&root)).unwrap();
        doc.root().append_child(root);
        let childs = root.children();
        assert_eq!(childs.len(), 2);
        let roles_options = childs[0].element().unwrap();
        assert_eq!(roles_options.name().local_part(), "options");
        assert_eq!(roles_options.children().len(), 6);
        for option_element in roles_options.children() {
            let option_element = option_element.element().unwrap();
            match option_element.name().local_part() {
                "path" => {
                    assert_eq!(
                        option_element.children()[0].text().unwrap().text(),
                        "global_test_path"
                    );
                }
                "env_whitelist" => {
                    assert_eq!(
                        option_element.children()[0].text().unwrap().text(),
                        "global_test_env_whitelist"
                    );
                }
                "env_checklist" => {
                    assert_eq!(
                        option_element.children()[0].text().unwrap().text(),
                        "global_test_env_checklist"
                    );
                }
                "allow-root" => {
                    assert_eq!(
                        option_element.attribute("enforce").unwrap().value(),
                        "false"
                    );
                }
                "allow-bounding" => {
                    assert_eq!(
                        option_element.attribute("enforce").unwrap().value(),
                        "false"
                    );
                }
                "wildcard_denied" => {
                    assert_eq!(
                        option_element.children()[0].text().unwrap().text(),
                        "global_test_wildcard_denied"
                    );
                }
                _ => {}
            }
        }
        let role_list = childs[1].element().unwrap();
        assert_eq!(role_list.name().local_part(), "roles");
        assert_eq!(role_list.children().len(), 1);
        let role = role_list.children()[0].element().unwrap();
        assert_eq!(role.name().local_part(), "role");
        assert_eq!(role.children().len(), 2);
        let task = role.children()[0].element().unwrap();
        assert_eq!(task.name().local_part(), "task");
        assert_eq!(task.children().len(), 4);
        let task_purpose = task.children()[0].element().unwrap();
        assert_eq!(task_purpose.name().local_part(), "purpose");
        assert_eq!(task_purpose.children().len(), 1);
        assert_eq!(
            task_purpose.children()[0].text().unwrap().text(),
            "test_purpose"
        );
        let task_command1 = task.children()[1].element().unwrap();
        assert_eq!(task_command1.name().local_part(), "command");
        assert_eq!(task_command1.children().len(), 1);
        assert!(task_command1.children()[0]
            .text()
            .unwrap()
            .text()
            .starts_with("test_command"));
        let task_command2 = task.children()[2].element().unwrap();
        assert_eq!(task_command2.name().local_part(), "command");
        assert_eq!(task_command2.children().len(), 1);
        assert!(task_command2.children()[0]
            .text()
            .unwrap()
            .text()
            .starts_with("test_command"));
        let package = read_xml_file(
            format!("{}/tests/resources/test_xml_manager_case1.xml", env!("PWD")).as_str(),
        )
        .unwrap();
        let doc = package.as_document();
        let element = doc.root().children();
        assert_eq!(element.len(), 3);
        let element = element[1].element().unwrap();
        roles_mut.save(Some(&doc), Some(&element)).unwrap();
        let childs = root.children();
        assert_eq!(childs.len(), 2);
        let roles_options = childs[0].element().unwrap();
        assert_eq!(roles_options.name().local_part(), "options");
        assert_eq!(roles_options.children().len(), 6);
        let role_list = childs[1].element().unwrap();
        assert_eq!(role_list.name().local_part(), "roles");
        assert_eq!(role_list.children().len(), 1);
        let role = role_list.children()[0].element().unwrap();
        assert_eq!(role.name().local_part(), "role");
        assert_eq!(role.children().len(), 2);
        let task = role.children()[0].element().unwrap();
        assert_eq!(task.name().local_part(), "task");
        assert_eq!(task.children().len(), 4);
        let task_purpose = task.children()[0].element().unwrap();
        assert_eq!(task_purpose.name().local_part(), "purpose");
        assert_eq!(task_purpose.children().len(), 1);
        assert_eq!(
            task_purpose.children()[0].text().unwrap().text(),
            "test_purpose"
        );
        let task_command1 = task.children()[1].element().unwrap();
        assert_eq!(task_command1.name().local_part(), "command");
        assert_eq!(task_command1.children().len(), 1);
        assert!(task_command1.children()[0]
            .text()
            .unwrap()
            .text()
            .starts_with("test_command"));
        let task_command2 = task.children()[2].element().unwrap();
        assert_eq!(task_command2.name().local_part(), "command");
        assert_eq!(task_command2.children().len(), 1);
        assert!(task_command2.children()[0]
            .text()
            .unwrap()
            .text()
            .starts_with("test_command"));
    }
}
