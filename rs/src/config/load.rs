use std::{borrow::BorrowMut, cell::RefCell, error::Error, rc::Rc};

use chrono::Duration;
use sxd_document::dom::Element;
use tracing::warn;

use crate::{
    options::{Level, Opt},
    util,
    version::PACKAGE_VERSION,
};

use super::{
    do_in_main_element, get_groups, read_xml_file,
    structs::{Config, IdTask, Role, Task, TimestampType},
    version::migrate, libxml2,
};

trait Load {
    fn load(&self, node: Element) -> Result<(), Box<dyn Error>>;
}

pub fn is_enforced(node: Element) -> bool {
    let enforce = node.attribute("enforce");
    (enforce.is_some()
        && enforce
            .expect("Unable to retrieve enforce attribute")
            .value()
            == "true")
        || enforce.is_none()
}

fn get_options(level: Level, node: Element) -> Opt {
    let mut rc_options = Opt::new(level);

    for child in node.children() {
        let mut options = rc_options.borrow_mut();
        if let Some(elem) = child.element() {
            match elem.name().local_part() {
                "path" => {
                    options.path = Some(
                        elem.children()
                            .first()
                            .unwrap()
                            .text()
                            .expect("Cannot read PATH option")
                            .text()
                            .to_string(),
                    )
                }
                "env-keep" => {
                    options.env_whitelist = Some(
                        elem.children()
                            .first()
                            .unwrap()
                            .text()
                            .expect("Cannot read Whitelist option")
                            .text()
                            .to_string(),
                    )
                }
                "env-check" => {
                    options.env_checklist = Some(
                        elem.children()
                            .first()
                            .unwrap()
                            .text()
                            .expect("Cannot read Checklist option")
                            .text()
                            .to_string(),
                    )
                }
                "allow-root" => options.allow_root = Some(is_enforced(elem)),
                "allow-bounding" => options.disable_bounding = Some(is_enforced(elem)),
                "wildcard-denied" => {
                    options.wildcard_denied = Some(
                        elem.children()
                            .first()
                            .unwrap()
                            .text()
                            .expect("Cannot read Checklist option")
                            .text()
                            .to_string(),
                    )
                }
                _ => warn!("Unknown option: {}", elem.name().local_part()),
            }
        }
    }
    rc_options
}

impl Load for Rc<RefCell<Task<'_>>> {
    fn load(&self, node: Element) -> Result<(), Box<dyn Error>> {
        if let Some(id) = node.attribute_value("id") {
            self.as_ref().borrow_mut().id = IdTask::Name(id.to_string());
        }
        if let Some(capabilities) = node.attribute_value("capabilities") {
            self.as_ref().borrow_mut().capabilities = Some(util::parse_capset(capabilities)?);
        }
        self.as_ref().borrow_mut().setuid =
            node.attribute_value("setuser").map(|setuid| setuid.into());
        self.as_ref().borrow_mut().setgid = node
            .attribute_value("setgroups")
            .map(|setgid| setgid.split(',').map(|e| e.to_string()).collect());
        for child in node.children() {
            if let Some(elem) = child.element() {
                match elem.name().local_part() {
                    "command" => self.as_ref().borrow_mut().commands.push(
                        elem.children()
                            .first()
                            .ok_or("Unable to get text from command")?
                            .text()
                            .map(|f| f.text().to_string())
                            .ok_or("Unable to get text from command")?,
                    ),
                    "options" => {
                        self.as_ref().borrow_mut().options =
                            Some(Rc::new(get_options(Level::Task, elem).into()));
                    }
                    "purpose" => {
                        self.as_ref().borrow_mut().purpose = Some(
                            elem.children()
                                .first()
                                .ok_or("Unable to get text from purpose")?
                                .text()
                                .map(|f| f.text().to_string())
                                .ok_or("Unable to get text from purpose")?,
                        );
                    }
                    _ => warn!("Unknown element: {}", elem.name().local_part()),
                }
            }
        }
        Ok(())
    }
}

fn add_actors(role: &mut Role, node: Element) -> Result<(), Box<dyn Error>> {
    for child in node.children() {
        if let Some(elem) = child.element() {
            match elem.name().local_part() {
                "user" => role.users.push(
                    elem.attribute_value("name")
                        .ok_or("Unable to retrieve user name")?
                        .to_string(),
                ),
                "group" => role.groups.push(get_groups(elem)),
                _ => warn!("Unknown element: {}", elem.name().local_part()),
            }
        }
    }
    Ok(())
}

impl Load for Rc<RefCell<Role<'_>>> {
    fn load(&self, element: Element) -> Result<(), Box<dyn Error>> {
        let mut i: usize = 0;
        for child in element.children() {
            if let Some(element) = child.element() {
                match element.name().local_part() {
                    "actors" => add_actors(&mut self.as_ref().borrow_mut(), element)?,
                    "task" => {
                        i += 1;
                        let task = Task::new(IdTask::Number(i), Rc::downgrade(&self));
                        task.load(element)?;
                        self.as_ref().borrow_mut().tasks.push(task);
                    }
                    "options" => {
                        self.as_ref().borrow_mut().options =
                            Some(Rc::new(get_options(Level::Role, element).into()))
                    }
                    _ => warn!(
                        "Unknown element: {}",
                        child
                            .element()
                            .expect("Unable to convert unknown to element")
                            .name()
                            .local_part()
                    ),
                }
            }
        }
        // load parents
        if let Some(parents) = element.attribute_value("parents") {
            let parents: Vec<&str> = parents.split(',').collect();
            let confparents = parents
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<String>>();
            let mut parents = Vec::new();
            if let Some(config) = self.as_ref().borrow().get_config() {
                let mut roles = config.as_ref().borrow_mut().roles.clone();
                roles.retain(|e| {
                    confparents.contains(&e.as_ref().borrow().name)
                        && e.as_ref().borrow().name != self.as_ref().borrow().name
                });
                if roles.len() != confparents.len() {
                    warn!(
                        "Role {} : Some parents are not found: {:?}",
                        self.as_ref().borrow().name,
                        confparents
                    );
                }
                if roles.len() != 0 {
                    for role in roles {
                        parents.push(Rc::downgrade(&role));
                    }
                }
            }
            if parents.len() != 0 {
                self.as_ref().borrow_mut().parents = Some(parents);
            }
        }
        Ok(())
    }
}

impl Load for Rc<RefCell<Config<'_>>> {
    fn load(&self, element: Element) -> Result<(), Box<dyn Error>> {
        if element.name().local_part() != "rootasrole" {
            return Err("Wrong Element".into());
        }

        if let Some(timestamp_type) = element.attribute_value("timestamp-type") {
            if let Ok(timestamptype) = timestamp_type.parse::<TimestampType>() {
                self.as_ref().borrow_mut().timestamp.timestamptype = timestamptype;
            } else {
                return Err(format!("Unknown timestamp type: {}", timestamp_type).into());
            }
        }

        if let Some(timestamp) = element.attribute_value("timestamp-timeout") {
            self.as_ref().borrow_mut().timestamp.offset = Duration::seconds(timestamp.parse::<i64>()?);
        }

        if let Some(usage_max) = element.attribute_value("password-usage-max") {
            self.as_ref().borrow_mut().timestamp.max_usage = Some(usage_max.parse::<u32>()?);
        }


        for role in element.children() {
            if let Some(element) = role.element() {
                if element.name().local_part() == "roles" {
                    let mut ziprole = Vec::new();
                    for role in element.children() {
                        if let Some(element) = role.element() {
                            if element.name().local_part() == "role" {
                                let name = element.attribute_value("name").unwrap();
                                let role = Role::new(name.to_string(), Some(Rc::downgrade(&self)));
                                ziprole.push((role, element));
                            }
                        }
                    }
                    // Load role after all roles are created, this is because of the hierarchy feature
                    for (role, element) in ziprole {
                        role.load(element)?;
                        self.as_ref().borrow_mut().roles.push(role);
                    }
                }
                if element.name().local_part() == "options" {
                    self.as_ref().borrow_mut().options =
                        Some(Rc::new(get_options(Level::Global, element).into()));
                }
            }
        }
        Ok(())
    }
}

pub fn load_config<'a>(filename: &str) -> Result<Rc<RefCell<Config<'a>>>, Box<dyn Error>> {
    if ! unsafe { libxml2::validate_xml_file(filename, true) } {
        return Err("Invalid XML file".into());
    }
    let package = read_xml_file(filename)?;
    let doc = package.as_document();

    let rc_roles = Config::new(PACKAGE_VERSION);
    do_in_main_element(doc, "rootasrole", |element| {
        if let Some(element) = element.element() {
            let migrated = migrate(
                element.attribute_value("version").expect("No version"),
                element.document(),
            )?;
            rc_roles.load(element)?;
            rc_roles.as_ref().borrow_mut().migrated = migrated;
        }
        Ok(())
    })?;
    Ok(rc_roles)
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_load_roles() {
        let roles = load_config(
            format!(
                "{}/../tests/resources/test_xml_manager_case1.xml",
                env!("PWD")
            )
            .as_str(),
        );
        if let Err(e) = roles {
            panic!("Unable to load roles: {}", e);
        }
        let binding = roles.unwrap();
        let roles = binding.as_ref().borrow();
        assert_eq!(roles.roles.len(), 2);
        let role = roles.roles.first().unwrap();
        let role = role.as_ref().borrow();
        assert_eq!(role.name, "test1");
        assert_eq!(role.users.len(), 1);
        assert_eq!(role.users.first().unwrap(), "test1");
        assert_eq!(role.groups.len(), 0);
        assert_eq!(role.tasks.len(), 2);
        let task = role.tasks.first().unwrap();
        let task = task.as_ref().borrow();
        assert_eq!(task.id, IdTask::Name("t1_test1".to_string()));
        assert_eq!(task.commands.len(), 1);
        assert_eq!(task.commands.first().unwrap(), "/bin/ls");
        let option = task.options.as_ref();
        assert!(option.is_some());
        let path = task
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .to_owned()
            .path;
        assert!(path.is_some());
        assert_eq!(path.unwrap(), "t1_test1");
        assert!(task.capabilities.is_some());
        let capabilities = task.capabilities.to_owned().unwrap();
        assert_eq!(
            capabilities,
            util::parse_capset("cap_dac_override").unwrap()
        );
        let task = role.tasks.last().unwrap();
        let task = task.as_ref().borrow();
        assert_eq!(task.id, IdTask::Name("t1_test2".to_string()));
        assert_eq!(task.commands.len(), 1);
        assert_eq!(task.commands.first().unwrap(), "/bin/ls");
        let option = task.options.as_ref();
        assert!(option.is_some());
        let path = task
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .to_owned()
            .path;
        assert!(path.is_some());
        assert_eq!(path.unwrap(), "t1_test2");
        assert!(task.capabilities.is_none());
        let role = roles.roles.last().unwrap();
        let role = role.as_ref().borrow();
        assert_eq!(role.name, "test2");
        assert_eq!(role.users.len(), 1);
        assert_eq!(role.users.first().unwrap(), "test1");
        assert_eq!(role.groups.len(), 0);
        assert_eq!(role.tasks.len(), 1);
        let task = role.tasks.first().unwrap();
        let task = task.as_ref().borrow();
        assert_eq!(task.id, IdTask::Name("t2_test1".to_string()));
        assert_eq!(task.commands.len(), 1);
        assert_eq!(task.commands.first().unwrap(), "/bin/ls");
        let option = task.options.as_ref();
        assert!(option.is_some());
        let path = task
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .to_owned()
            .path;
        assert!(path.is_some());
        assert_eq!(path.unwrap(), "t2_test1");
        let allowroot = task
            .options
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .to_owned()
            .allow_root;
        assert!(allowroot.is_some());
        assert_eq!(allowroot.unwrap(), true);
        assert!(task.capabilities.is_none());
    }
}
