use std::{
    cell::RefCell,
    collections::HashSet,
    error::Error,
    fs::File,
    hash::{Hash, Hasher},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    rc::{Rc, Weak},
};

use sxd_document::{
    dom::{ChildOfElement, ChildOfRoot, Document, Element},
    parser,
    writer::Writer,
    Package,
};

use libc::{c_int, c_ulong, ioctl};

use crate::{
    capabilities::Caps,
    options::Opt,
    rolemanager::RoleContext,
    version::DTD,
};

const FS_IOC_GETFLAGS: c_ulong = 0x80086601;
const FS_IOC_SETFLAGS: c_ulong = 0x40086602;
const FS_IMMUTABLE_FL: c_int = 0x00000010;

pub const FILENAME: &str = "/etc/security/rootasrole.xml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groups {
    pub groups: HashSet<String>,
}

impl Iterator for Groups {
    fn next(&mut self) -> Option<String> {
        self.groups.iter().next().map(|s| s.to_owned())
    }
    type Item = String;
}

impl Hash for Groups {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for group in self.groups.iter() {
            group.hash(state);
        }
    }
}

impl FromIterator<String> for Groups {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Groups {
        let mut groups = HashSet::new();
        for group in iter {
            groups.insert(group);
        }
        Groups { groups }
    }
}

impl From<Vec<String>> for Groups {
    fn from(groups: Vec<std::string::String>) -> Self {
        let mut set = HashSet::new();
        for group in groups {
            set.insert(group);
        }
        Groups { groups: set }
    }
}

impl Groups {
    pub fn join(&self, sep: &str) -> String {
        self.groups.iter().fold(String::new(), |acc, s| {
            if acc.is_empty() {
                s.to_owned()
            } else {
                format!("{}{}{}", acc, sep, s)
            }
        })
    }
}

impl Into<Vec<String>> for Groups {
    fn into(self) -> Vec<String> {
        self.into_iter().collect()
    }
}

pub trait ToXml {
    fn to_xml_string(&self) -> String;
}

#[derive(Clone, Debug)]
pub enum IdTask {
    Name(String),
    Number(usize),
}

impl IdTask {
    pub fn is_name(&self) -> bool {
        match self {
            IdTask::Name(s) => true,
            IdTask::Number(n) => false,
        }
    }

    pub fn as_ref(&self) -> &IdTask {
        self
    }

    pub fn unwrap(&self) -> String {
        match self {
            IdTask::Name(s) => s.to_owned(),
            IdTask::Number(s) => s.to_string(),
        }
    }
}

impl ToString for IdTask {
    fn to_string(&self) -> String {
        match self {
            IdTask::Name(s) => s.to_string(),
            IdTask::Number(n) => format!("Task #{}", n.to_string()),
        }
    }
}

impl From<String> for IdTask {
    fn from(s: String) -> Self {
        IdTask::Name(s)
    }
}

impl Into<String> for IdTask {
    fn into(self) -> String {
        match self {
            IdTask::Name(s) => s,
            IdTask::Number(n) => n.to_string(),
        }
    }
}

impl PartialEq for IdTask {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (IdTask::Name(a), IdTask::Name(b)) => a == b,
            (IdTask::Number(a), IdTask::Number(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Task<'a> {
    role: Weak<RefCell<Role<'a>>>,
    pub id: IdTask,
    pub options: Option<Rc<RefCell<Opt>>>,
    pub commands: Vec<String>,
    pub capabilities: Option<Caps>,
    pub setuid: Option<String>,
    pub setgid: Option<Groups>,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Role<'a> {
    roles: Option<Weak<RefCell<Roles<'a>>>>,
    pub name: String,
    pub users: Vec<String>,
    pub groups: Vec<Groups>,
    pub tasks: Vec<Rc<RefCell<Task<'a>>>>,
    pub options: Option<Rc<RefCell<Opt>>>,
}

#[derive(Debug, Clone)]
pub struct Roles<'a> {
    pub roles: Vec<Rc<RefCell<Role<'a>>>>,
    pub options: Option<Rc<RefCell<Opt>>>,
    pub version: &'a str,
}

impl<'a> Roles<'a> {
    pub fn new(version: &str) -> Rc<RefCell<Roles>> {
        Rc::new(
            Roles {
                roles: Vec::new(),
                options: None,
                version: version,
            }
            .into(),
        )
    }

    pub fn get_role(&self, name: &str) -> Option<Rc<RefCell<Role<'a>>>> {
        for r in self.roles.iter() {
            if r.as_ref().borrow().name == name {
                return Some(r.to_owned());
            }
        }
        None
    }

    pub fn get_roles_names(&self) -> HashSet<String> {
        let mut set = HashSet::new();
        for r in self.roles.iter() {
            set.insert(r.as_ref().borrow().name.to_string());
        }
        set
    }
}

impl<'a> Role<'a> {
    pub fn new(name: String, roles: Option<Weak<RefCell<Roles<'a>>>>) -> Rc<RefCell<Role<'a>>> {
        Rc::new(
            Role {
                roles,
                name,
                users: Vec::new(),
                groups: Vec::new(),
                tasks: Vec::new(),
                options: None,
            }
            .into(),
        )
    }
    pub fn get_task_from_index(&self, index: &usize) -> Option<Rc<RefCell<Task<'a>>>> {
        if self.tasks.len() > *index {
            return Some(self.tasks[*index].to_owned());
        }
        None
    }
    pub fn get_users_info(&self) -> String {
        let mut users_info = String::new();
        users_info.push_str(&format!(
            "Users:\n({})\n",
            self.users
                .to_owned()
                .into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        ));
        users_info
    }
    pub fn get_groups_info(&self) -> String {
        let mut groups_info = String::new();
        groups_info.push_str(&format!(
            "Groups:\n({})\n",
            self.groups
                .to_owned()
                .into_iter()
                .map(|x| x.join(" & ").to_string())
                .collect::<Vec<String>>()
                .join(")\n(")
        ));
        groups_info
    }
    pub fn get_tasks_info(&self) -> String {
        let mut tasks_info = String::new();
        tasks_info.push_str(&format!(
            "Tasks:\n{}\n",
            self.tasks
                .to_owned()
                .into_iter()
                .map(|x| x.as_ref().borrow().commands.join("\n"))
                .collect::<Vec<String>>()
                .join("\n")
        ));
        tasks_info
    }
    pub fn get_options_info(&self) -> String {
        let mut options_info = String::new();
        if let Some(o) = &self.options {
            options_info.push_str(&format!(
                "Options:\n{}",
                o.as_ref().borrow().get_description()
            ));
        }
        options_info
    }

    pub fn get_description(&self) -> String {
        let mut description = String::new();
        description.push_str(&self.get_users_info());
        description.push_str(&self.get_groups_info());
        description.push_str(&self.get_tasks_info());
        description.push_str(&self.get_options_info());
        description
    }

    pub fn remove_task(&mut self, id: IdTask) {
        let mut tasks = self.tasks.to_owned();
        tasks.retain(|x| x.as_ref().borrow().id != id);
        self.tasks = tasks;
    }
}

impl<'a> Task<'a> {
    pub fn new(id: IdTask, role: Weak<RefCell<Role<'a>>>) -> Rc<RefCell<Task<'a>>> {
        Rc::new(
            Task {
                role,
                id,
                options: None,
                commands: Vec::new(),
                capabilities: None,
                setuid: None,
                setgid: None,
                purpose: None,
            }
            .into(),
        )
    }
    pub fn get_parent(&self) -> Option<Rc<RefCell<Role<'a>>>> {
        self.role.upgrade()
    }

    pub fn get_description(&self) -> String {
        let mut description = String::new();

        if let Some(p) = &self.purpose {
            description.push_str(&format!("Purpose :\n{}\n", p));
        }

        if let Some(caps) = self.capabilities.to_owned() {
            description.push_str(&format!("Capabilities:\n({})\n", caps.to_string()));
        }
        if let Some(setuid) = self.setuid.to_owned() {
            description.push_str(&format!("Setuid:\n({})\n", setuid));
        }
        if let Some(setgid) = self.setgid.to_owned() {
            description.push_str(&format!("Setgid:\n({})\n", setgid.join(" & ")));
        }

        if let Some(options) = self.options.to_owned() {
            description.push_str(&format!(
                "Options:\n({})\n",
                options.as_ref().borrow().get_description()
            ));
        }

        description.push_str(&format!(
            "Commands:\n{}\n",
            self.commands
                .iter()
                .map(|s| {
                    if s.len() < 64 {
                        return s.to_owned();
                    }else {
                        let mut  s = s.to_owned().chars().take(64).collect::<String>();
                        s.push_str("...");
                        s
                    }
                    
                })
                .fold(String::new(), |acc, x| acc + &format!("{}\n", x))
        ));
        description
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
        task.push_str(">");
        if self.purpose.is_some() {
            task.push_str(&format!(
                "<purpose>{}</purpose>",
                self.purpose.as_ref().unwrap()
            ));
        }
        task.push_str(
            &self
                .commands
                .to_owned()
                .into_iter()
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
        role.push_str(">");
        if self.users.len() > 0 || self.groups.len() > 0 {
            role.push_str("<actors>\n");
            role.push_str(
                &self
                    .users
                    .to_owned()
                    .into_iter()
                    .map(|x| format!("<user name=\"{}\"/>\n", x))
                    .collect::<Vec<String>>()
                    .join(""),
            );
            role.push_str(
                &self
                    .groups
                    .to_owned()
                    .into_iter()
                    .map(|x| format!("<groups names=\"{}\"/>\n", x.join(",")))
                    .collect::<Vec<String>>()
                    .join(""),
            );
            role.push_str("</actors>\n");
        }

        role.push_str(
            &self
                .tasks
                .to_owned()
                .into_iter()
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

pub fn read_file(file_path: &str, contents: &mut String) -> Result<(), Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    file.read_to_string(contents)?;
    Ok(())
}

pub fn read_xml_file<'a>(file_path: &'a str) -> Result<Package, Box<dyn Error>> {
    let mut contents = String::new();
    read_file(file_path, &mut contents)?;
    Ok(parser::parse(&contents)?)
}

pub fn sxd_sanitize(element: &mut str) -> String {
    element
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;")
}

// get groups names from comma separated list in attribute "names"
pub fn get_groups(node: Element) -> Groups {
    node.attribute("names")
        .expect("Unable to retrieve group names")
        .value()
        .split(',')
        .map(|s| s.to_string())
        .collect()
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

fn toggle_lock_config(file: &str, lock: bool) -> Result<(), String> {
    let file = match File::open(file) {
        Err(e) => return Err(e.to_string()),
        Ok(f) => f,
    };
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if lock {
        val &= !(FS_IMMUTABLE_FL);
    } else {
        val |= FS_IMMUTABLE_FL;
    }
    if unsafe { ioctl(fd, FS_IOC_SETFLAGS, &mut val) } < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn foreach_element<F>(element: Element, mut f: F) -> Result<(), Box<dyn Error>>
where
    F: FnMut(ChildOfElement) -> Result<(), Box<dyn Error>>,
{
    for child in element.children() {
        if let Some(_) = child.element() {
            f(child)?;
        }
    }
    Ok(())
}

fn do_in_main_element<F>(doc: Document, name: &str, mut f: F) -> Result<(), Box<dyn Error>>
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

pub trait Save {
    fn save(&self, doc: Option<&Document>, element: Option<&Element>) -> Result<bool, Box<dyn Error>>;
}

impl<'a> Save for Roles<'a> {
    fn save(&self, doc: Option<&Document>, element: Option<&Element>) -> Result<bool, Box<dyn Error>> {
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
                                    if role.as_ref().borrow().save(doc.into(), Some(&role_element))? {
                                        edited = true;
                                    }
                                } else {
                                    role_element.remove_from_parent();
                                }
                                rolesnames.remove(&rolename.to_string());
                            }
                            Ok(())
                        })?;
                        if rolesnames.len() > 0 {
                            edited = true;
                        }
                        for rolename in rolesnames {
                            let role = self.get_role(&rolename).unwrap();
                            let role_element = doc.create_element("role");
                            role_element.set_attribute_value("name", &rolename);
                            role.as_ref().borrow().save(doc.into(), Some(&role_element))?;
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
    fn save(&self, doc: Option<&Document>, element: Option<&Element>) -> Result<bool, Box<dyn Error>> {
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
                                            .split(",")
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
                        if users.len() > 0 || groups.len() > 0 {
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
    fn save(&self, doc: Option<&Document>, element: Option<&Element>) -> Result<bool, Box<dyn Error>> {
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
            element.set_attribute_value("setuser", setuid.to_string().as_str());
        } else if element.attribute_value("setuser").is_some() {
            element.remove_attribute("setuser");
        }
        if let Some(setgid) = self.setgid.to_owned() {
            element.set_attribute_value("setgroups", setgid.join(",").to_string().as_str());
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
                            .and_then(|o| Some(o.as_ref().borrow().save(doc.into(), Some(&child_element))))
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
        if commands.len() > 0 {
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
    fn save(&self, _doc: Option<&Document>, element: Option<&Element>) -> Result<bool, Box<dyn Error>> {
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
                        } else if child_element.children().iter().fold(String::new(), |acc, c| {
                            acc + match c.text() {
                                Some(t) => t.text(),
                                None => "",
                            }
                        }) != *self.path.as_ref().unwrap()
                        {
                            child_element.set_text(self.path.as_ref().unwrap());
                            edited = true;
                        }
                    }
                    "env_whitelist" => {
                        if self.env_whitelist.is_none() {
                            child_element.remove_from_parent();
                            edited = true;
                        } else if child
                            .text()
                            .ok_or::<Box<dyn Error>>(
                                "Unable to retrieve env_whitelist Text".into(),
                            )?
                            .text()
                            .to_string()
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
                        } else if child
                            .text()
                            .ok_or::<Box<dyn Error>>(
                                "Unable to retrieve env_checklist Text".into(),
                            )?
                            .text()
                            .to_string()
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
                        } else if child.text().unwrap().text().to_string()
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
    fn save(&self, _doc: Option<&Document>, _element: Option<&Element>) -> Result<bool, Box<dyn Error>> {
        let path = "/etc/security/rootasrole.xml";
        let package = read_xml_file(path)?;
        let doc = package.as_document();
        let element = doc.root().children().first().unwrap().element().unwrap();
        if self.roles.as_ref().borrow().save(Some(&doc), Some(&element))? {
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

        return Ok(true);
    }
}
