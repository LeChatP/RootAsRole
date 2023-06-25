use std::{
    borrow::{BorrowMut, Borrow},
    cell::RefCell,
    error::Error,
    fs::{self, File},
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
use sxd_xpath::{Context, Factory, Value};
use tracing::warn;

use libc::{c_int, c_ulong, ioctl, FILE};

use crate::{
    capabilities::Caps,
    options::{Level, Opt},
    version::{DTD, PACKAGE_VERSION},
};

const FS_IOC_GETFLAGS: c_ulong = 0x80086601;
const FS_IOC_SETFLAGS: c_ulong = 0x40086602;
const FS_IMMUTABLE_FL: c_int = 0x00000010;

pub const FILENAME: &str = "/etc/security/rootasrole.xml";

pub type Groups = Vec<String>;

pub trait ToXml {
    fn to_xml_string(&self) -> String;
}

#[derive(Clone, Debug)]
pub enum IdTask {
    Name(String),
    Number(usize),
}

impl IdTask {
    pub fn is_some(&self) -> bool {
        match self {
            IdTask::Name(s) => !s.is_empty(),
            IdTask::Number(n) => *n != 0,
        }
    }

    pub fn as_ref(&self) -> &IdTask {
        self
    }

    pub fn unwrap(&self) -> &str {
        match self {
            IdTask::Name(s) => s.as_str(),
            IdTask::Number(_) => panic!("Called `unwrap()` on an `IdTask::Number` value"),
        }
    }
}

impl ToString for IdTask {
    fn to_string(&self) -> String {
        match self {
            IdTask::Name(s) => s.to_string(),
            IdTask::Number(n) => format!("Task #{}",n.to_string()),
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
    pub fn new(version : &str) -> Rc<RefCell<Roles>> {
        Rc::new(Roles {
            roles: Vec::new(),
            options: None,
            version: version,
        }.into())
    }

    pub fn get_role(&self, name: &str) -> Option<Rc<RefCell<Role<'a>>>> {
        for r in self.roles.iter() {
            if r.as_ref().borrow().name == name {
                return Some(r.to_owned());
            }
        }
        None
    }
}

impl<'a> Role<'a> {
    pub fn new(name: String, roles : Option<Weak<RefCell<Roles<'a>>>>) -> Rc<RefCell<Role<'a>>> {
        Rc::new(Role {
            roles,
            name,
            users: Vec::new(),
            groups: Vec::new(),
            tasks: Vec::new(),
            options: None,
        }.into())
    }
    pub fn set_parent(&mut self, roles: Weak<RefCell<Roles<'a>>>) {
        self.roles = Some(roles);
    }
    pub fn get_task(&self, id: &IdTask) -> Option<Rc<RefCell<Task<'a>>>> {
        for t in self.tasks.iter() {
            //test if they are in same enum
            if t.as_ref().borrow().id == *id {
                return Some(t.to_owned());
            }
        }
        None
    }
    pub fn get_parent(&self) -> Option<Rc<RefCell<Roles<'a>>>> {
        match &self.roles {
            Some(r) => r.upgrade(),
            None => None,
        }
    }
    pub fn get_users_info(&self) -> String {
        let mut users_info = String::new();
        users_info.push_str(&format!("Users:\n({})\n", self.users.join(", ")));
        users_info
    }
    pub fn get_groups_info(&self) -> String {
        let mut groups_info = String::new();
        groups_info.push_str(&format!("Groups:\n({})\n", self.groups.to_owned().into_iter().map(|x| x.join(" & ").to_string()).collect::<Vec<String>>().join(")\n(")));
        groups_info
    }
    pub fn get_tasks_info(&self) -> String {
        let mut tasks_info = String::new();
        tasks_info.push_str(&format!("Tasks:\n{}", self.tasks.to_owned().into_iter().map(|x| x.as_ref().borrow().commands.join("\n")).collect::<Vec<String>>().join("\n")));
        tasks_info
    }
    pub fn get_description(&self) -> String {
        let mut description = String::new();
        description.push_str(&self.get_users_info());
        description.push_str(&self.get_groups_info());
        description.push_str(&self.get_tasks_info());
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
        Rc::new(Task {
            role,
            id,
            options: None,
            commands: Vec::new(),
            capabilities: None,
            setuid: None,
            setgid: None,
        }.into())
    }
    pub fn get_parent(&self) -> Option<Rc<RefCell<Role<'a>>>> {
        self.role.upgrade()
    }

    pub fn get_description(&self) -> String {
        let mut description = self.id.to_owned().to_string();
        if let Some(caps) = self.capabilities.to_owned() {
            description.push_str(&format!(
                "\nCapabilities:\n({})\n",
                caps.to_string()
            ));
        }
        if let Some(setuid) = self.setuid.to_owned() {
            description.push_str(&format!(
                "Setuid:\n({})\n",
                setuid
            ));
        }
        if let Some(setgid) = self.setgid.to_owned() {
            description.push_str(&format!(
                "Setgid:\n({})\n",
                setgid.join(" & ")
            ));
        }
        
        if let Some(options) = self.options.to_owned() {
            description.push_str(&format!(
                "Options:\n({})\n",
                options.as_ref().borrow().to_string()
            ));
        }
        
        description.push_str(&format!("Commands:\n{}\n", self.commands.join("\n")));
        description
    }

}

impl<'a> ToXml for Task<'a> {
    fn to_xml_string(&self) -> String {
        let mut task = String::from("<task ");
        if self.id.is_some() {
            task.push_str(&format!("id=\"{}\" ", self.id.as_ref().unwrap()));
        }
        if self.capabilities.is_some() {
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

pub fn read_file(file_path: &str, contents : &mut String) -> Result<(), Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    file.read_to_string(contents)?;
    Ok(())
}


pub fn read_xml_file<'a>(file_path: &'a str) -> Result<Package, Box<dyn Error>> {
    let mut contents = String::new();
    read_file(file_path, &mut contents)?;
    Ok(parser::parse(&contents)?)
}
/**
fn read_xml_file<'a>(file_path: &'a str, document : &Option<Document<'a>>) -> Result<(), Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let package = parser::parse(&contents)?;
    document = Some(package.as_document());
    Ok(())
}*/


fn set_immuable(path: &str, immuable: bool) -> Result<(), std::io::Error> {
    let metadata = fs::metadata(path).expect("Unable to retrieve file metadata");
    let mut permissions = metadata.permissions();
    permissions.set_readonly(immuable);
    fs::set_permissions(path, permissions)?;
    Ok(())
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
fn get_groups(node: Element) -> Groups {
    node.attribute("names")
        .expect("Unable to retrieve group names")
        .value()
        .split(',')
        .map(|s| s.to_string())
        .collect()
}

fn is_enforced(node: Element) -> bool {
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
            println!("{}", elem.name().local_part());
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
                    .into()
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
                    .into()
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
                    .into()
                }
                "allow-root" => options.no_root = Some(is_enforced(elem)).into(),
                "allow-bounding" => options.bounding = Some(is_enforced(elem)).into(),
                "wildcard-denied" => options.wildcard_denied = Some(
                    elem.children()
                        .first()
                        .unwrap()
                        .text()
                        .expect("Cannot read Checklist option")
                        .text()
                        .to_string()),
                _ => warn!("Unknown option: {}", elem.name().local_part()),
            }
        }
    }
    rc_options
}

fn get_task<'a>(role: &Rc<RefCell<Role<'a>>>, node: Element, i: usize) -> Result<Rc<RefCell<Task<'a>>>, Box<dyn Error>> {
    let task = Task::new(IdTask::Number(i), Rc::downgrade(role));
    if let Some(id) = node.attribute_value("id") {
        task.as_ref().borrow_mut().id = IdTask::Name(id.to_string());
    }
    task.as_ref().borrow_mut().capabilities = match node.attribute_value("capabilities") {
        Some(cap) => Some(cap.into()).into(),
        None => None.into(),
    };
    for child in node.children() {
        if let Some(elem) = child.element() {
            println!("{}", elem.name().local_part());
            match elem.name().local_part() {
                "command" => task.as_ref().borrow_mut().commands.push(
                    elem.children()
                        .first()
                        .ok_or("Unable to get text from command")?
                        .text()
                        .map(|f| f.text().to_string())
                        .ok_or("Unable to get text from command")?
                        .into(),
                ),
                "options" => {
                    task.as_ref().borrow_mut().options = Some(Rc::new(get_options(Level::Task, elem).into()));
                }
                _ => warn!("Unknown element: {}", elem.name().local_part()),
            }
        }
    }
    Ok(task)
}

fn add_actors(role : &mut Role, node: Element) -> Result<(), Box<dyn Error>> {
    for child in node.children() {
        if let Some(elem) = child.element() {
            println!("{}", elem.name().local_part());
            match elem.name().local_part() {
                "user" => role.users.push(
                    elem
                        .attribute_value("name")
                        .ok_or("Unable to retrieve user name")?
                        .to_string()
                        .into(),
                ),
                "group" => role.groups.push(get_groups(elem).into()),
                _ => warn!("Unknown element: {}", elem.name().local_part()),
            }
        }
    }
    Ok(())
}

fn get_role<'a>(element: Element, roles: Option<Rc<RefCell<Roles<'a>>>>) -> Result<Rc<RefCell<Role<'a>>>, Box<dyn Error>> {
    let rc_role = Role::new(
        element.attribute_value("name").unwrap().to_string().into(),
        match roles {
            Some(roles) => Some(Rc::downgrade(&roles)),
            None => None,
        }
    );
    
    let mut i: usize = 0;
    for child in element.children() {
        let mut role = rc_role.as_ref().borrow_mut();
        if let Some(element) = child.element() {
            match element.name().local_part() {
                "actors" => add_actors(&mut role, element)?,
                "task" => {
                    i += 1;
                    role.tasks
                        .push(get_task(&rc_role, element, i)?)
                }
                "options" => {
                    role.options = Some(Rc::new(get_options(Level::Role, element).into())).into()
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
    Ok(rc_role)
}
#[allow(dead_code)]
pub fn find_role<'a>(doc : &'a Document, name:&'a str) -> Result<Rc<RefCell<Role<'a>>>,Box<dyn Error>>{
    let factory = Factory::new();
    let context = Context::new();
    let xpath = factory.build(&format!("//role[@name='{}']", name))?;
    let value = xpath.unwrap().evaluate(&context, doc.root())?;
    if let Value::Nodeset(nodes) = value {
        if nodes.size() != 0 {
            let role_element = nodes
                .iter()
                .next()
                .expect("Unable to retrieve element")
                .element()
                .expect("Unable to convert role node to element");
            return get_role(role_element, None);
        }
    }
    Err("Role not found".into())
}

pub fn load_roles<'a>(filename : &str) -> Result<Rc<RefCell<Roles<'a>>>, Box<dyn Error>> {
        let package = read_xml_file(filename).expect("Failed to read xml file");
        let doc = package.as_document();
        let rc_roles = Roles::new(PACKAGE_VERSION);
        {
        let mut roles = rc_roles.as_ref().borrow_mut();
        for child in doc.root().children() {
            if let Some(element) = child.element() {
                if element.name().local_part() == "rootasrole" {
                   
                    for role in element.children() {
                        if let Some(element) = role.element() {
                            if element.name().local_part() == "roles" {
                                for role in element.children() {
                                    if let Some(element) = role.element() {
                                        if element.name().local_part() == "role" {
                                            roles.roles.push(
                                                get_role(element,Some(rc_roles.to_owned()))?);
                                        }
                                    }
                                }
                            }
                            if element.name().local_part() == "options" {
                                roles.options =
                                    Some(Rc::new(get_options(Level::Global, element).into()));
                            }
                        }
                    }
                    return Ok(rc_roles.to_owned());
                }
            }
        }
    }
    Err("Unable to find rootasrole element".into())
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
    fn save(&self, path: &str) -> Result<bool, Box<dyn Error>>;
}

impl<'a> Save for Roles<'a> {
    fn save(&self, path: &str) -> Result<bool, Box<dyn Error>> {
        let binding = parser::parse(&self.to_xml_string())?;
        let new_roles = binding.as_document();
        let new_xml_element = new_roles
            .root()
            .children()
            .first()
            .expect("Unable to retrieve element")
            .element()
            .expect("Unable to convert to element");
        println!("Saving roles: {:?}", &self);
        let mut contents = String::new();
        read_file(path,&mut contents)?;
        let doc = parser::parse(&contents)?;
        let doc = doc.as_document();
        do_in_main_element(doc, "rootasrole", |element| {
            element.element().replace(new_xml_element);
            Ok(())
        })?;
        let mut content: Vec<u8> = Vec::new();
        let writer = Writer::new().set_single_quotes(false);
        writer
            .format_document(&doc, &mut content)
            .expect("Unable to write file");
        let mut content = String::from_utf8(content).expect("Unable to convert to string");
        content.insert_str(content.match_indices("?>").next().unwrap().0 + 2, DTD);
        toggle_lock_config(path, true).expect("Unable to remove immuable");
        let mut file = File::options()
            .write(true)
            .truncate(true)
            .open(FILENAME)
            .expect("Unable to create file");
        file.write_all(content.as_bytes())
            .expect("Unable to write file");
        toggle_lock_config(path, false).expect("Unable to set immuable");
        Ok(true)
    }
}

impl<'a> Save for Role<'a> {
    fn save(&self, path: &str) -> Result<bool, Box<dyn Error>> {
        let binding = parser::parse(&self.to_xml_string())?;
        let new_role = binding.as_document();
        let mut contents = String::new();
        read_file(path,&mut contents)?;
        let doc = parser::parse(&contents)?;
        let doc = doc.as_document();
        let mut found = false;
        do_in_main_element(doc, "rootasrole", |rootelement| {
            foreach_element(rootelement.element().unwrap(), |element| {
                if element_is_role(&element, self.name.to_owned()) {
                    let new_xml_element = new_role
                        .root()
                        .children()
                        .first()
                        .expect("Unable to retrieve element")
                        .element()
                        .expect("Unable to convert to element");
                    element.element().replace(new_xml_element);
                    found = true;
                }
                Ok(())
            })?;
            Ok(())
        })?;
        if !found {
            return Ok(false);
        }
        save_in_file(doc, path);
        Ok(true)
    }
}

impl<'a> Save for Task<'a> {
    fn save(&self, path: &str) -> Result<bool, Box<dyn Error>> {
        let binding = parser::parse(&self.to_xml_string())?;
        let new_task = binding.as_document();
        let mut contents = String::new();
        read_file(path,&mut contents)?;
        let doc = parser::parse(&contents)?;
        let doc = doc.as_document();
        let mut found = false;
        do_in_main_element(doc, "rootasrole", |rootelement| {
            self.save_task_roles(rootelement, new_task, &mut found)
        })?;
        if !found {
            return Ok(false);
        }
        save_in_file(doc, path);
        Ok(true)
    }
}
impl<'a> Task<'a> {
    fn save_task_roles(&self, rootelement: ChildOfRoot, new_task: Document, found: &mut bool) -> Result<(),Box<dyn Error>> {
        if let Some(rootelement) = rootelement.element() {
            foreach_element(rootelement, |rolelayer| {
                if element_is_role(&rolelayer, self.get_parent().unwrap().try_borrow()?.name.to_owned()) {
                    return self.save_task_role(rolelayer, new_task, found);
                }
                Ok(())
            })?;
        }
        Ok(())
    }

    fn save_task_role(&self, rolelayer: ChildOfElement, new_task: Document, found: &mut bool) -> Result<(), Box<dyn Error>> {
        let mut taskid = 1;
        foreach_element(rolelayer.element().unwrap(), |task_layer| {
            if element_is_task(&task_layer) {
                let new_xml_element = new_task
                    .root()
                    .children()
                    .first()
                    .expect("Unable to retrieve element")
                    .element()
                    .expect("Unable to convert to element");
                let mut id = (taskid + 1).to_string();
                if task_layer.element().unwrap().attribute("id").is_some() {
                    id = task_layer
                        .element()
                        .unwrap()
                        .attribute_value("id")
                        .unwrap()
                        .to_string();
                } else {
                    taskid += 1;
                }
                if id == self.id.to_owned().unwrap() {
                    task_layer.element().replace(new_xml_element);
                    *found = true;
                }
            }
            Ok(())
        })
    }
}

fn element_is_role(element: &ChildOfElement, name: String) -> bool {
    if let Some(element) = element.element() {
        if element.name().local_part() == "role" {
            if let Some(attr) = element.attribute("name") {
                return attr.value().to_string() == name;
            }
        }
    }
    false
}

fn element_is_task(element: &ChildOfElement) -> bool {
    if let Some(element) = element.element() {
        if element.name().local_part() == "task" {
            return true;
        }
    }
    false
}

fn save_in_file(doc: Document, path: &str) {
    let mut content: Vec<u8> = Vec::new();
    let writer = Writer::new().set_single_quotes(false);
    writer
        .format_document(&doc, &mut content)
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

pub fn save_options(
    options: &Opt,
    path: &str,
    role_name: Option<String>,
    task_id: Option<String>,
) -> Result<bool, Box<dyn Error>> {
    let binding = parser::parse(&options.to_string())?;
    let new_options = binding.as_document();
    let mut contents = String::new();
    read_file(path,&mut contents)?;
    let doc = parser::parse(&contents)?;
    let doc = doc.as_document();
    let mut found = false;
    do_in_main_element(doc, "rootasrole", |rootelement| {
        if let Some(role_name) = role_name.to_owned() {
            save_option_roles(
                rootelement,
                role_name,
                task_id.to_owned(),
                new_options,
                &mut found,
            )?
        } else {
            save_option_xml_layer(rootelement.into(), new_options, &mut found)?
        }
        Ok(())
    })?;
    if !found {
        return Ok(false);
    }
    save_in_file(doc, path);
    Ok(true)
}

fn save_option_roles(
    rootelement: ChildOfRoot,
    role_name: String,
    task_id: Option<String>,
    new_options: Document,
    found: &mut bool,
) -> Result<(), Box<dyn Error>> {
    foreach_element(rootelement.element().unwrap(), |role_layer| {
        if element_is_role(&role_layer, role_name.to_owned()) {
            if let Some(task_id) = task_id.to_owned() {
                save_option_task(role_layer, task_id, new_options, found)?;
            } else {
                save_option_xml_layer(role_layer, new_options, found)?;
            }
        }
        Ok(())
    })?;
    Ok(())
}

fn save_option_task(
    role_layer: ChildOfElement,
    task_id: String,
    new_options: Document,
    found: &mut bool,
) -> Result<(), Box<dyn Error>> {
    let mut tmp_taskid = 1;
    foreach_element(role_layer.element().unwrap(), |task_layer| {
        if element_is_task(&task_layer) {
            let mut id = (tmp_taskid + 1).to_string();
            if task_layer.element().unwrap().attribute("id").is_some() {
                id = task_layer
                    .element()
                    .ok_or("Unable to get element")?
                    .attribute_value("id")
                    .ok_or("Unable to get attribute value")?
                    .to_string();
            } else {
                tmp_taskid += 1;
            }
            if id == task_id.to_owned() {
                save_option_xml_layer(task_layer, new_options, found)?;
            }
        }
        Ok(())
    })
}

fn element_is_options(element: &ChildOfElement) -> bool {
    if let Some(element) = element.element() {
        if element.name().local_part() == "options" {
            return true;
        }
    }
    false
}

fn save_option_xml_layer(task_layer: ChildOfElement, new_options: Document, found: &mut bool) -> Result<(), Box<dyn Error>> {
    foreach_element(task_layer.element().unwrap(), |option_level| {
        if element_is_options(&option_level) {
            replace_element(new_options, option_level, found)?
        }
        Ok(())
    })
}

fn replace_element(new_options: Document, element: ChildOfElement, found: &mut bool) -> Result<(), Box<dyn Error>> {
    let new_xml_element = new_options
        .root()
        .children()
        .first()
        .ok_or("Unable to retrieve element")?
        .element()
        .ok_or("Unable to convert to element")?;
    element.element().replace(new_xml_element);
    *found = true;
    Ok(())
}
