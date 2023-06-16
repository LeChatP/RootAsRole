
use std::{fs::{File, self}, io::{Read, self, Write}, ops::{Index}, cell::{Cell, RefCell}, os::fd::AsRawFd, borrow::{Borrow, BorrowMut}, rc::Rc };

use sxd_document::{dom::{Document, Element}, Package, parser, writer::Writer };
use sxd_xpath::{Factory, Context, Value};
use tracing::warn;

use libc::{ioctl, c_int, c_ulong};

use crate::{capabilities::Caps, options::{Opt, Level}, version::{PACKAGE_VERSION, DTD}};

pub type Groups= Vec<String>;
const FS_IOC_GETFLAGS: c_ulong = 0x80086601;
const FS_IOC_SETFLAGS: c_ulong = 0x40086602;
const FS_IMMUTABLE_FL: c_int = 0x00000010;

#[derive(Clone,Debug)]
pub struct Commands{
    pub id: Option<String>,
    pub options: Option<Rc<RefCell<Opt>>>,
    pub commands: Vec<String>,
    pub capabilities: Option<Caps>,
    pub setuid: Option<String>,
    pub setgid: Option<Groups>,
}

#[derive(Debug)]
pub struct Role{
    pub name: String,
    pub priority: Option<i32>,
    pub users: Vec<String>,
    pub groups: Vec<Groups>,
    pub commands: Vec<Rc<RefCell<Commands>>>,
    pub options: Option<Rc<RefCell<Opt>>>,
}

#[derive(Debug)]
pub struct Roles{
    pub roles: Vec<Rc<RefCell<Role>>>,
    pub options: Option<Rc<RefCell<Opt>>>,
    pub version: String,
}

impl Roles {
    pub fn new() -> Roles {
        Roles {
            roles: Vec::new().into(),
            options: None.into(),
            version: PACKAGE_VERSION.to_string(),
        }
    }
}


impl Role {
    pub fn new() -> Role {
        Role {
            name: String::new().into(),
            users: Vec::new().into(),
            groups: Vec::new().into(),
            commands: Vec::new().into(),
            options: None.into(),
            priority: None.into(),
        }
    }
    pub fn get_users_info(&self) -> String {
        let mut users_info = String::new();
        users_info.push_str(&format!("Users:\n({})\n", self.users.join(", ")));
        users_info
    }
    pub fn get_groups_info(&self) -> String {
        let mut groups_info = String::new();
        groups_info.push_str(&format!("Groups:\n({})\n", self.groups.clone().into_iter().map(|x| x.join(" & ").to_string()).collect::<Vec<String>>().join(")\n(")));
        groups_info
    }
    pub fn get_commands_info(&self) -> String {
        let mut commands_info = String::new();
        commands_info.push_str(&format!("Commands:\n{}", self.commands.clone().into_iter().map(|x| x.as_ref().borrow().commands.join("\n")).collect::<Vec<String>>().join("\n")));
        commands_info
    }
    pub fn get_description(&self) -> String {
        let mut description = String::new();
        description.push_str(&self.get_users_info());
        description.push_str(&self.get_groups_info());
        description.push_str(&self.get_commands_info());
        description
    }
}

impl Commands {
    pub fn new() -> Commands {
        Commands {
            id: None.into(),
            options: None.into(),
            commands: Vec::new().into(),
            capabilities: None.into(),
            setuid: None.into(),
            setgid: None.into(),
        }
    }
}

impl ToString for Commands {
    fn to_string(&self) -> String {
        let mut commands = String::from("<commands ");
        if self.id.is_some() {
            commands.push_str(&format!("id=\"{}\" ", self.id.as_ref().unwrap()));
        }
        if self.capabilities.is_some() {
            commands.push_str(&format!("capabilities=\"{}\" ", self.capabilities.clone().unwrap().to_string().to_lowercase()));
        }
        commands.push_str(">");
        commands.push_str(&self.commands.clone().into_iter().map(|x| format!("<command>{}</command>", x)).collect::<Vec<String>>().join(""));
        commands.push_str("</commands>");
        commands
    }
}

impl ToString for Role {
    fn to_string(&self) -> String {
        let mut role = String::from("<role ");
        role.push_str(&format!("name=\"{}\" ", self.name));
        if self.priority.is_some() {
            role.push_str(&format!("priority=\"{}\" ", self.priority.unwrap()));
        }
        role.push_str(">");
        role.push_str(&self.users.clone().into_iter().map(|x| format!("<user name=\"{}\"/>", x)).collect::<Vec<String>>().join(""));
        role.push_str(&self.groups.clone().into_iter().map(|x| format!("<groups names=\"{}\"/>", x.join(","))).collect::<Vec<String>>().join(""));
        role.push_str(&self.commands.clone().into_iter().map(|x| x.as_ref().borrow().to_string()).collect::<Vec<String>>().join(""));
        role.push_str("</role>");
        role
    }
}

impl ToString for Roles {
    fn to_string(&self) -> String {
        
        let mut roles = String::from("<rootasrole ");
        roles.push_str(&format!("version=\"{}\">", self.version));
        if let Some(options) = self.options.clone() {
            roles.push_str(&format!("<options>{}</options>", options.as_ref().borrow().to_string()));
        }
        roles.push_str("<roles>");
        roles.push_str(&self.roles.iter().map(|x| x.as_ref().borrow().to_string()).collect::<Vec<String>>().join(""));
        roles.push_str("</roles></rootasrole>");
        roles
    }
}

impl AsRef<Commands> for Commands {
    fn as_ref(&self) -> &Commands{
        self
    }
}

impl AsRef<Role> for Role {
    fn as_ref(&self) -> &Role{
        self
    }
}

impl AsRef<Roles> for Roles {
    fn as_ref(&self) -> &Roles{
        self
    }
}

fn read_xml_file(filename: &str) -> Result<Package, String> {
    // Ouvrez le fichier en lecture
    let mut file = File::open(filename).map_err(|e| e.to_string())?;

    // Lisez le contenu du fichier dans une chaîne de caractères
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| e.to_string())?;

    // Utilisez la fonction parse de la librairie sxd_document pour analyser la chaîne XML
    let package = parser::parse(&contents).map_err(|e| e.to_string())?;
    Ok(package)
}

fn set_immuable(path : &str, immuable : bool) -> Result<(), std::io::Error> {
    let metadata = fs::metadata(path).expect("Unable to retrieve file metadata");
    let mut permissions = metadata.permissions();
    permissions.set_readonly(immuable);
    fs::set_permissions(path, permissions)?;
    Ok(())
} 

pub fn sxd_sanitize(element : &mut str) -> String {
    element.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;")
}

// get groups names from comma separated list in attribute "names"
fn get_groups(node : Element) -> Groups {
    node.attribute("names").expect("Unable to retrieve group names").value().split(',').map(|s| s.to_string()).collect()
}

fn is_enforced(node : Element) -> bool {
    let enforce = node.attribute("enforce");
    (enforce.is_some() && enforce.expect("Unable to retrieve enforce attribute").value() == "true") || enforce.is_none()
}

fn get_options(level: Level, node : Element) -> Opt {
    let mut rc_options = Opt::new(level);
    
    for child in node.children() {
        let mut options = rc_options.borrow_mut();
        if let Some(elem) = child.element(){
            println!("{}", elem.name().local_part());
            match elem.name().local_part() {
                "path" => options.path = Some(elem.children().first().unwrap().text().expect("Cannot read PATH option").text().to_string()).into(),
                "env-keep" => options.env_whitelist = Some(elem.children().first().unwrap().text().expect("Cannot read Whitelist option").text().to_string()).into(),
                "env-check" => options.env_checklist = Some(elem.children().first().unwrap().text().expect("Cannot read Checklist option").text().to_string()).into(),
                "allow-root" => options.no_root = Some(is_enforced(elem)).into(),
                "allow-bounding" => options.bounding = Some(is_enforced(elem)).into(),
                _ => warn!("Unknown option: {}", elem.name().local_part()),
            }
        }
    }
    rc_options
}

fn get_commands(node : Element) -> Commands {
    let mut commands = Commands{
        id: match node.attribute_value("id") {
            Some(id) => Some(id.to_string()).into(),
            None => None.into(),
        },
        capabilities: match node.attribute_value("capabilities") {
            Some(cap) => Some(cap.into()).into(),
            None => None.into(),
        },
        options: None.into(),
        commands: Vec::new().into(),
        setuid: None.into(),
        setgid: None.into(),
    };
    for child in node.children() {
        if let Some(elem) = child.element(){
            println!("{}", elem.name().local_part());
            match elem.name().local_part() {
                "command" => commands.commands.push(elem.children().first().expect("Unable to get text from command").text().map(|f| f.text().to_string()).unwrap_or("".to_string()).into()),
                "options" => {
                    commands.options = Some(Rc::new(get_options(Level::Commands,elem).into()));
                },
                _ => warn!("Unknown element: {}", elem.name().local_part()),
            }
        }
    }
    commands
}

fn get_role(element : Element) -> Role {
    let mut role = Role{
        name: element.attribute_value("name").unwrap().to_string().into(),
        users: Vec::new().into(),
        groups: Vec::new().into(),
        commands: Vec::new().into(),
        options: None.into(),
        priority: match element.attribute_value("priority") {
            Some(prio) => Some(prio.to_string().parse::<i32>().expect("Unable to parse priority")).into(),
            None => None.into(),
        },
    };
    for child in element.children() {
        if let Some(element) = child.element(){
            match element.name().local_part() {
                "user" => role.users.push(element.attribute_value("name").expect("Unable to retrieve user name").to_string().into()),
                "group" => role.groups.push(get_groups(element).into()),
                "commands" => role.commands.push(Rc::new(get_commands(element).into())),
                "options" => role.options = Some(Rc::new(get_options(Level::Role, element).into())).into(),
                _ => warn!("Unknown element: {}", child.element().expect("Unable to convert unknown to element").name().local_part()),
            }
        }
    }
    role
}

fn find_role(doc : Document, name :&str) -> Option<Role> {
    let factory = Factory::new();
    let context = Context::new();
    let xpath = factory.build(&format!("//role[@name='{}']",name)).unwrap();
    let value = xpath.unwrap().evaluate(&context, doc.root()).unwrap();
    if let Value::Nodeset(nodes) = value {
        if nodes.size() != 0 {
            let role_element = nodes.iter().next().expect("Unable to retrieve element").element().expect("Unable to convert role node to element");
            return Some(get_role(role_element))
        }
    }
    None
}

pub(crate) fn load_role(name :&str) -> Option<Role> {
    let binding = read_xml_file("/etc/security/rootasrole.xml").expect("Unable to parse config file");
    let doc = binding.as_document();
    find_role(doc, name)
}

pub fn load_roles() -> Option<Roles> {
    
    let binding = read_xml_file("/etc/security/rootasrole.xml").expect("Unable to parse config file");
    let doc = binding.as_document();
    
    for child in doc.root().children() {
        if let Some(element) = child.element(){
            if element.name().local_part() == "rootasrole" {
                let mut rc_roles = Roles::new();
                for role in element.children() {
                    if let Some(element) = role.element(){
                        if element.name().local_part() == "roles" {
                            for role in element.children() {
                                if let Some(element) = role.element(){
                                    if element.name().local_part() == "role" {
                                        rc_roles.roles.push(Rc::new(get_role(element).into()));
                                    }
                                }
                            }
                        }
                        if element.name().local_part() == "options" {
                            rc_roles.options = Some(Rc::new(get_options(Level::Global, element).into()));
                        }
                    }
                }
                return Some(rc_roles)
            }
        }
    }
    None
}



fn toggle_lock_config(file:&str, lock: bool) -> Result<(),String> {
    let file = match File::open(file){
        Err(e) => return Err(e.to_string()),
        Ok(f) => f,
    };
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if lock  {
        val &= !(FS_IMMUTABLE_FL);
    } else {
        val |= FS_IMMUTABLE_FL;
    }
    if unsafe { ioctl(fd, FS_IOC_SETFLAGS, &mut val) } < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub(crate) fn save_all(roles: &Roles) {
    println!("Saving roles: {:?}", roles);
    let path = "/etc/security/rootasrole.xml";
    let pack = read_xml_file(path).expect("Unable to parse config file");
    let doc = pack.as_document();
    for child in doc.root().children() {
        if let Some(element) = child.element(){
            if element.name().local_part() == "rootasrole" {
                let string = &roles.to_string();
                let binding = parser::parse(string).expect("Unable to parse roles");
                let pack = binding.as_document();
                let element = pack.root().children().first().expect("Unable to retrieve element").element().expect("Unable to convert to element");
                child.element().replace(element);
            }
        }
    }
    let mut content:Vec<u8> = Vec::new();
    let writer = Writer::new().set_single_quotes(false);
    writer.format_document(&doc,&mut content).expect("Unable to write file");
    let mut content = String::from_utf8(content).expect("Unable to convert to string");
    content.insert_str(content.match_indices("?>").next().unwrap().0+2, DTD);
    toggle_lock_config(path, true).expect("Unable to remove immuable");
    let mut file = File::options().write(true).truncate(true).open("/etc/security/rootasrole.xml").expect("Unable to create file");
    file.write_all(content.as_bytes()).expect("Unable to write file");
    toggle_lock_config(path, false).expect("Unable to set immuable");

}