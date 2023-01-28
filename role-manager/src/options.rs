use std::{cell::RefCell, rc::Rc, borrow::BorrowMut};

use crate::config::{Roles,Role,Commands, self};

pub trait Optionnable {
    fn has_options(&self) -> bool;
    fn get_options(&self) -> Option<Rc<RefCell<Opt>>>;
    fn set_options(&mut self, opt: Option<Rc<RefCell<Opt>>>);
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    None,
    Default,
    Global,
    Role,
    Commands,
}

#[derive(Debug,Clone)]
pub enum OptType {
    Path,
    EnvWhitelist,
    EnvChecklist,
    NoRoot,
    Bounding,
    Setuid,
    Setgid,
}

pub enum OptValue {
    String(String),
    Bool(bool),
    Setuid((bool,String)),
}

impl ToString for OptValue {
    fn to_string(&self) -> String {
        match self {
            OptValue::String(s) => s.to_string(),
            OptValue::Bool(b) => b.to_string(),
            OptValue::Setuid((b,s)) => format!("{}{}",s,if *b {""} else {" (not enforced)"}),
        }
    }
}

impl OptType {
    pub fn item_list_str() -> Vec<(OptType,String)> {
        vec![
            (OptType::Path,String::from("Path")),
            (OptType::EnvWhitelist,String::from("Environment Whitelist")),
            (OptType::EnvChecklist,String::from("Environment Checklist")),
            (OptType::NoRoot,String::from("Enforce NoRoot")),
            (OptType::Bounding,String::from("Restrict with Bounding")),
            (OptType::Setuid,String::from("Change effective user")),
            (OptType::Setgid,String::from("Change effective group(s)")),
        ]
    }
}

#[derive(Debug,Clone)]
pub struct Opt{
    level : Level,
    pub path: RefCell<Option<String>>,
    pub env_whitelist: RefCell<Option<String>>,
    pub env_checklist: RefCell<Option<String>>,
    pub no_root: RefCell<Option<bool>>,
    pub bounding: RefCell<Option<bool>>,
    pub setuid: RefCell<Option<(bool,String)>>,
    pub setgid: RefCell<Option<(bool,String)>>,
}

impl AsRef<Opt> for Opt {
    fn as_ref(&self) -> &Opt{
        self
    }
}


fn attribute_str(key : &str, value : &str) -> String {
    format!("{}=\"{}\"",key,value)
}

fn enforce_item_str(item : &(bool,String)) -> String {
    if item.0 {
        String::new()
    } else {
        attribute_str("enforce",&item.0.to_string())
    }
}

fn user_item_str(item : &(bool,String)) -> String {
    if item.1.is_empty() {
        String::new()
    } else {
        attribute_str("user",&item.1)
    }
}

fn group_item_str(item : &(bool,String)) -> String {
    if item.1.is_empty() {
        String::new()
    } else {
        attribute_str("group",&item.1)
    }
}

fn setuser_str(item : &(bool,String)) -> String {
    if item.0 {
        String::new()
    } else {
        [enforce_item_str(item),user_item_str(item)].join(" ")
    }
}

fn setgroup_str(item : &(bool,String)) -> String {
    if item.0 {
        String::new()
    } else {
        [enforce_item_str(item),group_item_str(item)].join(" ")
    }
}

fn setuid_xml_str(setuser: Option<&(bool, String)>, setgroup: Option<&(bool, String)>) -> String {
    let mut str_setuser = String::from("<setuid ");
    if let (Some(setuser), Some(setgroup)) = (&setuser, &setgroup) {
        if setuser.0 == setgroup.0 {
            //<setuid enforce="false" user="root" group="root"/>
            str_setuser.push_str([enforce_item_str(setuser),user_item_str(setuser),group_item_str(setgroup)].join(" ").as_str());
        }else {
            //<setuid enforce="false" user="root"/><setuid enforce="true" group="root"/>
            str_setuser.push_str(&format!("{}/>{}{}", 
                setuser_str(setuser),
                str_setuser, setgroup_str(setgroup)));
        }
    }else if let Some(setuser) = &setuser {
        // <setuid enforce="false" user="root"/>
        str_setuser.push_str(&setuser_str(setuser));
    }else if let Some(setgroup) = &setgroup {
        // <setuid enforce="true" group="root"/>
        str_setuser.push_str(&setgroup_str(setgroup));
    }
    str_setuser.push_str("/>");
    str_setuser
}

impl ToString for Opt {
    
    fn to_string(&self) -> String {
        let mut content = String::new();
        if let Some(path) = self.path.borrow().as_ref() {
            content.push_str(&format!("<path>{}</path>",config::sxd_sanitize(path.clone().borrow_mut())));
        }
        if let Some(env_whitelist) = self.env_whitelist.borrow().as_ref() {
            content.push_str(&format!("<env-keep>{}</env-keep>",config::sxd_sanitize(env_whitelist.clone().borrow_mut())));
        }
        if let Some(env_checklist) = self.env_checklist.borrow().as_ref() {
            content.push_str(&format!("<env-check>{}</env-check>",config::sxd_sanitize(env_checklist.clone().borrow_mut())));
        }
        if let Some(no_root) = self.no_root.borrow().as_ref() {
            if no_root == &false {
                content.push_str(&format!("<allow-root enforce=\"{}\"/>",!no_root));
            }
        }
        if let Some(bounding) = self.bounding.borrow().as_ref() {
            if bounding == &false {
                content.push_str(&format!("<allow-bounding enforce=\"{}\"/>",!bounding));
            }
        }
        let binding = self.setuid.borrow();
        let setuser = binding.as_ref().clone();
        let binding = self.setgid.borrow();
        let setgroup = binding.as_ref().clone();
        if setuser.or(setgroup).is_some() {
            content.push_str(&setuid_xml_str(setuser, setgroup));
        }

        format!("<options>{}</options>",content)
    }
}




impl Default for Opt {
    fn default() -> Opt {
        Opt {
            level: Level::Default,
            path: Some("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin".to_string()).into(),
            env_whitelist: Some("HOME,USER,LOGNAME,COLORS,DISPLAY,HOSTNAME,KRB5CCNAME,LS_COLORS,PS1,PS2,XAUTHORY,XAUTHORIZATION,XDG_CURRENT_DESKTOP".to_string()).into(),
            env_checklist: Some("COLORTERM,LANG,LANGUAGE,LC_*,LINGUAS,TERM,TZ".to_string()).into(),
            no_root: Some(true).into(),
            bounding: Some(true).into(),
            setuid: None.into(),
            setgid: None.into(),
        }
    }
}

impl Opt {
    pub fn new(level: Level) -> Opt {
        Opt {
            level,
            path: None.into(),
            env_whitelist: None.into(),
            env_checklist: None.into(),
            no_root: None.into(),
            bounding: None.into(),
            setuid: None.into(),
            setgid: None.into(),
        }
    }

}

#[derive(Clone)]
pub struct OptStack {
    stack : [Option<Rc<RefCell<Opt>>>;Level::Commands as usize + 1],
}

impl Default for OptStack {
    fn default() -> OptStack {
        OptStack {
            stack: [None, Some(Rc::new(Opt::default().into())), None, None, None],
        }
    }
}

impl OptStack {
    pub fn from_commands(roles: &Roles, role : &Role, commands: &Commands) -> Self {
        let mut stack = OptStack::from_role(roles,role);
        if commands.has_options() {
            stack.set(commands.get_options().unwrap());
        }
        stack
    }
    pub fn from_role(roles: &Roles, role : &Role) -> Self {
        let mut stack = OptStack::from_roles(roles);
        if role.has_options() {
            stack.set(role.get_options().unwrap());
        }
        stack
    }
    pub fn from_roles(roles: &Roles) -> Self {
        let mut stack = OptStack::default();
        if roles.has_options() {
            stack.set(roles.get_options().unwrap());
        }
        stack
    }
    pub fn get_level(&self) -> Level {
        self.stack.iter().rev().find(|opt| opt.is_some()).unwrap().as_ref().unwrap().as_ref().borrow().level
    }
    pub fn set(&mut self, opt: Rc<RefCell<Opt>>) {
        let level = opt.as_ref().borrow().level as usize;
        if self.stack[level].is_none() {
            self.stack[level].replace(opt.into());
        }
        
    }

    fn find_in_options<F: Fn(Rc<RefCell<Opt>>)->Option<(Level,T)>,T>(&self, f: F)->Option<(Level,T)>{
        for opt in self.stack.iter().rev() {
            if let Some(opt) = opt.clone() {
                let res = f(opt);
                if res.is_some() {
                    return res;
                }
            }
        }
        None
    }

    pub fn get(&self, opttype : OptType) -> (Level,OptValue) {
        match opttype {
            OptType::Path => {
                let res = self.get_path();
                (res.0,OptValue::String(res.1))
            },
            OptType::EnvWhitelist => {
                let res = self.get_env_whitelist();
                (res.0,OptValue::String(res.1))
            },
            OptType::EnvChecklist => {
                let res = self.get_env_checklist();
                (res.0,OptValue::String(res.1))
            },
            OptType::NoRoot => {
                let res = self.get_no_root();
                (res.0,OptValue::Bool(res.1))
            },
            OptType::Bounding => {
                let res = self.get_bounding();
                (res.0,OptValue::Bool(res.1))
            },
            OptType::Setuid => {
                let res = self.get_setuid();
                (res.0,OptValue::Setuid(res.1))
            },
            OptType::Setgid => {
                let res = self.get_setgid();
                (res.0,OptValue::Setuid(res.1))
            },
        }
    }

    pub fn get_path(&self) -> (Level, String) {
        self.find_in_options(|opt| {
                if let Some(p) = opt.borrow().path.borrow().as_ref() {
                    return Some((opt.borrow().level,p.clone())).into();
                }
                None.into()
            }
        ).unwrap_or((Level::None.into(),"".to_string()))
        
    }
    pub fn get_env_whitelist(&self) -> (Level, String) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().env_whitelist.borrow().as_ref() {
                return Some((opt.borrow().level,p.clone())).into();
            }
            None.into()
        }).unwrap_or((Level::None.into(),"".to_string()))
    }
    pub fn get_env_checklist(&self) -> (Level, String) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().env_checklist.borrow().as_ref() {
                return Some((opt.borrow().level,p.clone())).into();
            }
            None.into()
        }).unwrap_or((Level::None.into(),"".to_string()))
        
    }
    pub fn get_no_root(&self) -> (Level, bool) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().no_root.borrow().as_ref() {
                return Some((opt.borrow().level,p.clone())).into();
            }
            None.into()
        }).unwrap_or((Level::None.into(),true))
        
    }
    pub fn get_bounding(&self) -> (Level, bool) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().bounding.borrow().as_ref() {
                return Some((opt.borrow().level,p.clone())).into();
            }
            None.into()
        }).unwrap_or((Level::None.into(),true))
        
    }
    pub fn get_setuid(&self) -> (Level, (bool,String)) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().setuid.borrow().as_ref() {
                return Some((opt.borrow().level,p.clone())).into();
            }
            None.into()
        }).unwrap_or((Level::None.into(),(false,"".to_string())))
    }
    pub fn get_setgid(&self) -> (Level, (bool,String)) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().setgid.borrow().as_ref() {
                return Some((opt.borrow().level,p.clone())).into();
            }
            None.into()
        }).unwrap_or((Level::None.into(),(false,"".to_string())))
    }
}