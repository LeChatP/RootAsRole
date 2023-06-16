use std::{cell::{Cell, RefCell}, rc::Rc, borrow::{BorrowMut, Borrow}};

use crate::config::{Roles,Role,Commands, self};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    None,
    Default,
    Global,
    Role,
    Commands,
}

#[derive(Debug,Clone, Copy)]
pub enum OptType {
    Path,
    EnvWhitelist,
    EnvChecklist,
    NoRoot,
    Bounding,
}

impl OptType {
    pub fn from_index(index : usize) -> OptType {
        match index {
            0 => OptType::Path,
            1 => OptType::EnvWhitelist,
            2 => OptType::EnvChecklist,
            3 => OptType::NoRoot,
            4 => OptType::Bounding,
            _ => panic!("Invalid index for OptType"),
        }
    }
    pub fn as_index(&self) -> usize {
        match self {
            OptType::Path => 0,
            OptType::EnvWhitelist => 1,
            OptType::EnvChecklist => 2,
            OptType::NoRoot => 3,
            OptType::Bounding => 4,
        }
    }
}

pub enum OptValue {
    String(String),
    Bool(bool),
}

impl ToString for OptValue {
    fn to_string(&self) -> String {
        match self {
            OptValue::String(s) => s.to_string(),
            OptValue::Bool(b) => b.to_string(),
        }
    }
}

impl OptValue {
    pub fn as_bool(&self) -> bool {
        match self {
            OptValue::Bool(b) => *b,
            _ => panic!("OptValue is not a bool"),
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
        ]
    }
}

#[derive(Debug,Clone)]
pub struct Opt{
    level : Level,
    pub path: Option<String>,
    pub env_whitelist: Option<String>,
    pub env_checklist: Option<String>,
    pub no_root: Option<bool>,
    pub bounding: Option<bool>
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
        }
    }

}

#[derive(Debug)]
pub struct OptStack {
    pub(crate) stack : [Option<Rc<RefCell<Opt>>>;5],
}

impl Default for OptStack {
    fn default() -> OptStack {
        OptStack {
            stack: [None, Some(Rc::new(Opt::default().into())), None, None, None],
        }
    }
}

impl OptStack {
    pub fn from_commands(roles: &Roles, role : &usize, commands: &usize) -> Self {
        let mut stack = OptStack::from_role(roles,role);
        stack.set_opt(roles.roles[*role].as_ref().borrow().commands[*commands].as_ref().borrow().options.clone().unwrap());
        stack
    }
    pub fn from_role(roles: &Roles, role : &usize) -> Self {
        let mut stack = OptStack::from_roles(roles);
        stack.set_opt(roles.roles[*role].as_ref().borrow().options.clone().unwrap());
        stack
    }
    pub fn from_roles(roles: &Roles) -> Self {
        let mut stack = OptStack::default();
        stack.set_opt(roles.options.clone().unwrap());
        stack
    }
    pub fn get_level(&self) -> Level {
        self.stack.iter().rev().find(|opt| opt.is_some()).unwrap().as_ref().unwrap().as_ref().borrow().level
    }
    fn set_opt(&mut self, opt: Rc<RefCell<Opt>>) {
        let level = opt.as_ref().borrow().level;
        self.stack[level as usize] = Some(opt);
    }

    fn find_in_options<F: Fn(&Opt)->Option<(Level,T)>,T>(&self, f: F)->Option<(Level,T)>{
        for opt in self.stack.iter().rev() {
            if let Some(opt) = opt.clone() {
                let res = f(opt.as_ref().borrow().as_ref());
                if res.is_some() {
                    return res;
                }
            }
        }
        None
    }

    pub fn get_from_type(&self, opttype : OptType) -> (Level,OptValue) {
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
        }
    }

    pub fn get_from_level(&self, level : Level, opttype : OptType) -> Option<OptValue> {
        self.stack[level as usize].as_ref().map(|opt| {
            let opt = opt.as_ref().borrow();
            match opttype {
                OptType::Path => {
                    if let Some(value) = opt.path.borrow().as_ref() {
                        return Some(OptValue::String(value.clone()));
                    }
                },
                OptType::EnvWhitelist => {
                    if let Some(value) = opt.env_whitelist.borrow().as_ref() {
                        return Some(OptValue::String(value.clone()));
                    }
                },
                OptType::EnvChecklist => {
                    if let Some(value) = opt.env_checklist.borrow().as_ref() {
                        return Some(OptValue::String(value.clone()));
                    }
                },
                OptType::NoRoot => {
                    if let Some(value) = opt.no_root.borrow().as_ref() {
                        return Some(OptValue::Bool(value.clone()));
                    }
                },
                OptType::Bounding => {
                    if let Some(value) = opt.bounding.borrow().as_ref() {
                        return Some(OptValue::Bool(value.clone()));
                    }
                },
            }
            None
        }).unwrap_or(None)
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

    fn set_at_level(&mut self, opttype : OptType, value : Option<OptValue>, level : Level) {
        let ulevel = level as usize;
        if self.stack[ulevel].is_none() {
            //self.stack[ulevel].replace(&Opt::new(level).into());
            panic!("Unable");
        }
        let binding = self.stack[ulevel].as_ref().unwrap();
        let mut opt = binding.as_ref().borrow_mut();
        match opttype {
            OptType::Path => {
                if let Some(value) = value.borrow() {
                    if let OptValue::String(value) = value {
                        opt.path.replace(value.to_string());
                    }
                }
            },
            OptType::EnvWhitelist => {
                if let Some(value) = value.borrow() {
                    if let OptValue::String(value) = value {
                        opt.env_whitelist.replace(value.to_string());
                    }
                }
            },
            OptType::EnvChecklist => {
                if let Some(value) = value.borrow() {
                    if let OptValue::String(value) = value {
                        opt.env_checklist.replace(value.to_string());
                    }
                }
            },
            OptType::NoRoot => {
                if let Some(value) = value.borrow() {
                    if let OptValue::Bool(value) = value {
                        opt.no_root.replace(*value);
                    }
                }
            },
            OptType::Bounding => {
                if let Some(value) = value.borrow() {
                    if let OptValue::Bool(value) = value {
                        opt.bounding.replace(*value);
                    }
                }
            },
        }
    }

    /**
     * Set an option at the highest level
     */
    pub fn set_value(&mut self, opttype : OptType, value : Option<OptValue>) {
        self.set_at_level(opttype,value,self.get_level());
    }
}