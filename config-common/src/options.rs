use std::{borrow::Borrow, cell::RefCell, rc::Rc};

use crate::structs::{Task, Config, Role};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    None,
    Default,
    Global,
    Role,
    Task,
}

#[derive(Debug, Clone, Copy)]
pub enum OptType {
    Path,
    EnvWhitelist,
    EnvChecklist,
    NoRoot,
    Bounding,
    Wildcard,
}

impl OptType {
    pub fn from_index(index: usize) -> OptType {
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
            OptType::Wildcard => 5,
        }
    }
}

#[derive(Debug)]
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

impl OptValue {
    pub fn get_description(&self, opttype: OptType) -> String {
        match opttype {
            OptType::Path => self
                .to_string()
                .split(':')
                .collect::<Vec<&str>>()
                .join("\n"),
            OptType::EnvWhitelist => self
                .to_string()
                .split(',')
                .collect::<Vec<&str>>()
                .join("\n"),
            OptType::EnvChecklist => self
                .to_string()
                .split(',')
                .collect::<Vec<&str>>()
                .join("\n"),
            OptType::NoRoot => {
                if self.as_bool() {
                    String::from("Enforce NoRoot")
                } else {
                    String::from("Do not enforce NoRoot")
                }
            }
            OptType::Bounding => {
                if self.as_bool() {
                    String::from("Restrict with Bounding")
                } else {
                    String::from("Do not restrict with Bounding")
                }
            }
            OptType::Wildcard => self.to_string(),
        }
    }
}

impl OptType {
    pub fn item_list_str() -> Vec<(OptType, String)> {
        vec![
            (OptType::Path, String::from("Path")),
            (OptType::EnvWhitelist, String::from("Environment Whitelist")),
            (OptType::EnvChecklist, String::from("Environment Checklist")),
            (OptType::NoRoot, String::from("Enforce NoRoot")),
            (OptType::Bounding, String::from("Restrict with Bounding")),
        ]
    }
}

#[derive(Debug, Clone)]
pub struct Opt {
    level: Level,
    pub path: Option<String>,
    pub env_whitelist: Option<String>,
    pub env_checklist: Option<String>,
    pub wildcard_denied: Option<String>,
    pub allow_root: Option<bool>,
    pub disable_bounding: Option<bool>,
}

impl AsRef<Opt> for Opt {
    fn as_ref(&self) -> &Opt {
        self
    }
}

impl ToString for Opt {
    fn to_string(&self) -> String {
        let mut str = String::new();
        if let Some(path) = &self.path {
            str.push_str(format!("path={}\n", path).as_str());
        }
        if let Some(env_whitelist) = &self.env_whitelist {
            str.push_str(format!("env_whitelist={}\n", env_whitelist).as_str());
        }
        if let Some(env_checklist) = &self.env_checklist {
            str.push_str(format!("env_checklist={}\n", env_checklist).as_str());
        }
        if let Some(wildcard_denied) = &self.wildcard_denied {
            str.push_str(format!("wildcard_denied={}\n", wildcard_denied).as_str());
        }
        if let Some(no_root) = &self.allow_root {
            str.push_str(format!("no_root={}\n", no_root).as_str());
        }
        if let Some(bounding) = &self.disable_bounding {
            str.push_str(format!("bounding={}\n", bounding).as_str());
        }
        str
    }
}

impl Default for Opt {
    fn default() -> Opt {
        Opt {
            level: Level::Default,
            path: Some("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin".to_string()),
            env_whitelist: Some("HOME,USER,LOGNAME,COLORS,DISPLAY,HOSTNAME,KRB5CCNAME,LS_COLORS,PS1,PS2,XAUTHORY,XAUTHORIZATION,XDG_CURRENT_DESKTOP".to_string()),
            env_checklist: Some("COLORTERM,LANG,LANGUAGE,LC_*,LINGUAS,TERM,TZ".to_string()),
            allow_root: Some(true),
            disable_bounding: Some(true),
            wildcard_denied: Some(";&|".to_string())
        }
    }
}

impl Opt {
    pub fn new(level: Level) -> Opt {
        Opt {
            level,
            path: None,
            env_whitelist: None,
            env_checklist: None,
            allow_root: None,
            disable_bounding: None,
            wildcard_denied: None,
        }
    }

    pub fn get_description(&self) -> String {
        let mut description = String::new();
        if let Some(path) = self.path.borrow().as_ref() {
            description.push_str(format!("Path: {}\n", path).as_str());
        }
        if let Some(env_whitelist) = self.env_whitelist.borrow().as_ref() {
            description.push_str(format!("Env whitelist: {}\n", env_whitelist).as_str());
        }
        if let Some(env_checklist) = self.env_checklist.borrow().as_ref() {
            description.push_str(format!("Env checklist: {}\n", env_checklist).as_str());
        }
        if let Some(no_root) = self.allow_root.borrow().as_ref() {
            description.push_str(format!("No root: {}\n", no_root).as_str());
        }
        if let Some(bounding) = self.disable_bounding.borrow().as_ref() {
            description.push_str(format!("Bounding: {}\n", bounding).as_str());
        }
        if let Some(wildcard_denied) = self.wildcard_denied.borrow().as_ref() {
            description.push_str(format!("Wildcard denied: {}\n", wildcard_denied).as_str());
        }
        description
    }
}

#[derive(Debug, Clone)]
pub struct OptStack<'a> {
    pub(crate) stack: [Option<Rc<RefCell<Opt>>>; 5],
    roles: Rc<RefCell<Config<'a>>>,
    role: Option<Rc<RefCell<Role<'a>>>>,
    task: Option<Rc<RefCell<Task<'a>>>>,
}

impl<'a> OptStack<'a> {
    pub fn from_task(task: Rc<RefCell<Task<'a>>>) -> Self {
        let mut stack = OptStack::from_role(task.as_ref().borrow().get_role().unwrap());
        stack.task = Some(task.to_owned());
        stack.set_opt(Level::Task, task.as_ref().borrow().options.to_owned());
        stack
    }
    pub fn from_role(role: Rc<RefCell<Role<'a>>>) -> Self {
        let mut stack = OptStack::from_roles(role.as_ref().borrow().get_config().unwrap());
        stack.role = Some(role.to_owned());
        stack.set_opt(Level::Role, role.as_ref().borrow().options.to_owned());
        stack
    }
    pub fn from_roles(roles: Rc<RefCell<Config<'a>>>) -> Self {
        let mut stack = OptStack::new(roles);
        stack.set_opt(
            Level::Global,
            stack.get_roles().as_ref().borrow().options.to_owned(),
        );
        stack
    }

    fn new(roles: Rc<RefCell<Config<'a>>>) -> OptStack<'a> {
        OptStack {
            stack: [None, Some(Rc::new(Opt::default().into())), None, None, None],
            roles,
            role: None,
            task: None,
        }
    }

    fn get_roles(&self) -> Rc<RefCell<Config<'a>>> {
        self.roles.to_owned()
    }

    fn save(&mut self) {
        let level = self.get_level();
        let opt = self.get_opt(level);
        match level {
            Level::Global => {
                self.get_roles().as_ref().borrow_mut().options = opt;
            }
            Level::Role => {
                self.role.to_owned().unwrap().as_ref().borrow_mut().options = opt;
            }
            Level::Task => {
                self.task.to_owned().unwrap().as_ref().borrow_mut().options = opt;
            }
            Level::None | Level::Default => {
                panic!("Cannot save None/default options");
            }
        }
    }

    pub fn get_level(&self) -> Level {
        self.stack
            .iter()
            .rev()
            .find(|opt| opt.is_some())
            .unwrap()
            .as_ref()
            .unwrap()
            .as_ref()
            .borrow()
            .level
    }
    fn set_opt(&mut self, level: Level, opt: Option<Rc<RefCell<Opt>>>) {
        if let Some(opt) = opt {
            self.stack[level as usize] = Some(opt);
        } else {
            self.stack[level as usize] = Some(Rc::new(Opt::new(level).into()));
        }
    }

    fn get_opt(&self, level: Level) -> Option<Rc<RefCell<Opt>>> {
        self.stack[level as usize].to_owned()
    }

    fn find_in_options<F: Fn(&Opt) -> Option<(Level, T)>, T>(&self, f: F) -> Option<(Level, T)> {
        for opt in self.stack.iter().rev() {
            if let Some(opt) = opt.to_owned() {
                let res = f(opt.as_ref().borrow().as_ref());
                if res.is_some() {
                    println!("res: {:?}", res.as_ref().unwrap().0);
                    return res;
                }
            }
        }
        None
    }

    pub fn get_from_type(&self, opttype: OptType) -> (Level, OptValue) {
        match opttype {
            OptType::Path => {
                let res = self.get_path();
                (res.0, OptValue::String(res.1))
            }
            OptType::EnvWhitelist => {
                let res = self.get_env_whitelist();
                (res.0, OptValue::String(res.1))
            }
            OptType::EnvChecklist => {
                let res = self.get_env_checklist();
                (res.0, OptValue::String(res.1))
            }
            OptType::NoRoot => {
                let res = self.get_no_root();
                (res.0, OptValue::Bool(res.1))
            }
            OptType::Bounding => {
                let res = self.get_bounding();
                (res.0, OptValue::Bool(res.1))
            }
            OptType::Wildcard => {
                let res = self.get_wildcard();
                (res.0, OptValue::String(res.1))
            }
        }
    }

    pub fn get_from_level(&self, level: Level, opttype: OptType) -> Option<OptValue> {
        self.stack[level as usize]
            .as_ref()
            .map(|opt| {
                let opt = opt.as_ref().borrow();
                match opttype {
                    OptType::Path => {
                        if let Some(value) = opt.path.borrow().as_ref() {
                            return Some(OptValue::String(value.to_owned()));
                        }
                    }
                    OptType::EnvWhitelist => {
                        if let Some(value) = opt.env_whitelist.borrow().as_ref() {
                            return Some(OptValue::String(value.to_owned()));
                        }
                    }
                    OptType::EnvChecklist => {
                        if let Some(value) = opt.env_checklist.borrow().as_ref() {
                            return Some(OptValue::String(value.to_owned()));
                        }
                    }
                    OptType::NoRoot => {
                        if let Some(value) = opt.allow_root.borrow().as_ref() {
                            return Some(OptValue::Bool(value.to_owned()));
                        }
                    }
                    OptType::Bounding => {
                        if let Some(value) = opt.disable_bounding.borrow().as_ref() {
                            return Some(OptValue::Bool(value.to_owned()));
                        }
                    }
                    OptType::Wildcard => {
                        if let Some(value) = opt.wildcard_denied.borrow().as_ref() {
                            return Some(OptValue::String(value.to_owned()));
                        }
                    }
                }
                None
            })
            .unwrap_or(None)
    }

    pub fn get_path(&self) -> (Level, String) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().path.borrow().as_ref() {
                return Some((opt.borrow().level, p.to_owned()));
            }
            None
        })
        .unwrap_or((Level::None, "".to_string()))
    }
    pub fn get_env_whitelist(&self) -> (Level, String) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().env_whitelist.borrow().as_ref() {
                return Some((opt.borrow().level, p.to_owned()));
            }
            None
        })
        .unwrap_or((Level::None, "".to_string()))
    }
    pub fn get_env_checklist(&self) -> (Level, String) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().env_checklist.borrow().as_ref() {
                return Some((opt.borrow().level, p.to_owned()));
            }
            None
        })
        .unwrap_or((Level::None, "".to_string()))
    }
    pub fn get_no_root(&self) -> (Level, bool) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().allow_root.borrow().as_ref() {
                return Some((opt.borrow().level, p.to_owned()));
            }
            None
        })
        .unwrap_or((Level::None, true))
    }
    pub fn get_bounding(&self) -> (Level, bool) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().disable_bounding.borrow().as_ref() {
                return Some((opt.borrow().level, p.to_owned()));
            }
            None
        })
        .unwrap_or((Level::None, true))
    }
    pub fn get_wildcard(&self) -> (Level, String) {
        self.find_in_options(|opt| {
            if let Some(p) = opt.borrow().wildcard_denied.borrow().as_ref() {
                return Some((opt.borrow().level, p.to_owned()));
            }
            None
        })
        .unwrap_or((Level::None, "".to_string()))
    }

    fn set_at_level(&mut self, opttype: OptType, value: Option<OptValue>, level: Level) {
        let ulevel = level as usize;
        if self.stack[ulevel].is_none() {
            self.stack[ulevel] = Some(Rc::new(Opt::new(level).into()));
            return;
        }
        println!("stack : {:?}", self.stack);
        let binding = self.stack[ulevel].as_ref().unwrap();
        let mut opt = binding.as_ref().borrow_mut();
        match opttype {
            OptType::Path => {
                if let Some(OptValue::String(value)) = value.borrow() {
                    opt.path.replace(value.to_string());
                }
            }
            OptType::EnvWhitelist => {
                if let Some(OptValue::String(value)) = value.borrow() {
                    opt.env_whitelist.replace(value.to_string());
                }
            }
            OptType::EnvChecklist => {
                if let Some(OptValue::String(value)) = value.borrow() {
                    opt.env_checklist.replace(value.to_string());
                }
            }
            OptType::NoRoot => {
                if let Some(OptValue::Bool(value)) = value.borrow() {
                    opt.allow_root.replace(*value);
                }
            }
            OptType::Bounding => {
                if let Some(OptValue::Bool(value)) = value.borrow() {
                    opt.disable_bounding.replace(*value);
                }
            }
            OptType::Wildcard => {
                if let Some(OptValue::String(value)) = value.borrow() {
                    opt.wildcard_denied.replace(value.to_string());
                }
            }
        }
    }

    /**
     * Set an option at the highest level
     */
    pub fn set_value(&mut self, opttype: OptType, value: Option<OptValue>) {
        self.set_at_level(opttype, value, self.get_level());
        self.save();
    }

    pub fn get_description(&self, current_level: Level, opttype: OptType) -> String {
        let (level, value) = self.get_from_type(opttype.to_owned());
        let leveldesc = if level != current_level {
            match level {
                Level::Default => " (Inherited from Default)",
                Level::Global => " (Inherited from Global)",
                Level::Role => " (Inherited from Role)",
                Level::Task => " (Inherited from Commands)",
                Level::None => " (Inherited from None)",
            }
        } else {
            " (setted at this level)"
        };
        format!("{}\n{}", leveldesc, value.get_description(opttype))
    }
}

#[cfg(test)]
mod tests {
    use crate::{structs::IdTask, version::PACKAGE_VERSION};

    use super::*;

    #[test]
    fn test_find_in_options() {
        let roles = Config::new(PACKAGE_VERSION);
        let role = Role::new("test".to_string(), Some(Rc::downgrade(&roles)));
        roles.as_ref().borrow_mut().roles.push(role);
        let mut options = OptStack::from_role(roles.as_ref().borrow().roles[0].to_owned());
        options.set_at_level(
            OptType::Path,
            Some(OptValue::String("path1".to_string())),
            Level::Global,
        );
        options.set_at_level(
            OptType::Path,
            Some(OptValue::String("path2".to_string())),
            Level::Role,
        );

        let res = options.find_in_options(|opt| {
            if let Some(value) = opt.path.borrow().as_ref() {
                Some((opt.level, value.to_owned()))
            } else {
                None
            }
        });
        assert_eq!(res, Some((Level::Role, "path2".to_string())));
    }

    #[test]
    fn test_get_description() {
        let mut options = OptStack::from_roles(Config::new("3.0.0"));
        println!("{:?}", options);
        options.set_at_level(
            OptType::Path,
            Some(OptValue::String("path1".to_string())),
            Level::Global,
        );
        println!("{:?}", options);
        options.set_at_level(
            OptType::EnvWhitelist,
            Some(OptValue::String("tets".to_string())),
            Level::Role,
        );
        println!("{:?}", options);
        let res = options.get_description(Level::Role, OptType::Path);
        assert_eq!(res, " (Inherited from Global)\npath1");
    }

    #[test]
    fn test_get_description_inherited() {
        let mut options = OptStack::from_roles(Config::new("3.0.0"));
        options.set_at_level(
            OptType::Path,
            Some(OptValue::String("path1".to_string())),
            Level::Global,
        );
        options.set_at_level(
            OptType::EnvWhitelist,
            Some(OptValue::String("tets".to_string())),
            Level::Global,
        );

        let res = options.get_description(Level::Global, OptType::Path);
        assert_eq!(res, " (setted at this level)\npath1");
    }

    #[test]
    fn test_task_level() {
        let roles = Config::new(PACKAGE_VERSION);
        let role = Role::new("test".to_string(), Some(Rc::downgrade(&roles)));
        let task = Task::new(IdTask::Number(1), Rc::downgrade(&role));
        let mut options = OptStack::from_task(task);
        options.set_at_level(
            OptType::EnvChecklist,
            Some(OptValue::String("checklist1".to_string())),
            Level::Global,
        );
        options.set_at_level(
            OptType::EnvChecklist,
            Some(OptValue::String("checklist2".to_string())),
            Level::Task,
        );

        let res = options.get_description(Level::Task, OptType::EnvChecklist);
        assert_eq!(res, " (setted at this level)\nchecklist2");
    }

    #[test]
    fn test_get_from_level() {
        let roles = Config::new(PACKAGE_VERSION);
        let role = Role::new("test".to_string(), Some(Rc::downgrade(&roles)));
        let task = Task::new(IdTask::Number(1), Rc::downgrade(&role));
        let mut options = OptStack::from_task(task);
        options.set_at_level(
            OptType::EnvChecklist,
            Some(OptValue::String("checklist1".to_string())),
            Level::Global,
        );
        options.set_at_level(
            OptType::EnvChecklist,
            Some(OptValue::String("checklist2".to_string())),
            Level::Task,
        );

        let res = options.get_from_level(Level::Task, OptType::EnvChecklist);
        assert_eq!(res.unwrap().to_string(), "checklist2");
    }

    #[test]
    fn test_set_value() {
        let roles = Config::new(PACKAGE_VERSION);
        let role = Role::new("test".to_string(), Some(Rc::downgrade(&roles)));
        let task = Task::new(IdTask::Number(1), Rc::downgrade(&role));
        let mut options = OptStack::from_task(task);
        options.set_value(OptType::NoRoot, Some(OptValue::Bool(true)));

        let res = options.get_from_level(Level::Task, OptType::NoRoot);
        assert_eq!(res.unwrap().to_string(), "true");
    }
}
