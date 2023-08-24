use std::cell::RefCell;
use std::collections::HashSet;
use std::error::Error;
use std::ffi::{CStr, CString};
use std::hash::{Hash, Hasher};
use std::ops::Index;
use std::rc::{Rc, Weak};
use std::str::Split;

use capctl::CapSet;
use chrono::Duration;
use nix::unistd::{getgrouplist, Group};
use sxd_document::dom::{Document, Element};

use crate::util::capset_to_string;

use super::options::Opt;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Groups {
    pub groups: Vec<String>,
}

impl Iterator for Groups {
    fn next(&mut self) -> Option<String> {
        self.groups.iter().next().map(|s| s.to_string())
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

impl Index<usize> for Groups {
    type Output = String;
    fn index(&self, index: usize) -> &Self::Output {
        &self.groups[index]
    }
}

impl FromIterator<String> for Groups {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Groups {
        let mut groups = Vec::new();
        for group in iter {
            groups.push(group);
        }
        Groups { groups }
    }
}

impl From<Vec<String>> for Groups {
    fn from(groups: Vec<std::string::String>) -> Self {
        let mut set = Vec::new();
        for group in groups {
            set.push(group);
        }
        Groups { groups: set }
    }
}

impl From<Split<'_, char>> for Groups {
    fn from(groups: Split<char>) -> Self {
        let mut set = Vec::new();
        for group in groups {
            set.push(group.to_string());
        }
        Groups { groups: set }
    }
}

impl Groups {
    pub fn join(&self, sep: &str) -> String {
        self.groups.iter().fold(String::new(), |acc, s| {
            if acc.is_empty() {
                s.to_string()
            } else {
                format!("{}{}{}", acc, sep, s)
            }
        })
    }
    fn to_hashset(&self) -> HashSet<String> {
        self.groups.clone().into_iter().collect()
    }
    pub fn is_subset(&self, other: &Groups) -> bool {
        self.to_hashset().is_subset(&other.to_hashset())
    }
    pub fn is_unix_subset(&self, other: &Vec<Group>) -> bool {
        let mut remaining = self.groups.clone();
        for group in other {
            if remaining.is_empty() {
                return true;
            }
            if let Some(index) = remaining
                .iter()
                .position(|x| x == &group.name || x == &group.gid.to_string())
            {
                remaining.remove(index);
            }
        }
        remaining.is_empty()
    }
    pub fn len(&self) -> usize {
        self.groups.len()
    }
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

impl From<Groups> for Vec<String> {
    fn from(val: Groups) -> Self {
        val.groups.into_iter().collect()
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
            IdTask::Name(_) => true,
            IdTask::Number(_) => false,
        }
    }

    pub fn as_ref(&self) -> &IdTask {
        self
    }

    pub fn unwrap(&self) -> String {
        match self {
            IdTask::Name(s) => s.to_string(),
            IdTask::Number(s) => s.to_string(),
        }
    }
}

impl ToString for IdTask {
    fn to_string(&self) -> String {
        match self {
            IdTask::Name(s) => s.to_string(),
            IdTask::Number(n) => format!("Task #{}", n),
        }
    }
}

impl From<String> for IdTask {
    fn from(s: String) -> Self {
        IdTask::Name(s)
    }
}

impl From<IdTask> for String {
    fn from(val: IdTask) -> Self {
        match val {
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
    pub capabilities: Option<CapSet>,
    pub setuid: Option<String>,
    pub setgid: Option<Groups>,
    pub setgroups: Option<Groups>,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Role<'a> {
    roles: Option<Weak<RefCell<Config<'a>>>>,
    ssd: Option<Vec<Weak<Role<'a>>>>,
    pub parents: Option<Vec<Weak<RefCell<Role<'a>>>>>,
    pub name: String,
    pub users: Vec<String>,
    pub groups: Vec<Groups>,
    pub tasks: Vec<Rc<RefCell<Task<'a>>>>,
    pub options: Option<Rc<RefCell<Opt>>>,
}

#[derive(Debug, Clone)]
pub struct CookieConstraint {
    pub offset: Duration,
    pub timestamptype: String,
    pub max_usage: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Config<'a> {
    pub config: Option<Weak<RefCell<Config<'a>>>>,
    pub roles: Vec<Rc<RefCell<Role<'a>>>>,
    pub options: Option<Rc<RefCell<Opt>>>,
    pub version: &'a str,
    pub timestamp: CookieConstraint,
    pub migrated: bool,
}

impl Default for CookieConstraint {
    fn default() -> Self {
        CookieConstraint {
            offset: Duration::seconds(0),
            timestamptype: "tty".to_string(),
            max_usage: None,
        }
    }
}

impl<'a> Config<'a> {
    pub fn new(version: &'a str) -> Rc<RefCell<Config<'a>>> {
        Rc::new(
            Config {
                config: None,
                roles: Vec::new(),
                options: None,
                version,
                timestamp: CookieConstraint::default(),
                migrated: false,
            }
            .into(),
        )
    }

    pub fn get_role(&self, name: &str) -> Option<Rc<RefCell<Role<'a>>>> {
        for r in self.roles.iter() {
            if r.as_ref().borrow().name == name {
                return Some(r.clone());
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
    pub fn new(name: String, roles: Option<Weak<RefCell<Config<'a>>>>) -> Rc<RefCell<Role<'a>>> {
        Rc::new(
            Role {
                roles,
                name,
                users: Vec::new(),
                groups: Vec::new(),
                tasks: Vec::new(),
                options: None,
                parents: None,
                ssd: None,
            }
            .into(),
        )
    }
    pub fn in_config(&self) -> bool {
        self.roles.is_some()
    }
    pub fn get_config(&self) -> Option<Rc<RefCell<Config<'a>>>> {
        if let Some(roles) = &self.roles {
            return roles.upgrade();
        }
        None
    }
    pub fn get_task_from_index(&self, index: &usize) -> Option<Rc<RefCell<Task<'a>>>> {
        if self.tasks.len() > *index {
            return Some(self.tasks[*index].clone());
        }
        None
    }
    pub fn get_users_info(&self) -> String {
        let mut users_info = String::new();
        users_info.push_str(&format!("Users:\n({})\n", self.users.to_vec().join(", ")));
        users_info
    }
    pub fn get_groups_info(&self) -> String {
        let mut groups_info = String::new();
        groups_info.push_str(&format!(
            "Groups:\n({})\n",
            self.groups
                .iter()
                .cloned()
                .map(|x| x.join(" & "))
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
                .iter()
                .cloned()
                .map(|x| x.as_ref().borrow().id.to_string())
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
        self.tasks.retain(|x| x.as_ref().borrow().id != id);
    }

    pub fn groups_are_forbidden(&self, groups: &Vec<String>) -> bool {
        return match self.ssd.as_ref() {
            Some(roles) => {
                let mut vgroups = Vec::new();
                for group in groups {
                    match nix::unistd::Group::from_name(&group) {
                        Ok(Some(nixgroup)) => {
                            vgroups.push(nixgroup);
                        }
                        _ => (),
                    };
                }
                for role in roles.iter() {
                    if let Some(role) = role.upgrade() {
                        if role
                            .groups
                            .iter()
                            .any(|group| group.is_unix_subset(&vgroups))
                        {
                            return true;
                        }
                    }
                }
                false
            }
            None => false,
        };
    }

    pub fn user_is_forbidden(&self, user: &str) -> bool {
        return match self.ssd.as_ref() {
            Some(roles) => match nix::unistd::User::from_name(user) {
                Ok(Some(nixuser)) => {
                    let mut groups_to_check = Vec::new();
                    if let Ok(groups) = getgrouplist(
                        &CString::new(nixuser.name.as_str()).unwrap().as_c_str(),
                        nixuser.gid,
                    ) {
                        for group in groups.iter() {
                            let group = nix::unistd::Group::from_gid(group.to_owned());
                            if let Ok(Some(group)) = group {
                                groups_to_check.push(group);
                            }
                        }
                    }
                    for role in roles.iter() {
                        if let Some(role) = role.upgrade() {
                            if role.users.contains(&nixuser.name)
                                || role.users.contains(&nixuser.uid.to_string())
                                || role
                                    .groups
                                    .iter()
                                    .any(|group| group.is_unix_subset(&groups_to_check))
                            {
                                return true;
                            }
                        }
                    }
                    false
                }
                Ok(None) => false,
                Err(_) => false,
            },
            None => false,
        };
        /*
        let groups = getgrouplist(CString::from(user) as CStr, group)
        if let Some(roles) = self.ssd.as_ref() {
            for role in roles.iter() {
                if let Some(role) = role.upgrade() {
                    if role.users.contains(&user.to_string()) {
                        return true;
                    }
                }
            }
        }
        false
        */
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
                setgroups: None,
                purpose: None,
            }
            .into(),
        )
    }
    pub fn get_role(&self) -> Option<Rc<RefCell<Role<'a>>>> {
        self.role.upgrade()
    }

    pub fn get_description(&self) -> String {
        let mut description = String::new();

        if let Some(p) = &self.purpose {
            description.push_str(&format!("Purpose :\n{}\n", p));
        }

        if let Some(caps) = &self.capabilities {
            description.push_str(&format!("Capabilities:\n({})\n", capset_to_string(caps)));
        }
        if let Some(setuid) = &self.setuid {
            description.push_str(&format!("Setuid:\n({})\n", setuid));
        }
        if let Some(setgid) = &self.setgid {
            description.push_str(&format!("Setgid:\n({})\n", setgid.join(" & ")));
        }

        if let Some(options) = &self.options {
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
                        s.to_string()
                    } else {
                        let mut s = s.to_string().chars().take(64).collect::<String>();
                        s.push_str("...");
                        s
                    }
                })
                .fold(String::new(), |acc, x| acc + &format!("{}\n", x))
        ));
        description
    }
}

pub trait Save {
    fn save(
        &self,
        doc: Option<&Document>,
        element: Option<&Element>,
    ) -> Result<bool, Box<dyn Error>>;
}

#[cfg(test)]
mod tests {

    use capctl::Cap;

    use super::super::{capset_to_string, options::Level};

    use super::*;

    #[test]
    fn test_get_empty_description() {
        let binding = "test_role".to_string();
        let role = Role::new(binding, None);
        assert_eq!(
            role.as_ref().borrow().get_description(),
            "Users:\n()\nGroups:\n()\nTasks:\n\n"
        );
        let task = Task::new(IdTask::Number(0), Rc::downgrade(&role));
        assert_eq!(task.as_ref().borrow().get_description(), "Commands:\n\n");
    }

    #[test]
    fn test_get_description() {
        let binding = "test_role".to_string();
        let role = Role::new(binding, None);
        let task = Task::new(IdTask::Number(0), Rc::downgrade(&role));
        task.as_ref().borrow_mut().commands.push("ls".to_string());
        task.as_ref()
            .borrow_mut()
            .commands
            .push("another".to_string());
        task.as_ref().borrow_mut().purpose = Some("thepurpose".to_string());
        task.as_ref().borrow_mut().setuid = Some("thesetuid".to_string());
        task.as_ref().borrow_mut().setgid =
            Some(vec!["thesetgid".to_string(), "thesecondsetgid".to_string()].into());
        let mut caps = CapSet::empty();
        caps.add(Cap::DAC_READ_SEARCH);
        task.as_ref().borrow_mut().capabilities = Some(caps.clone());
        let mut opt = Opt::new(Level::Task);
        opt.path = Some("thepath".to_string());
        opt.disable_bounding = Some(false);
        opt.allow_root = Some(true);
        opt.wildcard_denied = Some("thewildcard-denied".to_string());
        opt.env_checklist = Some("thechecklist".to_string());
        opt.env_whitelist = Some("thewhitelist".to_string());
        task.as_ref().borrow_mut().options = Some(Rc::new(RefCell::new(opt)));
        let desc = task.as_ref().borrow().get_description();
        println!("{}", desc);
        assert!(desc.contains("ls\nanother\n"));
        assert!(desc.contains("thepurpose"));
        assert!(desc.contains("thesetuid"));
        assert!(desc.contains("thesetgid"));
        assert!(desc.contains("thesecondsetgid"));
        assert!(desc.contains(&capset_to_string(&caps)));
        assert!(desc.contains("Options"));
        assert!(desc.contains("thepath"));
        assert!(desc.contains("thewildcard-denied"));
        assert!(desc.contains("thechecklist"));
        assert!(desc.contains("thewhitelist"));
        assert!(desc.contains("No root: true"));
        assert!(desc.contains("Bounding: false"));
    }

    #[test]
    fn test_idtask() {
        let id = IdTask::Number(0);
        assert_eq!(id.to_string(), "Task #0");
        let id = IdTask::Name("test".to_string());
        assert_eq!(id.to_string(), "test");
        let id: IdTask = "test".to_string().into();
        assert_eq!(Into::<String>::into(id), "test");
    }
}
