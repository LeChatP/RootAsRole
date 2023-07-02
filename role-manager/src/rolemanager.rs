

use std::borrow::Borrow;
use std::cell::{RefCell};
use std::error::Error;
use std::rc::{Rc, Weak};

use crate::config::{self, Role, Task, Save, Groups, IdTask};
use crate::options::{OptType, Opt, OptStack, Level};
pub trait ContextMemento<T> {
    fn restore(&self) -> T;
}

#[derive(Debug)]
pub struct RoleContextHistory {
    mementos: Vec<RoleContext>
}

impl RoleContextHistory {
    pub fn new() -> Self {
        RoleContextHistory {
            mementos: Vec::new()
        }
    }

    pub fn save(&mut self, memento: RoleContext) {
        self.mementos.push(memento);
    }

    pub fn restore(&mut self) -> Option<RoleContext> {
        self.mementos.pop()
    }
}

#[derive(Debug)]
pub struct RoleContext {
    history: Weak<RefCell<RoleContextHistory>>,
    pub roles: Rc<RefCell<config::Roles<'static>>>,
    selected_role: Option<usize>,
    new_role: Option<Rc<RefCell<Role<'static>>>>,
    selected_task: Option<usize>,
    new_task: Option<Rc<RefCell<Task<'static>>>>,
    selected_command: Option<usize>,
    new_command: Option<String>,
    selected_groups: Option<usize>,
    new_groups: Option<Groups>,
    selected_options: Option<OptType>,
    new_options: Option<Opt>,
    error: Option<Box<dyn Error>>,
    is_new: bool,
    
}

impl Clone for RoleContext {
    fn clone(&self) -> Self {
        RoleContext {
            history: Rc::downgrade(&self.history.upgrade().unwrap()),
            roles: Rc::new(RefCell::new(self.roles.as_ref().borrow().clone())),
            selected_role: self.selected_role.clone(),
            new_role: Some(Rc::new(RefCell::new(self.new_role.clone().unwrap().as_ref().borrow().clone()))),
            selected_task: self.selected_task.clone(),
            new_task: Some(Rc::new(RefCell::new(self.new_task.clone().unwrap().as_ref().borrow().clone()))),
            selected_command: self.selected_command.clone(),
            new_command: self.new_command.clone(),
            selected_groups: self.selected_groups.clone(),
            new_groups: self.new_groups.clone(),
            selected_options: self.selected_options.clone(),
            new_options: self.new_options.clone(),
            error: None,
            is_new: self.is_new.clone(),
        }
    }
}

impl RoleContext {
    pub fn new(roles: Rc<RefCell<config::Roles<'static>>>) -> RoleContext {
        RoleContext {
            history: Rc::downgrade(&Rc::new(RoleContextHistory::new().into())),
            roles,
            selected_role: None,
            selected_task: None,
            selected_command: None,
            selected_groups: None,
            selected_options: None,
            new_role: None,
            new_task: None,
            new_command: None,
            new_groups: None,
            new_options: None,
            error: None,
            is_new: false,
        }
    }


    pub fn save_state(&self) {
        self.history.upgrade().unwrap().borrow_mut().save(self.clone())
    }

    pub fn restore_state(&mut self) {
        if let Some(memento) = self.history.upgrade().unwrap().borrow_mut().restore() {
            *self = memento;
        }
    }

    pub fn is_new(&self) -> bool {
        self.is_new
    }

    pub fn list_roles(&self) {
        println!("Roles:");
        for (i, r) in self.roles.as_ref().borrow().roles.iter().enumerate() {
            println!("{}: {}", i, r.as_ref().borrow().name);
        }
    }

    pub fn select_role(&mut self, role_index: usize) -> Result<(), Box<dyn Error>> {
        let len = self.roles.as_ref().borrow().roles.len();
        if role_index > len - 1 {
            return Err("role not exist".into());
        } else {
            self.selected_role = Some(role_index);
            return Ok(());
        }
    }

    pub fn create_new_role(&mut self, name: String) {
        self.unselect_role();
        self.new_role = Some(Role::new(name, Some(Rc::downgrade(&self.roles.to_owned()))));
    }

    pub fn delete_new_role(&mut self) {
        self.new_role = None;
    }

    pub fn save_new_role(&mut self) {
        if let Some(role) = &self.new_role {
            self.roles.as_ref().borrow_mut().roles.push(role.to_owned());
        }
        self.new_role = None;
    }

    pub fn create_new_task(&mut self, pid: Option<String>) -> Result<(), Box<dyn Error>> {
        let parent;
        let mut id;
        self.unselect_task();
        if let Some(role) = self.get_role(){
            id = IdTask::Number(role.as_ref().borrow().tasks.len()+1);
            parent = Rc::downgrade(&role);
        } else {
            return Err("role not selected".into());
        }
        if let Some(pid) = pid {
            id = IdTask::Name(pid);
        }
        self.new_task = Some(Task::new(id, parent));
        Ok(())
    }

    pub fn delete_new_task(&mut self) {
        self.new_task = None;
    }

    pub fn save_new_task(&mut self) {
        if let Some(task) = &self.new_task {
            task.as_ref().borrow().get_parent().unwrap().borrow_mut().tasks.push(task.to_owned());
        }
        self.new_task = None;
    }

    pub fn get_new_role(&self) -> Option<Rc<RefCell<Role<'static>>>> {
        self.new_role.to_owned()
    }

    pub fn get_new_task(&self) -> Option<Rc<RefCell<Task<'static>>>> {
        self.new_task.to_owned()
    }

    pub fn unselect_role(&mut self) {
        self.selected_role = None;
        self.unselect_task();
        self.unselect_groups();
        self.unselect_options();
    }

    pub fn select_task(&mut self, task_index: usize) -> Result<(), Box<dyn Error>> {
        let len = self.get_role().unwrap().as_ref().borrow().tasks.len();
        if task_index > len - 1 {
            return Err("command not exist".into());
        } else {
            self.selected_task = Some(task_index);
            return Ok(());
        }
    }

    pub fn unselect_task(&mut self) {
        self.selected_task = None;
        self.unselect_command();
        self.unselect_options();
    }

    pub fn select_command(&mut self, command_index: usize) -> Result<(), Box<dyn Error>> {
        let len = self.get_task().unwrap().as_ref().borrow().commands.len();
        if command_index > len - 1 {
            return Err("command not exist".into());
        } else {
            self.selected_command = Some(command_index);
            return Ok(());
        }
    }

    pub fn unselect_command(&mut self) {
        self.selected_command = None;
    }

    pub fn select_groups(&mut self, group_index: usize) -> Result<(), Box<dyn Error>> {
        let len = self
            .roles.as_ref().borrow()
            .roles[self.selected_role.unwrap()].as_ref().borrow()
            .groups
            .len();
        if group_index > len - 1 {
            return Err("groups not exist".into());
        } else {
            self.selected_groups = Some(group_index);
            return Ok(());
        }
    }

    pub fn unselect_groups(&mut self) {
        self.selected_groups = None;
    }

    pub fn select_options(&mut self, option_type: OptType) -> Result<(), Box<dyn Error>> {
        self.selected_options = Some(option_type);
        return Ok(());
    }

    pub fn unselect_options(&mut self) {
        self.selected_options = None;
    }

    pub fn delete_role(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(i) = self.selected_role {
            self.roles.as_ref().borrow_mut().roles.remove(i);
            self.unselect_role();
            return Ok(());
        } else {
            return Err("no role selected".into());
        }
    }

    pub fn add_group(&mut self, group: Vec<String>) -> Result<(), Box<dyn Error>> {
        if self.selected_role.is_some() {
            self.roles.as_ref().borrow()
                .roles[self.selected_role.unwrap()].as_ref().borrow_mut()
                .groups
                .push(group);
            return Ok(());
        } else {
            return Err("no role selected".into());
        }
    }

    pub fn add_option(&mut self, level : Level, option: Opt) {
        match level {
            Level::Global => {
                self.roles.as_ref().borrow_mut().options = Some(Rc::new(option.into()));
            }
            Level::Role => {
                match self.selected_role {
                    Some(i) => {
                        self.roles.as_ref().borrow()
                            .roles[i].as_ref().borrow_mut()
                            .options = Some(Rc::new(option.into()));
                    }
                    None => {
                        println!("no role selected");
                    }
                }
            }
            Level::Task => {
                match self.selected_task {
                    Some(i) => {
                        self.roles.as_ref().borrow()
                            .roles[self.selected_role.unwrap()].as_ref().borrow_mut()
                            .tasks[i]
                            .as_ref().borrow_mut()
                            .options = Some(Rc::new(option.into()));
                    }
                    None => {
                        println!("no command selected");
                    }
                }
            }
            _ => {
                println!("unimplemented level");
            }
        }
    }

    pub fn get_selected_role(&self) -> Option<Rc<RefCell<Role<'static>>>> {
        match self.selected_role {
            Some(i) => {
                return Some(self.roles.as_ref().borrow().roles[i].to_owned());
            }
            None => {
                return None;
            }
        }
    }

    pub fn get_role(&self) -> Option<Rc<RefCell<Role<'static>>>> {
        self.get_selected_role().or(self.get_new_role())
    }

    pub fn get_selected_task(&self) -> Option<Rc<RefCell<Task<'static>>>> {
        match self.selected_task {
            Some(i) => {
                let id = self.get_role().unwrap().as_ref().borrow().tasks[i].to_owned();
                return Some(id);
            }
            None => {
                return None;
            }
        }
    }

    pub fn get_task(&self) -> Option<Rc<RefCell<Task<'static>>>> {
        self.get_selected_task().or(self.get_new_task())
    }

    pub fn get_task_index(&self) -> Option<usize> {
        return self.selected_task;
    }

    pub fn get_command(&self) -> Option<String> {
        match self.selected_command {
            Some(i) => {
                return Some(self.get_task().unwrap().as_ref().borrow().commands[i].to_owned());
            }
            None => {
                return None;
            }
        }
    }

    pub fn set_command(&mut self, command: String) -> Result<(), Box<dyn Error>> {
        match self.selected_command {
            Some(i) => {
                self.get_task().unwrap().borrow_mut().commands[i] = command;
                return Ok(());
            }
            None => {
                return Err("no command selected".into());
            }
        }
    }

    pub fn get_group(&self) -> Option<Vec<String>> {
        match self.selected_groups {
            Some(i) => {
                return Some(self.get_role().unwrap().as_ref().borrow().groups[i].to_owned());
            }
            None => {
                return None;
            }
        }
    }

    pub fn set_group(&mut self, group: Vec<String>) -> Result<(), Box<dyn Error>> {
        match self.selected_groups {
            Some(i) => {
                self.get_role().unwrap().as_ref().borrow_mut().groups[i] = group;
                return Ok(());
            }
            None => {
                return Err("no group selected".into());
            }
        }
    }

/**
* Return a OptStack that contains Opt in function of selections
*/
    pub fn get_options(&self) -> OptStack<'static>  {
        if self.selected_task.is_some() {
            OptStack::from_task(self.roles.clone(), &self.selected_role.unwrap(), &self.selected_task.unwrap())
        } else if self.selected_role.is_some() {
            OptStack::from_role(self.roles.clone(), &self.selected_role.unwrap())
        } else {
            OptStack::from_roles(self.roles.clone())
        }
    }

    pub fn saveall(&self) -> Result<bool, Box<dyn Error>> {
        self.roles.as_ref().borrow().save("/etc/security/rootasrole.xml")
    }

    pub fn set_error(&mut self, error: Box<dyn Error>) {
        self.error = Some(error);
    }

    pub fn take_error(&mut self) -> Option<Box<dyn Error>> {
        return self.error.take();
    }
}

