use std::cell::RefCell;
use std::collections::HashSet;
use std::error::Error;
use std::rc::{Rc, Weak};
use sxd_document::dom::{Document, Element};

use crate::config::{
    options::{Opt, OptStack},
    save::save_config,
    structs::{Config, Groups, IdTask, Role, Save, Task},
    FILENAME,
};
pub trait ContextMemento<T> {
    fn restore(&self) -> T;
}

#[derive(Debug)]
pub struct RoleContextHistory {
    mementos: Vec<RoleContext>,
}

impl RoleContextHistory {
    pub fn new() -> Self {
        RoleContextHistory {
            mementos: Vec::new(),
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
    pub roles: Rc<RefCell<Config<'static>>>,
    selected_role: Option<usize>,
    new_role: Option<Rc<RefCell<Role<'static>>>>,
    selected_task: Option<usize>,
    new_task: Option<Rc<RefCell<Task<'static>>>>,
    selected_command: Option<usize>,
    new_command: Option<String>,
    new_groups: Option<Groups>,
    new_options: Option<Opt>,
    pub selected_actors: Option<Rc<RefCell<HashSet<String>>>>,
    error: Option<Box<dyn Error>>,
    is_new: bool,
    exiting: bool,
}

impl Clone for RoleContext {
    fn clone(&self) -> Self {
        RoleContext {
            history: Rc::downgrade(&self.history.upgrade().unwrap()),
            roles: Rc::new(RefCell::new(self.roles.as_ref().borrow().clone())),
            selected_role: self.selected_role,
            new_role: Some(Rc::new(RefCell::new(
                self.new_role.clone().unwrap().as_ref().borrow().clone(),
            ))),
            selected_task: self.selected_task,
            new_task: Some(Rc::new(RefCell::new(
                self.new_task.clone().unwrap().as_ref().borrow().clone(),
            ))),
            selected_command: self.selected_command,
            new_command: self.new_command.clone(),
            new_groups: self.new_groups.clone(),
            new_options: self.new_options.clone(),
            selected_actors: self.selected_actors.clone(),
            error: None,
            is_new: self.is_new,
            exiting: self.exiting,
        }
    }
}

impl RoleContext {
    pub fn new(roles: Rc<RefCell<Config<'static>>>) -> RoleContext {
        RoleContext {
            history: Rc::downgrade(&Rc::new(RoleContextHistory::new().into())),
            roles,
            selected_role: None,
            selected_task: None,
            selected_command: None,
            selected_actors: None,
            new_role: None,
            new_task: None,
            new_command: None,
            new_groups: None,
            new_options: None,
            error: None,
            is_new: false,
            exiting: false,
        }
    }

    pub fn exit(&mut self) {
        self.exiting = true;
    }

    pub fn is_exiting(&self) -> bool {
        self.exiting
    }

    pub fn save_state(&self) {
        self.history
            .upgrade()
            .unwrap()
            .borrow_mut()
            .save(self.clone())
    }

    pub fn restore_state(&mut self) {
        if let Some(memento) = self.history.upgrade().unwrap().borrow_mut().restore() {
            *self = memento;
        }
    }

    pub fn is_new(&self) -> bool {
        self.new_role.is_some() || self.new_task.is_some()
    }

    pub fn list_roles(&self) {
        println!("Config:");
        for (i, r) in self.roles.as_ref().borrow().roles.iter().enumerate() {
            println!("{}: {}", i, r.as_ref().borrow().name);
        }
    }

    pub fn select_role_by_index(&mut self, role_index: usize) -> Result<(), Box<dyn Error>> {
        let len = self.roles.as_ref().borrow().roles.len();
        if role_index > len - 1 {
            Err("role not exist".into())
        } else {
            self.selected_role = Some(role_index);
            Ok(())
        }
    }

    pub fn select_role_by_name(&mut self, role_name: &str) -> Result<(), Box<dyn Error>> {
        let mut index = None;
        for (i, r) in self.roles.as_ref().borrow().roles.iter().enumerate() {
            if r.as_ref().borrow().name == role_name {
                index = Some(i);
                break;
            }
        }
        if let Some(index) = index {
            self.selected_role = Some(index);
            Ok(())
        } else {
            Err("role not exist".into())
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

    pub fn create_new_task(&mut self, pid: Option<&String>) -> Result<(), Box<dyn Error>> {
        let parent;
        let mut id;
        self.unselect_task();
        if let Some(role) = self.get_role() {
            id = IdTask::Number(role.as_ref().borrow().tasks.len() + 1);
            parent = Rc::downgrade(&role);
        } else {
            return Err("role not selected".into());
        }
        if let Some(pid) = pid {
            id = IdTask::Name(pid.to_owned());
        }
        self.new_task = Some(Task::new(id, parent));
        Ok(())
    }

    pub fn delete_new_task(&mut self) {
        self.new_task = None;
    }

    pub fn save_new_task(&mut self) {
        if let Some(task) = &self.new_task {
            task.as_ref()
                .borrow()
                .get_role()
                .unwrap()
                .borrow_mut()
                .tasks
                .push(task.to_owned());
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
    }

    pub fn select_task_by_index(&mut self, task_index: usize) -> Result<(), Box<dyn Error>> {
        let len = self.get_role().unwrap().as_ref().borrow().tasks.len();
        if task_index > len - 1 {
            Err("command not exist".into())
        } else {
            self.selected_task = Some(task_index);
            Ok(())
        }
    }

    pub fn select_task_by_id(&mut self, task_id: &IdTask) -> Result<(), Box<dyn Error>> {
        let mut index = None;
        for (i, t) in self
            .get_role()
            .unwrap()
            .as_ref()
            .borrow()
            .tasks
            .iter()
            .enumerate()
        {
            if t.as_ref().borrow().id == *task_id {
                index = Some(i);
                break;
            }
        }
        if let Some(index) = index {
            self.selected_task = Some(index);
            Ok(())
        } else {
            Err("task not exist".into())
        }
    }

    pub fn unselect_task(&mut self) {
        self.selected_task = None;
    }

    pub fn select_command(&mut self, command_index: usize) -> Result<(), Box<dyn Error>> {
        let len = self.get_task().unwrap().as_ref().borrow().commands.len();
        if command_index > len - 1 {
            Err("command not exist".into())
        } else {
            self.selected_command = Some(command_index);
            Ok(())
        }
    }

    pub fn delete_role(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(i) = self.selected_role {
            self.roles.as_ref().borrow_mut().roles.remove(i);
            self.unselect_role();
            Ok(())
        } else {
            Err("no role selected".into())
        }
    }

    pub fn delete_task(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(i) = self.selected_task {
            self.get_role()
                .unwrap()
                .as_ref()
                .borrow_mut()
                .tasks
                .remove(i);
            self.unselect_task();
            Ok(())
        } else {
            Err("no task selected".into())
        }
    }

    pub fn get_selected_role(&self) -> Option<Rc<RefCell<Role<'static>>>> {
        match self.selected_role {
            Some(i) => {
                return Some(self.roles.as_ref().borrow().roles[i].to_owned());
            }
            None => None,
        }
    }

    pub fn find_role(&self, name: &str) -> Option<Rc<RefCell<Role<'static>>>> {
        for role in self.roles.as_ref().borrow().roles.iter() {
            if role.as_ref().borrow().name == name {
                return Some(role.to_owned());
            }
        }
        None
    }

    pub fn get_role(&self) -> Option<Rc<RefCell<Role<'static>>>> {
        self.get_selected_role().or(self.get_new_role())
    }

    pub fn get_selected_task(&self) -> Option<Rc<RefCell<Task<'static>>>> {
        match self.selected_task {
            Some(i) => {
                let id = self.get_role().unwrap().as_ref().borrow().tasks[i].to_owned();
                Some(id)
            }
            None => None,
        }
    }

    pub fn get_task(&self) -> Option<Rc<RefCell<Task<'static>>>> {
        self.get_selected_task().or(self.get_new_task())
    }

    pub fn get_command(&self) -> Option<String> {
        match self.selected_command {
            Some(i) => {
                return Some(self.get_task().unwrap().as_ref().borrow().commands[i].to_string());
            }
            None => None,
        }
    }

    pub fn set_command(&mut self, command: String) -> Result<(), Box<dyn Error>> {
        match self.selected_command {
            Some(i) => {
                self.get_task().unwrap().borrow_mut().commands[i] = command;
                Ok(())
            }
            None => Err("no command selected".into()),
        }
    }

    /**
     * Return a OptStack that contains Opt in function of selections
     */
    pub fn get_options(&self) -> OptStack<'static> {
        if let Some(task) = self.get_task() {
            OptStack::from_task(task)
        } else if let Some(role) = self.get_role() {
            OptStack::from_role(role)
        } else {
            OptStack::from_roles(self.roles.to_owned())
        }
    }

    pub fn set_error(&mut self, error: Box<dyn Error>) {
        self.error = Some(error);
    }

    pub fn take_error(&mut self) -> Option<Box<dyn Error>> {
        self.error.take()
    }
}

impl Save for RoleContext {
    fn save(
        &self,
        _doc: Option<&Document>,
        _element: Option<&Element>,
    ) -> Result<bool, Box<dyn Error>> {
        save_config(FILENAME, &self.roles.as_ref().borrow(), true).map(|_| true)
    }
}
