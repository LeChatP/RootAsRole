

use std::cell::{RefCell};
use std::rc::Rc;

use crate::config::{self, Role, Task, Save};
use crate::options::{OptType, Opt, OptStack, Level};

#[derive(Debug)]
pub struct RoleContext {
    pub roles: Rc<RefCell<config::Roles<'static>>>,
    selected_role: Option<usize>,
    selected_task: Option<usize>,
    selected_command: Option<usize>,
    selected_groups: Option<usize>,
    selected_options: Option<OptType>,
    
}

impl RoleContext {
    pub fn new(roles: Rc<RefCell<config::Roles<'static>>>) -> RoleContext {
        RoleContext {
            roles,
            selected_role: None,
            selected_task: None,
            selected_command: None,
            selected_groups: None,
            selected_options: None,
        }
    }
    
    fn assert_selected_role(&self) {
        if self.selected_role.is_none() {
            panic!("No role selected");
        }
    }

    fn assert_selected_commands(&self) {
        if self.selected_task.is_none() {
            panic!("No commands selected");
        }
    }

    fn assert_selected_command(&self) {
        if self.selected_command.is_none() {
            panic!("No command selected");
        }
    }

    fn assert_selected_group(&self) {
        if self.selected_groups.is_none() {
            panic!("No group selected");
        }
    }

    pub fn list_roles(&self) {
        println!("Roles:");
        for (i, r) in self.roles.as_ref().borrow().roles.iter().enumerate() {
            println!("{}: {}", i, r.as_ref().borrow().name);
        }
    }

    pub fn select_role(&mut self, role_index: usize) -> Result<(), &'static str> {
        let len = self.roles.as_ref().borrow().roles.len();
        if role_index > len - 1 {
            return Err("role not exist");
        } else {
            self.selected_role = Some(role_index);
            return Ok(());
        }
    }

    pub fn unselected_role(&mut self) {
        self.selected_role = None;
        self.unselect_commands();
        self.unselect_groups();
        self.unselect_options();
    }

    pub fn select_commands(&mut self, command_index: usize) -> Result<(), &'static str> {
        let len = self.roles.as_ref().borrow().roles[self.selected_role.unwrap()].as_ref().borrow().tasks.len();
        if command_index > len - 1 {
            return Err("command not exist");
        } else {
            self.selected_task = Some(command_index);
            return Ok(());
        }
    }

    pub fn unselect_commands(&mut self) {
        self.selected_task = None;
        self.unselect_command();
        self.unselect_options();
    }

    pub fn select_command(&mut self, command_index: usize) -> Result<(), &'static str> {
        let len = self
            .roles.as_ref().borrow()
            .roles[self.selected_role.unwrap()].as_ref().borrow()
            .tasks[self.selected_task.unwrap()].borrow()
            .commands
            .len();
        if command_index > len - 1 {
            return Err("command not exist");
        } else {
            self.selected_command = Some(command_index);
            return Ok(());
        }
    }

    pub fn unselect_command(&mut self) {
        self.selected_command = None;
    }

    pub fn select_groups(&mut self, group_index: usize) -> Result<(), &'static str> {
        let len = self
            .roles.as_ref().borrow()
            .roles[self.selected_role.unwrap()].as_ref().borrow()
            .groups
            .len();
        if group_index > len - 1 {
            return Err("groups not exist");
        } else {
            self.selected_groups = Some(group_index);
            return Ok(());
        }
    }

    pub fn unselect_groups(&mut self) {
        self.selected_groups = None;
    }

    pub fn select_options(&mut self, option_type: OptType) -> Result<(), &'static str> {
        self.selected_options = Some(option_type);
        return Ok(());
    }

    pub fn unselect_options(&mut self) {
        self.selected_options = None;
    }

    pub fn delete_role(&mut self) {
        self.roles.as_ref().borrow_mut()
        .roles.remove(self.selected_role.unwrap());
    }

    pub fn add_group(&mut self, group: Vec<String>) -> Result<(), &'static str> {
        if self.selected_role.is_some() {
            self.roles.as_ref().borrow()
                .roles[self.selected_role.unwrap()].as_ref().borrow_mut()
                .groups
                .push(group);
            return Ok(());
        } else {
            return Err("no role selected");
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

    pub fn get_role(&self) -> Option<Rc<RefCell<Role<'static>>>> {
        match self.selected_role {
            Some(i) => {
                return Some(self.roles.as_ref().borrow().roles[i].clone());
            }
            None => {
                return None;
            }
        }
    }

    pub fn get_task(&self) -> Option<Rc<RefCell<Task<'static>>>> {
        match self.selected_task {
            Some(i) => {
                let id = self.roles.as_ref().borrow().roles[self.selected_role.unwrap()].borrow().tasks[i].clone();
                return Some(id);
            }
            None => {
                return None;
            }
        }
    }

    pub fn get_commands_index(&self) -> Option<usize> {
        return self.selected_task;
    }

    pub fn get_command(&self) -> Option<String> {
        match self.selected_command {
            Some(i) => {
                return Some(self.roles.as_ref().borrow().roles[self.selected_role.unwrap()].as_ref().borrow().tasks[self.selected_task.unwrap()].borrow().commands[i].clone());
            }
            None => {
                return None;
            }
        }
    }

    pub fn set_command(&mut self, command: String) -> Result<(), &'static str> {
        match self.selected_command {
            Some(i) => {
                self.roles.as_ref().borrow().roles[self.selected_role.unwrap()].as_ref().borrow().tasks[self.selected_task.unwrap()].borrow_mut().commands[i] = command;
                return Ok(());
            }
            None => {
                return Err("no command selected");
            }
        }
    }

    pub fn get_group(&self) -> Option<Vec<String>> {
        match self.selected_groups {
            Some(i) => {
                return Some(self.roles.as_ref().borrow().roles[self.selected_role.unwrap()].as_ref().borrow().groups[i].clone());
            }
            None => {
                return None;
            }
        }
    }

    pub fn set_group(&mut self, group: Vec<String>) -> Result<(), &'static str> {
        match self.selected_groups {
            Some(i) => {
                self.roles.as_ref().borrow().roles[self.selected_role.unwrap()].as_ref().borrow_mut().groups[i] = group;
                return Ok(());
            }
            None => {
                return Err("no group selected");
            }
        }
    }

/**
* Return a OptStack that contains Opt in function of selections
*/
    pub fn get_options(&self) -> OptStack  {
        if self.selected_task.is_some() {
            OptStack::from_commands(&self.roles.as_ref().borrow(), &self.selected_role.unwrap(), &self.selected_task.unwrap())
        } else if self.selected_role.is_some() {
            OptStack::from_role(&self.roles.as_ref().borrow(), &self.selected_role.unwrap())
        } else {
            OptStack::from_roles(&self.roles.as_ref().borrow())
        }
    }

    pub fn saveall(&self) {
        self.roles.as_ref().borrow().save("/etc/security/rootasrole.xml");
    }
}

