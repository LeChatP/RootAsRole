#[macro_use]
extern crate pest_derive;
extern crate pest;

mod config;
mod capabilities;
mod checklist;
mod options;
mod version;
mod state;
mod cli;
mod sudoers;


use std::{rc::Rc, cell::RefCell};

use cli::parse_args;
use config::{Commands, Role};
use cursive::{Cursive};
use options::{OptType, Opt, OptStack, Level};
use state::{role::SelectRoleState, InitState};
use tracing_subscriber::FmtSubscriber;


pub enum ActorType {
    User,
    Group,
}

#[derive(Debug)]
pub struct RoleManager {
    pub roles: config::Roles,
    selected_role: Option<usize>,
    selected_commands: Option<usize>,
    selected_command: Option<usize>,
    selected_groups: Option<usize>,
    selected_options: Option<OptType>,
    
}

pub struct RoleManagerApp {
    manager: RoleManager,
    state: Box<dyn state::State>,
}


impl RoleManager {
    pub fn new(roles: config::Roles) -> RoleManager {
        RoleManager {
            roles,
            selected_role: None,
            selected_commands: None,
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
        if self.selected_commands.is_none() {
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
        for (i, r) in self.roles.roles.iter().enumerate() {
            println!("{}: {} ({})", i, r.as_ref().borrow().name, r.as_ref().borrow().priority.unwrap_or(-1));
        }
    }

    pub fn select_role(&mut self, role_index: usize) -> Result<(), &'static str> {
        let len = self.roles.roles.len();
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
        let len = self.roles.roles[self.selected_role.unwrap()].as_ref().borrow().commands.len();
        if command_index > len - 1 {
            return Err("command not exist");
        } else {
            self.selected_commands = Some(command_index);
            return Ok(());
        }
    }

    pub fn unselect_commands(&mut self) {
        self.selected_commands = None;
        self.unselect_command();
        self.unselect_options();
    }

    pub fn select_command(&mut self, command_index: usize) -> Result<(), &'static str> {
        let len = self
            .roles
            .roles[self.selected_role.unwrap()].as_ref().borrow()
            .commands[self.selected_commands.unwrap()].borrow()
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
            .roles
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
        self.roles.roles.remove(self.selected_role.unwrap());
    }

    pub fn add_group(&mut self, group: Vec<String>) -> Result<(), &'static str> {
        if self.selected_role.is_some() {
            self.roles
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
                self.roles.options = Some(Rc::new(option.into()));
            }
            Level::Role => {
                match self.selected_role {
                    Some(i) => {
                        self.roles
                            .roles[i].as_ref().borrow_mut()
                            .options = Some(Rc::new(option.into()));
                    }
                    None => {
                        println!("no role selected");
                    }
                }
            }
            Level::Commands => {
                match self.selected_commands {
                    Some(i) => {
                        self.roles
                            .roles[self.selected_role.unwrap()].as_ref().borrow_mut()
                            .commands[i]
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

    pub fn get_role(&self) -> Option<Rc<RefCell<Role>>> {
        match self.selected_role {
            Some(i) => {
                return Some(self.roles.roles[i].clone());
            }
            None => {
                return None;
            }
        }
    }

    pub fn get_commands(&self) -> Option<Rc<RefCell<Commands>>> {
        match self.selected_commands {
            Some(i) => {
                return Some(self.roles.roles[self.selected_role.unwrap()].as_ref().borrow().commands[i].clone());
            }
            None => {
                return None;
            }
        }
    }

    pub fn get_commands_name(&self) -> Option<String> {
        match self.selected_commands {
            Some(i) => {
                if let Some(id) =  self.roles.roles[self.selected_role.unwrap()].as_ref().borrow().commands[i].borrow().id.clone() {
                    return Some(id);
                } else {
                    return Some(format!("Block #{}", i));
                }
            }
            None => {
                return None;
            }
        }
    }

    pub fn get_commands_index(&self) -> Option<usize> {
        return self.selected_commands;
    }

    pub fn get_command(&self) -> Option<String> {
        match self.selected_command {
            Some(i) => {
                return Some(self.roles.roles[self.selected_role.unwrap()].as_ref().borrow().commands[self.selected_commands.unwrap()].borrow().commands[i].clone());
            }
            None => {
                return None;
            }
        }
    }

    pub fn set_command(&mut self, command: String) -> Result<(), &'static str> {
        match self.selected_command {
            Some(i) => {
                self.roles.roles[self.selected_role.unwrap()].as_ref().borrow().commands[self.selected_commands.unwrap()].borrow_mut().commands[i] = command;
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
                return Some(self.roles.roles[self.selected_role.unwrap()].as_ref().borrow().groups[i].clone());
            }
            None => {
                return None;
            }
        }
    }

    pub fn set_group(&mut self, group: Vec<String>) -> Result<(), &'static str> {
        match self.selected_groups {
            Some(i) => {
                self.roles.roles[self.selected_role.unwrap()].as_ref().borrow_mut().groups[i] = group;
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
        if self.selected_commands.is_some() {
            OptStack::from_commands(&self.roles, &self.selected_role.unwrap(), &self.selected_commands.unwrap())
        } else if self.selected_role.is_some() {
            OptStack::from_role(&self.roles, &self.selected_role.unwrap())
        } else {
            OptStack::from_roles(&self.roles)
        }
    }

    pub fn saveall(&self) {
        config::save_all(&self.roles);
    }
}

fn main(){
    parse_args();
    return;
    // a builder for `FmtSubscriber`.
    let subscriber = FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(tracing::Level::TRACE)
        // completes the builder.
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let roles = config::load_roles().expect("Failed to load roles");
    let mut rc_role_manager = RoleManager::new(roles);
    let mut siv = cursive::default();
    //let caps = rc_role_manager.as_ref().borrow().selected_command_group().as_ref().borrow().get_capabilities();
    //siv.add_layer(select_capabilities(rc_role_manager.to_owned(), caps.into()));
    
    

    siv.add_layer(SelectRoleState.init(&mut rc_role_manager));

    let app = RoleManagerApp {
        manager: rc_role_manager,
        state : Box::new(SelectRoleState), 
    };
    
    siv.set_user_data(app);
    siv.run();

}