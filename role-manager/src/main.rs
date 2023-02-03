mod config;
mod capabilities;
mod checklist;
mod options;
mod version;
mod state;

use std::{cell::{RefCell, Cell}, rc::Rc};

use cursive::{Cursive};
use libc::printf;
use options::{OptType, Opt, Optionnable, OptStack};
use state::{role::SelectRoleState, InitState};
use tracing_subscriber::FmtSubscriber;


pub enum ActorType {
    User,
    Group,
}

#[derive(Clone)]
pub struct RoleManager {
    roles: config::Roles,
    selected_role: Option<usize>,
    selected_commands: Option<usize>,
    selected_command: Option<usize>,
    selected_group: Option<usize>,
    selected_option: Option<OptType>,
    
}

pub struct RoleManagerApp {
    manager: RoleManager,
    state: Box<dyn state::State>,
}

impl RoleManager {

    pub fn new(roles : config::Roles) -> Self {
        RoleManager {
            roles,
            selected_role: None,
            selected_commands: None,
            selected_command: None,
            selected_group: None,
            selected_option: None,
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
        if self.selected_group.is_none() {
            panic!("No group selected");
        }
    }

    pub fn selected_group(&self) -> Option<config::Groups> {
        self.assert_selected_role();
        if self.selected_group.is_none() {
            return None;
        }
        Some(self.selected_role().unwrap().get_groups(self.selected_group.unwrap()))
    }

    pub fn replace_group(&mut self, group : Vec<String>) {
        self.assert_selected_group();
        self.selected_role().unwrap().set_groups(self.selected_group.unwrap(), group)
    }

    pub fn selected_command_group(&self) -> Option<config::Commands> {
        self.selected_commands.and(Some(self.selected_role().unwrap().get_commands(self.selected_commands.unwrap())))
    }

    pub fn selected_command_group_mut(&mut self) -> Option<*mut config::Commands> {
        self.selected_commands.and(Some(self.selected_role().unwrap().get_commands_mut(self.selected_commands.unwrap())))
    }

    pub fn selected_command_group_index(&self) -> usize {
        self.assert_selected_commands();
        self.selected_commands.unwrap()
    }

    pub fn selected_role(&self) -> Option<config::Role> {
        if let Some(selected_role) = self.selected_role {
            Some(self.roles().get_role(selected_role))
        } else {
            None
        }
    }

    pub fn selected_command(&self) -> Option<String> {
        if let Some(selected_command) = self.selected_command {
            Some(self.selected_command_group().unwrap().get_command(selected_command).to_string())
        } else {
            None
        }
    }

    pub fn selected_options(&self) -> Option<Rc<RefCell<Opt>>> {
        if let Some(selected_command_block) = self.selected_commands {
            self.selected_command_group().unwrap().get_options()
        } else if let Some(selected_role) = self.selected_role {
            self.selected_role().unwrap().get_options()
        } else {
            self.roles().get_options()
        }
    }

    pub fn get_optstack(&self) -> OptStack {
        if let Some(selected_command_block) = self.selected_commands {
            OptStack::from_commands(&self.roles(), &self.selected_role().unwrap(), &self.selected_command_group().unwrap())
        } else if let Some(selected_role) = self.selected_role {
            OptStack::from_role(&self.roles(), &self.selected_role().unwrap())
        } else {
            OptStack::from_roles(&self.roles())
        }
    }

    pub fn selected_option(&self) -> Option<OptType> {
        self.selected_option.clone()
    }

    pub fn selected_command_index(&self) -> Option<usize> {
        self.assert_selected_command();
        self.selected_command
    }

    pub fn roles(&self) -> config::Roles {
        self.roles.clone()
    }

    pub fn delete_selected_role(&mut self) {
        self.assert_selected_role();
        self.roles.remove_role(self.selected_role.unwrap());
        self.unset_selected_role();
    }

    pub fn delete_selected_commands_block(&mut self) {
        self.assert_selected_commands();
        self.selected_role().unwrap().remove_command_block(self.selected_commands.unwrap());
    }

    pub fn set_selected_role(&mut self, selected_role: usize) {
        self.selected_role.replace(selected_role);
        self.selected_commands = None;
        self.selected_command = None;
    }

    pub fn unset_selected_role(&mut self) {
        self.selected_role = None;
        self.unset_selected_command_group()
    }

    pub fn set_selected_command_group(&mut self, selected_commands: usize) {
        self.assert_selected_role();
        self.selected_commands.replace(selected_commands);
        self.selected_command = None;
    }

    pub fn unset_selected_command_group(&mut self) {
        self.selected_commands = None;
        self.unset_selected_command()
    }

    pub fn set_selected_command(&mut self, selected_command: usize) {
        self.assert_selected_role();
        self.assert_selected_commands();
        self.selected_command.replace(selected_command);
    }

    pub fn unset_selected_command(&mut self) {
        self.selected_command = None;
    }

    pub fn set_selected_group(&mut self, selected_group: usize) {
        self.assert_selected_role();
        self.selected_group.replace(selected_group);
    }

    pub fn unset_selected_group(&mut self) {
        self.selected_group = None;
    }
}

fn main(){
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
    let rc_role_manager = Rc::new(RefCell::new(RoleManager::new(roles)));
    let mut siv = cursive::default();
    //let caps = rc_role_manager.as_ref().borrow().selected_command_group().as_ref().borrow().get_capabilities();
    //siv.add_layer(select_capabilities(rc_role_manager.to_owned(), caps.into()));
    let app = RoleManagerApp {
        manager: rc_role_manager.as_ref().borrow().clone(),
        state : Box::new(SelectRoleState), 
    };
    

    siv.add_layer(SelectRoleState.init(&mut rc_role_manager.as_ref().borrow_mut()));
    
    siv.set_user_data(app);
    siv.run();

}