mod config;
mod capabilities;
mod checklist;
mod options;
mod version;
mod state;

use std::{cell::{RefCell, Cell}, rc::Rc};

use capabilities::Caps;
use checklist::CheckListView;
use cursive::{views::{Dialog, TextView, LinearLayout, SelectView}, direction::Orientation, view::{Scrollable, Nameable, self}, Cursive, event::{Event, Key}};
use options::{OptType, Opt, Optionnable, OptStack};
use state::{role::SelectRoleState, InitState};
use tracing_subscriber::FmtSubscriber;
use users::all_users;

enum ActorType {
    User,
    Group,
}

#[derive(Clone)]
pub struct RoleManager {
    roles: Rc<RefCell<config::Roles>>,
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

    pub fn new(roles : Rc<RefCell<config::Roles>>) -> Self {
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

    pub fn selected_gid_group_list(&self) -> Option<Cell<config::Groups>> {
        self.assert_selected_role();
        if self.selected_group.is_none() {
            return None;
        }
        Some(self.selected_role().as_ref().borrow().get_groups(self.selected_group.unwrap()))
    }

    pub fn replace_gid_group_list(&mut self, group : Vec<String>) {
        self.assert_selected_group();
        self.selected_role().as_ref().borrow_mut().set_groups(self.selected_group.unwrap(), group)
    }

    pub fn selected_command_group(&self) -> Rc<RefCell<config::Commands>> {
        self.assert_selected_commands();
        self.selected_role().as_ref().borrow().get_commands(self.selected_commands.unwrap())
    }

    pub fn selected_command_group_index(&self) -> usize {
        self.assert_selected_commands();
        self.selected_commands.unwrap()
    }

    pub fn selected_role(&self) -> Rc<RefCell<config::Role>> {
        self.assert_selected_role();
        self.roles().as_ref().borrow().get_role(self.selected_role.unwrap())
    }

    pub fn selected_command(&self) -> Option<String> {
        self.selected_command.and(Some( self.selected_command_group().as_ref().borrow().get_command(self.selected_command.unwrap()).to_string()))
    }

    pub fn selected_options(&self) -> Option<Rc<RefCell<Opt>>> {
        if let Some(selected_command_block) = self.selected_commands {
            self.selected_command_group().as_ref().borrow().get_options()
        } else if let Some(selected_role) = self.selected_role {
            self.selected_role().as_ref().borrow().get_options()
        } else {
            self.roles().as_ref().borrow().get_options()
        }
    }

    pub fn get_optstack(&self) -> OptStack {
        if let Some(selected_command_block) = self.selected_commands {
            OptStack::from_commands(&self.roles().as_ref().borrow(), &self.selected_role().as_ref().borrow(), &self.selected_command_group().as_ref().borrow())
        } else if let Some(selected_role) = self.selected_role {
            OptStack::from_role(&self.roles().as_ref().borrow(), &self.selected_role().as_ref().borrow())
        } else {
            OptStack::from_roles(&self.roles().as_ref().borrow())
        }
    }

    pub fn selected_option(&self) -> Option<OptType> {
        self.selected_option.clone()
    }

    pub fn selected_command_index(&self) -> Option<usize> {
        self.assert_selected_command();
        self.selected_command
    }

    pub fn roles(&self) -> Rc<RefCell<config::Roles>> {
        self.roles.clone()
    }

    pub fn delete_selected_role(&mut self) {
        self.assert_selected_role();
        self.roles.as_ref().borrow_mut().remove_role(self.selected_role.unwrap());
        self.unset_selected_role();
    }

    pub fn delete_selected_commands_block(&mut self) {
        self.assert_selected_commands();
        self.selected_role().borrow_mut().remove_command_block(self.selected_commands.unwrap());
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


fn view_select_role(role_manager : Rc<RefCell<RoleManager>>) -> Dialog {
    let rc_role_manager = role_manager.clone();
    let mut select = SelectView::new().autojump()
        .on_select(move |s, item| {
            let info = s.find_name::<TextView>("info");
            if let Some(mut info) = info {
                info.set_content(rc_role_manager.as_ref().borrow().roles().as_ref().borrow().get_role(*item).as_ref().borrow().get_description());
            }
        });
    let mut pos = 0;
    for role in role_manager.as_ref().borrow().roles().as_ref().borrow().get_roles_list() {
        select.add_item(role.as_ref().borrow().get_name().clone(), pos);
        pos+=1;
    }
    let mut layout = LinearLayout::new(Orientation::Horizontal);
    layout.add_child(select.with_name("roles").scrollable());
    
    layout.add_child(TextView::new("Select a role").with_name("info"));
    Dialog::around( layout)
        .title("Select a role")
        .button("Ok",  move|s| {
            
            let commands =  role_manager.clone();
            
            s.call_on_name("roles",  move|view: &mut SelectView<usize>| {
                commands.clone().as_ref().borrow_mut().set_selected_role(*view.selection().unwrap());
            });
            s.add_layer(view_role(role_manager.clone()));

        })
        
}

fn view_actors(role_manager : Rc<RefCell<RoleManager>>, actor : ActorType) -> Dialog {
    let rc_add = role_manager.clone();
    let rc_del = role_manager.clone();
    let rc_loc = role_manager.clone();
    let mut select = SelectView::new().autojump();
    let mut pos = 0;
    let binding = rc_loc.as_ref().borrow().selected_role();
    let binding = binding.as_ref().borrow();
    let actors = match actor {
        ActorType::User => {
            binding.get_users_list().clone()
        },
        ActorType::Group => {
            binding.get_groups_list().iter().map(|s| s.join(",").to_string()).collect::<Vec<String>>()
        }
    };
    for user in actors {
        select.add_item(user.clone(), pos);
        pos+=1;
    }

    Dialog::around( select.autojump().with_name("actors").scrollable())
        .title("Select actor")
        .button("Del",  move|s| {
            let rc =  rc_del.clone();
            s.call_on_name("actors",  move|view: &mut SelectView<usize>| {
                rc.clone().as_ref().borrow().selected_role().as_ref().borrow_mut().remove_user(*view.selection().unwrap());
                view.remove_item(*view.selection().unwrap())
            });

        })
        .button("Add",  move|s| {
            s.add_layer(add_user(rc_add.clone(), &rc_add.as_ref().borrow().selected_role().as_ref().borrow().get_users_list()));
        })
        .button("Ok",  |s| {
            s.pop_layer();
        })
}

fn add_user(role_manager : Rc<RefCell<RoleManager>>, users_in_role : &Vec<String>) -> Dialog {
    let rc_role_manager = role_manager.clone();
    let mut select = SelectView::new().autojump()
        .on_submit(move |s, item| {
            rc_role_manager.as_ref().borrow().selected_role().as_ref().borrow_mut().add_user(item);
        });
    let users = unsafe { all_users() };
    for user in users {
        let username = &user.name().to_str().unwrap().to_string();
        if !users_in_role.contains(username) {
            select.add_item(username.clone(), username.clone());
        }
    }
    Dialog::around( select.autojump().with_name("users").scrollable())
        .title("Select a user to add to the role")
}

fn view_role(role_manager : Rc<RefCell<RoleManager>>) -> Dialog {
    let rc_role_manager = role_manager.clone();
    let mut select = SelectView::new().autojump()
        .on_select(move |s, item| {
            let info = s.find_name::<TextView>("info");
            if let Some(mut info) = info {
                match item{
                    0 => {
                        info.set_content(role_manager.as_ref().borrow().selected_role().as_ref().borrow().get_users_info());
                    },
                    1 => {
                        info.set_content(role_manager.as_ref().borrow().selected_role().as_ref().borrow().get_groups_info());
                    },
                    2 => {
                        info.set_content(role_manager.as_ref().borrow().selected_role().as_ref().borrow().get_commands_info());
                    },
                    _ => {
                        info.set_content("Unknown");
                    }
                }
            }
        })
        .on_submit( move|s, item| {
            let rc = rc_role_manager.clone();
            match item {
                0 => {
                    let rc_actors = rc.clone();
                    s.add_global_callback(Event::Key(Key::Del), move |s| {
                        let rc_call = rc.clone();
                        s.call_on_name("actors",  move|view: &mut SelectView<usize>| {
                            rc_call.clone().as_ref().borrow().selected_role().as_ref().borrow_mut().remove_user(*view.selection().unwrap());
                            view.remove_item(*view.selection().unwrap())
                        });
                    });
                    s.add_layer(view_actors(rc_actors.clone(), ActorType::User));
                },
                1 => {
                    s.add_layer(view_actors(rc, ActorType::Group));
                },
                2 => {
                    //s.add_layer(view_commands(commands));
                },
                _ => {
                    s.add_layer(Dialog::info("Unknown"));
                }
            }
        });
    select.add_all([
        ("Edit Users",0),
        ("Edit Groups",1),
        ("Edit Commands",2),
    ]);
    let mut layout = LinearLayout::new(Orientation::Horizontal);
    layout.add_child(select.with_name("commands").scrollable());
    
    layout.add_child(TextView::new("Select a commands").with_name("info"));
    Dialog::around( layout)
        .title("Edit a role")
        .button("Save",  move|s| {
            s.pop_layer();
            //role_manager.as_ref().borrow_mut().save();
        })
        
}

fn select_capabilities(role_manager : Rc<RefCell<RoleManager>>,selected : u64) -> Dialog {
    let mut select = checklist::CheckListView::<(&str,&str)>::new().autojump()
        .on_select(|s, item| {
            let info = s.find_name::<TextView>("info");
            if let Some(mut info) = info {
                info.set_content(item.1);
            }
        });
    
    let mut pos = 0;
    for capability in capabilities::POSITIONS {
        select.add_item(capability.0.clone(), selected & (1 << pos) != 0, capability);
        pos+=1;
    }
    let mut layout = LinearLayout::new(Orientation::Horizontal);
    layout.add_child(select.with_name("capabilities").scrollable());
    
    layout.add_child(TextView::new(capabilities::POSITIONS[0].1).with_name("info"));
    Dialog::around( layout)
        .title("Select capabilities, CTRL+A to check all, CTRL+U to uncheck all and CTRL+D to invert selection")
        .button("Ok",  move|s| {
            
            let commands =  role_manager.as_ref();
            
            s.call_on_name("capabilities",  move|view: &mut CheckListView<(&str, &str)>| {
                let mut caps = Caps::V2(0);
                for (pos, item) in view.iter().enumerate() {
                    if *item.1 {
                        caps |= 1 << pos;
                    }
                }
                commands.borrow().selected_command_group().borrow_mut().set_capabilities(caps);
            });
            
            
            //self.get_mut_commands().capabilities = Some(capabilities);
            s.pop_layer();
        })
        
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