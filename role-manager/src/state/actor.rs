use std::ffi::CStr;

use cursive::{views::{SelectView, Dialog, EditView}, Cursive, view::Nameable};
use libc::{getgrent, setgrent, endgrent, setpwent, getpwent, endpwent};


use crate::{RoleManager, RoleManagerApp, checklist::CheckListView, ActorType};

use super::{State, role::EditRoleState, Input, ExecuteType, execute};
pub struct SelectUserState;
pub struct CreateUserState;
pub struct DeleteUserState;
pub struct EditUserState;

pub struct SelectGroupState;
pub struct CreateGroupState;
pub struct DeleteGroupState;
pub struct EditGroupState;

fn get_groups() -> Vec<String> {
    let mut groups = Vec::new();
    unsafe{setgrent()};
    let mut group = unsafe { getgrent().as_mut() };
    while !group.is_none() {
        let gr = unsafe { group.unwrap() };
        groups.push(unsafe { CStr::from_ptr(gr.gr_name).to_str().unwrap().to_string() });
        group = unsafe { getgrent().as_mut() };
    }
    unsafe{endgrent()};
    groups
}

fn get_users() -> Vec<String> {
    let mut users = Vec::new();
    unsafe {setpwent()};
    let mut pwentry = unsafe { getpwent().as_mut() };
    while !pwentry.is_none() {
        let user = unsafe { pwentry.unwrap() };
        users.push(unsafe { CStr::from_ptr(user.pw_name).to_str().unwrap().to_string() });
        pwentry = unsafe { getpwent().as_mut() };
    }
    unsafe {endpwent()};
    users
}

fn add_actors(actortype : ActorType,view : &mut CheckListView<String>, already_in_list : Option<Vec<String>>){
    let actors = match actortype {
        ActorType::User => {
            get_users()
        },
        ActorType::Group => {
            get_groups()
        },
        _ => panic!("Invalid state"),
    };
    let some =  already_in_list.is_some();
    for user in actors {
        view.add_item(user.clone(), some && already_in_list.as_ref().unwrap().contains(&user), user.clone());
    }
}

impl State for SelectUserState {
    fn create(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        Box::new(CreateUserState)
    }

    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State> {
        self
    }

    fn cancel(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        Box::new(EditRoleState)
    }

    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        Box::new(EditRoleState)
    }

    fn config(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State> {
        self
    }

    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive) {
        let mut select = CheckListView::<String>::new().autojump();
        add_actors(ActorType::User, &mut select, Some(manager.selected_role().borrow().get_users_list().to_vec()));
        cursive.add_layer(
            Dialog::around(select)
            .title("Select User")
            .button("Input new user", |s| {
                execute(s,ExecuteType::Create);
            })
            .button("Cancel", |s| {
                execute(s,ExecuteType::Cancel);
            })
            .button("Ok", |s| {
                execute(s,ExecuteType::Confirm);
            })
        );
    }
}
impl State for CreateUserState {
    fn create(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        self
    }

    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State> {
        self
    }

    fn cancel(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        Box::new(SelectUserState)
    }

    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        self
    }

    fn config(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State> {
        manager.selected_role().borrow_mut().add_user(&input.as_string());
        Box::new(SelectUserState)
    }

    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive) {
        let mut input = EditView::new();
        cursive.add_layer(Dialog::around( input.with_name("input"))
            .title("Enter username or uid")
            .button("Cancel", |s| {
                execute(s,ExecuteType::Cancel);
            })
            .button("Confirm", |s| {
                let input = s.find_name::<EditView>("input").unwrap();
                execute(s,ExecuteType::Input( Input::String(input.get_content().as_str().into())));
            }));
    }
}

impl State for SelectGroupState {
    fn create(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        Box::new(EditGroupState)
    }

    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State> {
        manager.set_selected_group(index);
        Box::new(EditGroupState)
    }

    fn cancel(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        Box::new(EditRoleState)
    }

    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        self
    }

    fn config(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State> {
        self
    }

    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive) {
        let mut select = SelectView::<usize>::new().autojump()
        .on_submit(|s, item| {
            execute(s,ExecuteType::Submit( *item));
        });
        for (index, group) in manager.selected_role().borrow().get_groups_list().iter().enumerate() {
            select.add_item(group.join(" & "),index);
        }
        cursive.add_layer(Dialog::around( select)
            .title("Select Group List to Edit")
            .button("Cancel", |s| {
                execute(s,ExecuteType::Cancel);
            })
            .button("Add",  move|s| {
                execute(s,ExecuteType::Create);
            }));
    }
}

impl State for EditGroupState {
    fn create(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        self
    }

    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State> {
        self
    }

    fn cancel(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        Box::new(SelectGroupState)
    }

    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        self
    }

    fn config(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State> {
        if manager.selected_gid_group_list().is_some() {
            manager.replace_gid_group_list(input.as_vec());
        }
        Box::new(SelectGroupState)
    }

    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive) {
        let mut select = CheckListView::<String>::new().autojump();
        add_actors(ActorType::Group, &mut select, Some(manager.selected_gid_group_list().unwrap().take().to_vec()));
        cursive.add_layer(
            Dialog::around(select.with_name("select"))
            .title("Select Group")
            .button("Input new group", |s| {
                execute(s,ExecuteType::Create);
            })
            .button("Cancel", |s| {
                execute(s,ExecuteType::Cancel);
            })
            .button("Ok", |s| {
                let mut res = None;
                s.call_on_name("select", |view : &mut CheckListView<String>| {
                    res = Some(Input::Vec(view.iter().filter_map(|(_,checked, group)| {
                        if *checked { Some(group.to_string()) } else { None }
                    }).collect()));
                });
                execute(s,ExecuteType::Input(res.expect("No input")));
            })
        );
    }
}