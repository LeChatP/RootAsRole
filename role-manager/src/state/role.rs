use std::cell::RefCell;
use std::rc::Rc;

use super::actor::{SelectGroupState, SelectUserState};
use super::common::{ConfirmState, InputState};
use super::options::SelectOptionState;
use super::task::SelectTaskState;
use super::{execute, ExecuteType, InitState, Input, State, DeletableItemState, PushableItemState};

use cursive::direction::Orientation;
use cursive::event::Event;
use cursive::view::{Nameable, Scrollable};
use cursive::views::{Dialog, EditView, LinearLayout, SelectView, TextView};
use cursive::Cursive;

use crate::config::Role;
use crate::{RoleContext, RoleManagerApp};

#[derive(Clone)]
pub struct SelectRoleState;

#[derive(Clone)]
pub struct EditRoleState;

/**
 * List roles and allow editing, creation and deletion of roles
 */
impl State for SelectRoleState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(InputState::<EditRoleState,SelectRoleState>::new_with_next(self,Box::new(EditRoleState), "Enter the new role name:", None))
    }

    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        if let Err(err) = manager.select_role(index) {
            manager.set_error(err);
        }
        Box::new(ConfirmState::new(self, format!("Delete Role {}?", manager.get_role().unwrap().borrow().name).as_str(), index))
    }

    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        if let Err(err) = manager.select_role(index) {
            manager.set_error(err);
        }
        Box::new(EditRoleState)
    }

    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        manager.unselect_role();
        Box::new(SelectRoleState)
    }

    fn confirm(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        if let Err(err) = manager.saveall() {
            manager.set_error(err);
        }
        Box::new(SelectRoleState)
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectOptionState::new(*self))
    }

    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }

    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        cursive.add_layer(self.init(manager));
    }
}

impl Into<Box<SelectRoleState>> for Box<EditRoleState> {
    fn into(self) -> Box<SelectRoleState> {
        Box::new(SelectRoleState)
    }
}

impl DeletableItemState for SelectRoleState {
    fn remove_selected(&mut self, manager: &mut RoleContext, index: usize) {
        if let Err(err) = manager.delete_role() {
            manager.set_error(err);
        }
    }
}

impl InitState for SelectRoleState {
    fn init(&self, manager: &mut RoleContext) -> Dialog {
        let mut select = SelectView::new()
            .autojump()
            .on_select(move |s, item| {
                let RoleManagerApp { manager, state } = s.take_user_data().unwrap();
                let info = s.find_name::<TextView>("info");
                if let Some(mut info) = info {
                    let binding: &Rc<RefCell<Role>> = &manager.roles.as_ref().borrow().roles[*item];
                    info.set_content(binding.as_ref().borrow().get_description());
                }
                s.set_user_data(RoleManagerApp { manager, state });
            })
            .on_submit(|s, item| {
                execute(s, ExecuteType::Submit(*item));
            });
        let mut pos = 0;
        for role in &manager.roles.as_ref().borrow().roles {
            select.add_item(role.as_ref().borrow().name.to_owned(), pos);
            pos += 1;
        }
        let mut layout = LinearLayout::new(Orientation::Horizontal);
        layout.add_child(select.with_name("roles").scrollable());
        println!("{:?}", manager.roles);
        layout.add_child(
            TextView::new(
                manager
                    .roles.as_ref().borrow()
                    .roles
                    .get(0)
                    .unwrap()
                    .as_ref()
                    .borrow()
                    .get_description()
            )
            .with_name("info"),
        );
        Dialog::around(layout)
            .title("Select a role")
            .button("New Role", move |s| {
                execute(s, ExecuteType::Create);
            })
            .button("Options", move |s| {
                execute(s, ExecuteType::Config);
            })
            .button("Exit Without Saving", move |s| {
                s.quit();
            })
            .button("Save & Quit", move |s| {
                execute(s, ExecuteType::Confirm);
                s.quit();
            })
    }
}


impl State for EditRoleState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn delete(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        match index {
            0 => Box::new(SelectUserState::new(
                true,
                Some(manager.get_role().unwrap().as_ref().borrow().users.to_owned()),
            )),
            1 => Box::new(SelectGroupState),
            2 => Box::new(SelectTaskState),
            3 => Box::new(SelectOptionState::new(*self)),
            _ => self,
        }
    }

    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        if manager.get_new_role().is_some() {
            manager.delete_new_role();
        }
        Box::new(SelectRoleState)
    }

    fn confirm(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        if manager.get_new_role().is_some() {
            manager.save_new_role();
        }
        Box::new(SelectRoleState)
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectOptionState::new(*self))
    }

    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }

    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = SelectView::new()
            .autojump()
            .on_select(move |s, item| {
                let RoleManagerApp { manager, state } = s.take_user_data().unwrap();
                let info = s.find_name::<TextView>("info");
                if let Some(mut info) = info {
                    match item {
                        0 => {
                            info.set_content(
                                manager
                                    .get_role()
                                    .unwrap()
                                    .as_ref()
                                    .borrow()
                                    .get_users_info(),
                            );
                        }
                        1 => {
                            info.set_content(
                                manager
                                    .get_role()
                                    .unwrap()
                                    .as_ref()
                                    .borrow()
                                    .get_groups_info(),
                            );
                        }
                        2 => {
                            info.set_content(
                                manager
                                    .get_role()
                                    .unwrap()
                                    .as_ref()
                                    .borrow()
                                    .get_tasks_info(),
                            );
                        },
                        3 => {
                            info.set_content(
                                manager
                                    .get_role()
                                    .unwrap()
                                    .as_ref()
                                    .borrow()
                                    .get_options_info(),
                            );
                        }
                        _ => {
                            info.set_content("Unknown");
                        }
                    }
                }
                s.set_user_data(RoleManagerApp { manager, state })
            })
            .on_submit(move |s, item| {
                execute(s, ExecuteType::Submit(*item));
            });
        select.add_all([("Edit Users", 0), ("Edit Groups", 1), ("Edit Tasks", 2), ("Edit Options", 3)]);
        let mut layout = LinearLayout::new(Orientation::Horizontal);
        layout.add_child(select.with_name("commands").scrollable());
        let title ;
        let role = manager
        .get_role();
        if role.is_none() {
            manager.set_error("No role selected".into());
            return;
        }
        let role = role.unwrap();
        layout.add_child(
            TextView::new(
                
                    role
                    .as_ref()
                    .borrow()
                    .get_users_info(),
            )
            .with_name("info")
        );

        match manager.is_new() {
            true => title = format!("Edit role {}", role.as_ref().borrow().name),
            false => title = format!("Create the role {}", role.as_ref().borrow().name),
        }
        
        cursive.add_layer(
            Dialog::around(layout)
                .title(title)
                .button("Cancel", move |s| {
                    execute(s, ExecuteType::Cancel);
                })
                .button("Save", move |s| {
                    execute(s, ExecuteType::Confirm);
                }),
        );
    }
}

impl PushableItemState<String> for EditRoleState {
    fn push(&mut self, manager: &mut RoleContext, item: String) {
        manager.create_new_role(item);
    }
}