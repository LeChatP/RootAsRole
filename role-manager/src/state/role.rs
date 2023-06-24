use std::cell::RefCell;
use std::rc::Rc;

use super::actor::{SelectGroupState, SelectUserState};
use super::command::SelectTaskState;
use super::options::SelectOptionState;
use super::{execute, ExecuteType, InitState, Input, State};

use cursive::direction::Orientation;
use cursive::view::{Nameable, Scrollable};
use cursive::views::{Dialog, EditView, LinearLayout, SelectView, TextView};
use cursive::Cursive;

use crate::config::Role;
use crate::{RoleContext, RoleManagerApp};

pub struct SelectRoleState;
pub struct CreateRoleState;
pub struct DeleteRoleState;
pub struct EditRoleState;

/**
 * List roles and allow editing, creation and deletion of roles
 */
impl State for SelectRoleState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(CreateRoleState)
    }

    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        if let Err(err) = manager.select_role(index) {
            manager.set_error(err);
        }
        Box::new(DeleteRoleState)
    }

    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        if let Err(err) = manager.select_role(index) {
            manager.set_error(err);
        }
        Box::new(EditRoleState)
    }

    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        manager.unselected_role();
        Box::new(SelectRoleState)
    }

    fn confirm(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        if let Err(err) = manager.saveall() {
            manager.set_error(err);
        }
        Box::new(SelectRoleState)
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectOptionState::new())
    }

    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }

    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        cursive.add_layer(self.init(manager));
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
            select.add_item(role.as_ref().borrow().name.clone(), pos);
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
                    .clone(),
            )
            .with_name("info"),
        );
        Dialog::around(layout)
            .title("Select a role")
            .button("Create", move |s| {
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

impl State for CreateRoleState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn delete(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectRoleState)
    }

    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        let role = Role::new(input.as_string().trim().to_owned(), Some(Rc::downgrade(&manager.roles)));
        manager.roles.as_ref().borrow_mut().roles.push(role.clone());
        Box::new(EditRoleState)
    }

    fn render(&self, _manager: &mut RoleContext, cursive: &mut Cursive) {
        let text = EditView::new().with_name("name");
        cursive.add_layer(
            Dialog::around(text)
                .title("Enter a name for the new role")
                .button("Create", move |s| {
                    let name = s.find_name::<EditView>("name");
                    if let Some(name) = name {
                        execute(
                            s,
                            ExecuteType::Input(Input::String(name.get_content().to_string())),
                        );
                    }
                })
                .button("Cancel", move |s| {
                    execute(s, ExecuteType::Cancel);
                }),
        );
    }
}

impl State for DeleteRoleState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn delete(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectRoleState)
    }

    fn confirm(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        manager.delete_role();
        Box::new(SelectRoleState)
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }

    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        cursive.add_layer(
            Dialog::around(TextView::new(format!(
                "Are you sure you want to delete the role {}?",
                manager.get_role().unwrap().as_ref().borrow().name
            )))
            .title("Confirm delete role")
            .button("Yes", move |s| {
                execute(s, ExecuteType::Confirm);
            })
            .button("No", move |s| {
                execute(s, ExecuteType::Cancel);
            }),
        );
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
                Some(manager.get_role().unwrap().as_ref().borrow().users.clone()),
            )),
            1 => Box::new(SelectGroupState),
            2 => Box::new(SelectTaskState),
            _ => self,
        }
    }

    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectRoleState)
    }

    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        //TODO: save
        Box::new(SelectRoleState)
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectOptionState::new())
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
                                    .get_commands_info(),
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
        select.add_all([("Edit Users", 0), ("Edit Groups", 1), ("Edit Commands", 2)]);
        let mut layout = LinearLayout::new(Orientation::Horizontal);
        layout.add_child(select.with_name("commands").scrollable());
        layout.add_child(
            TextView::new(
                manager
                    .get_role()
                    .unwrap()
                    .as_ref()
                    .borrow()
                    .get_users_info(),
            )
            .with_name("info"),
        );
        cursive.add_layer(
            Dialog::around(layout)
                .title("Edit a role")
                .button("Save", move |s| {
                    execute(s, ExecuteType::Confirm);
                }),
        );
    }
}
