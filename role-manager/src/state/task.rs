use cursive::{
    event::Key,
    view::{Nameable, Scrollable},
    views::{Dialog, SelectView, LinearLayout, TextView},
    Cursive,
};

use crate::{rolemanager::RoleContext, state::State, RoleManagerApp};

use super::{
    actor::{SelectGroupState, SelectUserState},
    command::{EditCapabilitiesState, EditCommandState},
    common::ConfirmState,
    execute,
    options::SelectOptionState,
    role::{EditRoleState, SelectRoleState},
    DeletableItemState, ExecuteType, Input,
};

#[derive(Clone)]
pub struct SelectTaskState;

#[derive(Clone)]
pub struct EditTaskState;

impl State for SelectTaskState {
    fn create(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        if let Err(err) = manager.create_new_task(None) {
            manager.set_error(err);
            return self;
        }
        Box::new(EditTaskState)
    }
    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        match manager.select_task(index) {
            Err(err) => {
                manager.set_error(err);
                return self;
            }
            Ok(_) => {
                let task = manager.get_task().or(manager.get_new_task()).unwrap();
                let id = task.as_ref().borrow().id.clone();
                return Box::new(ConfirmState::new(
                    self,
                    &format!("Are you sure to delete {}?", id.to_string()),
                    index,
                ));
            }
        }
    }
    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        if let Err(err) = manager.select_task(index) {
            manager.set_error(err);
        }
        Box::new(EditTaskState)
    }
    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        manager.unselect_task();
        Box::new(EditRoleState)
    }
    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditRoleState)
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        
        let mut select = SelectView::new().on_submit(|s, item| {
            execute(s, ExecuteType::Submit(*item));
        }).on_select(move |s, _ | {
            let RoleManagerApp { manager, state } = s.take_user_data().unwrap();
            let info = s.find_name::<TextView>("info");
            if let Some(mut info) = info {
                let task = manager.get_task().or(manager.get_new_task());
                if let Some(task) = task {
                    let task = task.as_ref().borrow();
                    info.set_content(task.get_description());
                }else {
                    info.set_content("No task selected");
                }
            }
            s.set_user_data(RoleManagerApp { manager, state });
        });
        
        cursive.set_global_callback(Key::Del, move |s| {
            let sel = s
                .find_name::<SelectView<usize>>("select")
                .unwrap()
                .selection()
                .unwrap();
            execute(s, ExecuteType::Delete(*sel));
        });
        match manager
            .get_role()
            .or(manager.get_new_role()) {
            Some(role) => {
                role.as_ref()
            .borrow()
            .tasks
            .iter()
            .enumerate()
            .for_each(|(index, tasks)| {
                if tasks.as_ref().borrow().id.is_some() {
                    select.add_item(tasks.as_ref().borrow().id.to_owned().to_string(), index);
                } else {
                    select.add_item(format!("Task #{}", index), index);
                }
            });
            if let Err(err) = manager.select_task(0) {
                manager.set_error(err);
                return;
            }
        let layout = LinearLayout::horizontal()
            .child(select.with_name("select").scrollable())
            .child(TextView::new(manager.get_task().unwrap().as_ref().borrow().get_description()).with_name("info"));
        cursive.add_layer(
            Dialog::around(layout)
                .button("Add", |s| {
                    execute(s, ExecuteType::Create);
                })
                .button("Cancel", |s| {
                    execute(s, ExecuteType::Cancel);
                })
                .button("Ok", |s| {
                    execute(s, ExecuteType::Confirm);
                }),
        );
            }
            None => {
                manager.set_error("No role selected".into());
            }
        }
            
    }
}

impl DeletableItemState for SelectTaskState {
    fn remove_selected(&mut self, manager: &mut RoleContext, _index: usize) {
        let task = manager
            .get_task()
            .or(manager.get_new_task())
            .unwrap_or_else(|| {
                let msg = "No task selected";
                manager.set_error(msg.into());
                panic!("{}", msg);
            });
        let id = task.as_ref().borrow().id.clone();
        task.as_ref().borrow()
            .get_parent()
            .unwrap()
            .borrow_mut()
            .remove_task(id);
    }
}

/**
 * This State is used to edit a command block
 * Add command with add button (with Dialog)
 * Delete command with delete Key (Backspace or Delete)
 * Also used to set capabilities on the command block (with Dialog)
 * And used to set the id of the command block (with Dialog)
 * And used to set options on the command block (with Dialog)
 */
impl State for EditTaskState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditCommandState)
    }
    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        if let Err(err) = manager.select_command(index) {
            manager.set_error(err);
            return self;
        }
        Box::new(ConfirmState::new(
            self,
            &format!(
                "Are you sure to delete Command #{}?\n\"{}\"",
                index,
                manager.get_command().unwrap()
            ),
            index,
        ))
    }
    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        if let Err(err) = manager.select_command(index) {
            manager.set_error(err);
            return self;
        }
        Box::new(EditCommandState)
    }
    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        if manager.get_new_task().is_some() {
            manager.delete_new_task();
        }
        manager.unselect_task();
        Box::new(SelectTaskState)
    }
    fn confirm(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        if manager.get_new_task().is_some() {
            manager.save_new_task();
        }
        manager.unselect_task();
        Box::new(SelectTaskState)
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectOptionState::new())
    }
    fn input(self: Box<Self>, _manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        match input.as_string().as_ref() {
            "u" => Box::new(SelectUserState::new(false, None)),
            "g" => Box::new(SelectGroupState),
            "c" => Box::new(EditCapabilitiesState),
            _ => panic!("Unknown input {}", input.as_string()),
        }
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut title = "".to_owned();
        let task = manager
            .get_task()
            .and_then(|o| {
                title = format!("Edit {}", o.as_ref().borrow().id.to_string());
                Some(o)
            })
            .or_else(|| {
                title = "Add new Task".to_owned();
                manager.get_new_task()
            });
        let mut select = SelectView::new().on_submit(|s, item| {
            execute(s, ExecuteType::Submit(*item));
        });

        if let Some(task) = task {
            task.as_ref().borrow()
                .commands
                .iter()
                .enumerate()
                .for_each(|(index, e)| {
                    select.add_item(e.to_string(), index);
                });
            cursive.set_global_callback(Key::Del, move |s| {
                let sel = s
                    .find_name::<SelectView<usize>>("select")
                    .unwrap()
                    .selection()
                    .unwrap();
                execute(s, ExecuteType::Delete(*sel));
            });
            title = format!("Edit {}", task.as_ref().borrow().id.to_string());
        }

        cursive.add_layer(
            Dialog::around(select.with_name("select").scrollable())
                .title(title)
                .button("Add Cmd", |s| {
                    execute(s, ExecuteType::Create);
                })
                .button("Options", |s| {
                    execute(s, ExecuteType::Config);
                })
                .button("Caps", |s| {
                    execute(s, ExecuteType::Input(Input::String("c".to_owned())));
                })
                .button("UID", |s| {
                    execute(s, ExecuteType::Input(Input::String("u".to_owned())));
                })
                .button("GID", |s| {
                    execute(s, ExecuteType::Input(Input::String("g".to_owned())));
                })
                .button("Cancel", |s| {
                    execute(s, ExecuteType::Cancel);
                })
                .button("Ok", |s| {
                    execute(s, ExecuteType::Confirm);
                }),
        )
    }
}

impl DeletableItemState for EditTaskState {
    fn remove_selected(&mut self, manager: &mut RoleContext, index: usize) {
        manager
            .get_task()
            .or_else(|| manager.get_new_task())
            .unwrap_or_else(|| {
                let err = "No Command selected";
                manager.set_error(err.into());
                panic!("{}", err);
            })
            .borrow_mut()
            .commands
            .remove(index);
    }
}
