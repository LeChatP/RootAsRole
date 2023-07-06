use cursive::{
    align::{HAlign, VAlign},
    event::Key,
    view::{Nameable, Scrollable},
    views::{Dialog, LinearLayout, SelectView, TextView},
    Cursive,
};

use crate::{
    config::structs::{Groups, IdTask},
    rolemanager::RoleContext,
    state::State,
    RoleManagerApp,
};

use super::{
    actor::{EditGroupState, SelectUserState, Users},
    command::{EditCapabilitiesState, EditCommandState},
    common::{ConfirmState, InputState},
    execute,
    options::SelectOptionState,
    role::EditRoleState,
    DeletableItemState, ExecuteType, Input, PushableItemState,
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
        match manager.select_task_by_index(index) {
            Err(err) => {
                manager.set_error(err);
                return self;
            }
            Ok(_) => {
                let task = manager.get_task().unwrap();
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
        if let Err(err) = manager.select_task_by_index(index) {
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
        let mut select = SelectView::new()
            .on_submit(|s, item| {
                execute(s, ExecuteType::Submit(*item));
            })
            .on_select(move |s, i| {
                let RoleManagerApp { manager, state } = s.take_user_data().unwrap();
                let info = s.find_name::<TextView>("info");
                if let Some(mut info) = info {
                    let role = manager.get_role();
                    if let Some(role) = role {
                        let role = role.as_ref().borrow();
                        let task = role.get_task_from_index(i).unwrap();
                        let task = task.as_ref().borrow();
                        info.set_content(task.get_description());
                    } else {
                        info.set_content("No task selected");
                    }
                } else {
                    panic!("No info view found");
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
        let mut layout = LinearLayout::horizontal();
        match manager.get_role() {
            Some(role) => {
                role.as_ref()
                    .borrow()
                    .tasks
                    .iter()
                    .enumerate()
                    .for_each(|(index, tasks)| {
                        if tasks.as_ref().borrow().id.is_name() {
                            select
                                .add_item(tasks.as_ref().borrow().id.to_owned().to_string(), index);
                        } else {
                            select.add_item(format!("Task #{}", index), index);
                        }
                    });
                layout.add_child(select.with_name("select"));
                let info;
                if role.as_ref().borrow().tasks.len() > 0 {
                    info = TextView::new(
                        role.as_ref().borrow().tasks[0]
                            .as_ref()
                            .borrow()
                            .get_description(),
                    )
                    .with_name("info");
                } else {
                    info = TextView::new("There is no tasks").with_name("info");
                }
                layout.add_child(info);

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
        let task = manager.get_task().unwrap_or_else(|| {
            let msg = "No task selected";
            manager.set_error(msg.into());
            panic!("{}", msg);
        });
        let id = task.as_ref().borrow().id.clone();
        task.as_ref()
            .borrow()
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
        Box::new(SelectOptionState::new(*self))
    }
    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        match input.as_string().as_ref() {
            "u" => Box::new(SelectUserState::new(*self.clone(), *self, false, None)),
            "g" => {
                let setgid = manager
                    .get_task()
                    .unwrap()
                    .as_ref()
                    .borrow()
                    .setgid
                    .to_owned();
                Box::new(EditGroupState::new(*self.clone(), *self, setgid))
            }
            "c" => Box::new(EditCapabilitiesState),
            "p" => Box::new(InputState::<EditTaskState, EditTaskState, String>::new(
                self,
                "Set purpose",
                manager
                    .get_task()
                    .unwrap()
                    .as_ref()
                    .borrow()
                    .purpose
                    .to_owned(),
            )),
            "i" => Box::new(InputState::<EditTaskState, EditTaskState, IdTask>::new(
                self,
                "Set task id",
                Some(manager.get_task().unwrap().as_ref().borrow().id.to_owned()),
            )),
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

        let mut purpose = String::new();

        if let Some(task) = task {
            task.as_ref()
                .borrow()
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
            if let Some(p) = &task.as_ref().borrow().purpose {
                purpose.push_str(format!("Purpose : {}\n", p).as_str());
            }
            if let Some(setuid) = &task.as_ref().borrow().setuid {
                purpose.push_str(format!("Setuid : {}\n", setuid).as_str());
            }
            if let Some(setgid) = &task.as_ref().borrow().setgid {
                purpose.push_str(format!("Setgid : {}\n", setgid.join(",")).as_str());
            }
            if let Some(caps) = &task.as_ref().borrow().capabilities {
                purpose.push_str(format!("Capabilities : {}\n", caps.to_string()).as_str());
            }
        } else {
            purpose = "".to_owned();
        }

        let layout = LinearLayout::vertical()
            .child(select.with_name("select").scrollable())
            .child(TextView::new(purpose).align(cursive::align::Align {
                h: HAlign::Center,
                v: VAlign::Bottom,
            }));

        cursive.add_layer(
            Dialog::around(layout)
                .title(title)
                .button("Add Cmd", |s| {
                    execute(s, ExecuteType::Create);
                })
                .button("Set Purpose", |s| {
                    execute(s, ExecuteType::Input(Input::String("p".to_owned())));
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
                .button("Task Id", |s| {
                    execute(s, ExecuteType::Input(Input::String("i".to_owned())));
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
impl PushableItemState<Users> for EditTaskState {
    fn push(&mut self, manager: &mut RoleContext, item: Users) {
        manager
            .get_task()
            .unwrap()
            .borrow_mut()
            .setuid
            .replace(item.name[0].to_owned());
    }
}

impl PushableItemState<String> for EditTaskState {
    fn push(&mut self, manager: &mut RoleContext, item: String) {
        manager
            .get_task()
            .unwrap()
            .borrow_mut()
            .purpose
            .replace(item);
    }
}

impl PushableItemState<IdTask> for EditTaskState {
    fn push(&mut self, manager: &mut RoleContext, item: IdTask) {
        if item.to_string().len() > 0 {
            manager.get_task().unwrap().borrow_mut().id = item;
        }
    }
}

impl PushableItemState<Groups> for EditTaskState {
    fn push(&mut self, manager: &mut RoleContext, item: Groups) {
        manager
            .get_task()
            .unwrap()
            .borrow_mut()
            .setgid
            .replace(item);
    }
}
