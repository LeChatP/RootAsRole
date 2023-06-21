use cursive::{
    direction::Orientation,
    event::Key,
    view::{Nameable, Scrollable},
    views::{Dialog, EditView, LinearLayout, SelectView, TextView},
};

use super::{
    actor::{SelectGroupState, SelectUserState},
    common::ConfirmState,
    execute,
    options::SelectOptionState,
    role::EditRoleState,
    DeletableItemState, ExecuteType, Input, State,
};
use crate::{
    capabilities::{self, Caps},
    checklist::CheckListView,
    ActorType, Cursive, RoleContext
};

pub struct SelectCommandBlockState;
pub struct DeleteCommandBlockState;

#[derive(Clone)]
pub struct EditCommandBlockState;

pub struct EditCapabilitiesState;

pub struct EditSetIDState {
    pub actor_type: ActorType,
}

pub struct EditCommandState;
pub struct DeleteCommandState;

impl State for SelectCommandBlockState {
    fn create(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditCommandBlockState)
    }
    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        self
    }
    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        manager.select_commands(index);
        Box::new(EditCommandBlockState)
    }
    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn confirm(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditRoleState)
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        self
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = SelectView::new().on_submit(|s, item| {
            execute(s, ExecuteType::Submit(*item));
        });
        manager
            .get_role()
            .unwrap()
            .as_ref()
            .borrow()
            .tasks
            .iter()
            .enumerate()
            .for_each(|(index, commands)| {
                if commands.borrow().id.is_some() {
                    select.add_item(commands.borrow().id.clone().unwrap(), index);
                } else {
                    select.add_item(format!("Block #{}", index), index);
                }
            });
        cursive.add_layer(
            Dialog::around(select.scrollable())
                .button("Add", |s| {
                    execute(s, ExecuteType::Create);
                })
                .button("Ok", |s| {
                    execute(s, ExecuteType::Confirm);
                }),
        )
    }
}

impl State for DeleteCommandBlockState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        self
    }
    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        self
    }
    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectCommandBlockState)
    }
    fn confirm(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        manager
            .get_role()
            .unwrap()
            .as_ref()
            .borrow_mut()
            .tasks
            .remove(manager.get_commands_index().unwrap());
        Box::new(SelectCommandBlockState)
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        self
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let command_block = manager.get_task().unwrap();
        let binding = manager.get_task();
        let name = &binding.as_deref().unwrap().borrow().id;
        cursive.add_layer(
            Dialog::around(TextView::new(format!(
                "Are you sure you want to delete {} ?",
                name.to_string()
            )))
            .title("Confirm delete command block")
            .button("Yes", move |s| {
                execute(s, ExecuteType::Confirm);
            })
            .button("No", move |s| {
                execute(s, ExecuteType::Cancel);
            }),
        );
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
impl State for EditCommandBlockState {
    fn create(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditCommandState)
    }
    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        manager.select_command(index);
        Box::new(ConfirmState::new(
            self,
            &format!(
                "Are you sure to delete {} ?",
                manager.get_task().as_deref().unwrap().borrow().id.unwrap().to_string()
            ),
            index,
        ))
    }
    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        manager.select_command(index);
        Box::new(EditCommandState)
    }
    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectCommandBlockState)
    }
    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn config(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectOptionState::new())
    }
    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        match input.as_string().as_ref() {
            "u" => Box::new(SelectUserState::new(false, None)),
            "g" => Box::new(SelectGroupState),
            "c" => Box::new(EditCapabilitiesState),
            _ => panic!("Unknown input {}", input.as_string()),
        }
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let task = manager.get_task().clone().unwrap();
        let mut select = SelectView::new().on_submit(|s, item| {
            execute(s, ExecuteType::Submit(*item));
        });
        task
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
        cursive.add_layer(
            Dialog::around(select.with_name("select").scrollable())
                .title(format!("Edit {}", task.clone().borrow().id.to_string()))
                .button("Add", |s| {
                    execute(s, ExecuteType::Create);
                })
                .button("Options", |s| {
                    execute(s, ExecuteType::Config);
                })
                .button("Capabilities", |s| {
                    execute(s, ExecuteType::Input(Input::String("c".to_owned())));
                })
                .button("UID", |s| {
                    execute(s, ExecuteType::Input(Input::String("u".to_owned())));
                })
                .button("GID", |s| {
                    execute(s, ExecuteType::Input(Input::String("g".to_owned())));
                })
                .button("Ok", |s| {
                    execute(s, ExecuteType::Confirm);
                }),
        )
    }
}

impl State for EditCapabilitiesState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        self
    }
    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        self
    }
    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditCommandBlockState)
    }
    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        manager
            .get_task()
            .unwrap()
            .borrow_mut()
            .capabilities = Some(input.as_caps());
        Box::new(SelectCommandBlockState)
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = CheckListView::<(&str, &str)>::new()
            .autojump()
            .on_select(|s, item| {
                let info = s.find_name::<TextView>("info");
                if let Some(mut info) = info {
                    info.set_content(item.1);
                }
            });
        let selected = manager
            .get_task()
            .unwrap()
            .borrow()
            .capabilities
            .clone()
            .unwrap_or(Caps::V2(0));
        let mut pos = 0;
        for capability in capabilities::POSITIONS {
            select.add_item(capability.0.clone(), selected.capable(pos), capability);
            pos += 1;
        }
        let mut layout = LinearLayout::new(Orientation::Horizontal);
        layout.add_child(select.with_name("capabilities").scrollable());

        layout.add_child(TextView::new(capabilities::POSITIONS[0].1).with_name("info"));
        cursive.add_layer(Dialog::around( layout)
        .title("Select capabilities, CTRL+A to check all, CTRL+U to uncheck all and CTRL+D to invert selection")
        .button("Ok",  move|s| {
            let view = s.find_name::<CheckListView<(&str, &str)>>("capabilities").unwrap();
            let mut caps = Caps::V2(0);
            for (pos, item) in view.iter().enumerate() {
                if *item.1 {
                    caps |= 1 << pos;
                }
            }
            execute(s,ExecuteType::Input( Input::Caps(caps)));
        }));
    }
}

impl State for EditCommandState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        self
    }
    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        self
    }
    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditCommandBlockState)
    }
    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        if manager.get_command().is_some() {
            manager.set_command(input.as_string());
        } else {
            manager
                .get_task()
                .unwrap()
                .borrow_mut()
                .commands
                .push(input.as_string());
        }
        Box::new(EditCommandBlockState)
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut edit = EditView::new();
        if manager.get_command().is_some() {
            edit.set_content(manager.get_command().unwrap());
        }
        cursive.add_layer(
            Dialog::around(edit.with_name("edit"))
                .title("Edit command")
                .button("Ok", move |s| {
                    let view = s.find_name::<EditView>("edit").unwrap();
                    execute(
                        s,
                        ExecuteType::Input(Input::String(view.get_content().to_string())),
                    );
                })
                .button("Cancel", move |s| {
                    execute(s, ExecuteType::Cancel);
                }),
        );
    }
}

impl DeletableItemState for EditCommandBlockState {
    fn remove_selected(&mut self, manager: &mut RoleContext, index: usize) {
        manager
            .get_task()
            .unwrap()
            .borrow_mut()
            .commands
            .remove(index);
        println!("Commands {:?}", manager.get_task().unwrap());
    }
}
