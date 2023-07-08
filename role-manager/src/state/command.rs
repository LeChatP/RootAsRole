use cursive::{
    direction::Orientation,
    view::{Margins, Nameable, Resizable, Scrollable},
    views::{Dialog, LinearLayout, TextArea, TextView},
};

use super::{execute, task::EditTaskState, ExecuteType, Input, State};
use crate::{
    capabilities::{self, Caps},
    checklist::CheckListView,
    Cursive, RoleContext,
};

pub struct EditCapabilitiesState;

pub struct EditCommandState;

impl State for EditCapabilitiesState {
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
        Box::new(EditTaskState)
    }
    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        let task = manager.get_task();
        if let Some(task) = task {
            task.borrow_mut().capabilities = Some(input.as_caps());
        }

        Box::new(EditTaskState)
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = CheckListView::<(&str, &str)>::new()
            .autojump()
            .on_select(|s, _, item| {
                let info = s.find_name::<TextView>("info");
                if let Some(mut info) = info {
                    info.set_content(item.1);
                }
            });
        let task = manager.get_task();
        let mut selected = Caps::V2(0);
        if let Some(task) = task {
            selected = task.borrow().capabilities.to_owned().unwrap_or(Caps::V2(0));
        }
        for (pos,capability) in capabilities::POSITIONS.iter().enumerate() {
            select.add_item(capability.0, selected.capable(pos), *capability);
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
    fn delete(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }
    fn submit(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }
    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditTaskState)
    }
    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        if manager.get_command().is_some() {
            if let Err(err) = manager.set_command(input.as_string()) {
                manager.set_error(err);
                return self;
            }
        } else {
            manager
                .get_task()
                .unwrap()
                .borrow_mut()
                .commands
                .push(input.as_string());
        }
        Box::new(EditTaskState)
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut edit = TextArea::new();
        if manager.get_command().is_some() {
            edit.set_content(manager.get_command().unwrap());
        }

        cursive.add_layer(
            Dialog::around(edit.with_name("edit").full_screen())
                .title("Edit command")
                .button("Ok", move |s| {
                    let view = s.find_name::<TextArea>("edit").unwrap();
                    execute(
                        s,
                        ExecuteType::Input(Input::String(view.get_content().to_string())),
                    );
                })
                .button("Cancel", move |s| {
                    execute(s, ExecuteType::Cancel);
                })
                .padding(Margins::trbl(1, 1, 1, 0)),
        );
    }
}
