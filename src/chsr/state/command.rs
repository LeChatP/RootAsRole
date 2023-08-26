use cursive::{
    direction::Orientation,
    view::{Margins, Nameable, Resizable, Scrollable},
    views::{Dialog, LinearLayout, TextArea, TextView},
};

#[allow(clippy::all)]
#[rustfmt::skip]
#[path = "../../descriptions.rs"]
mod descriptions;

use super::{execute, task::EditTaskState, ExecuteType, Input, State};
use crate::{checklist::CheckListView, Cursive, RoleContext, RoleManagerApp};

use capctl::{Cap, CapSet};

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
        let role = manager.get_role().unwrap();
        let caps = input.as_caps();
        if role.borrow().capabilities_are_denied(caps) {
            manager.set_error(format!(
                "Capabilities {:?} are denied by role definition (or in hierarchy definition)",
                role.borrow().denied_capabilities()
            ).into());
            return self;
        }
        if let Some(task) = task {
            task.borrow_mut().capabilities = Some(caps);
        }

        Box::new(EditTaskState)
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = CheckListView::<Cap>::new()
            .autojump()
            .on_select(|s, _, item| {
                let RoleManagerApp { manager, state } = s.take_user_data().unwrap();
                let info = s.find_name::<TextView>("info");
                if let Some(mut info) = info {
                    let mut capset = CapSet::empty();
                    capset.add(*item);
                    let warning = if manager.get_role().unwrap().borrow().capabilities_are_denied(capset) {
                        "WARNING: This capability is denied by role definition (or in hierarchy definition)\n"
                    } else {
                        ""
                    };
                    info.set_content(format!("{}{}\n", warning, descriptions::get_capability_description(item)));
                }
                s.set_user_data(RoleManagerApp { manager, state });
            });
        let task = manager.get_task();
        let mut selected = CapSet::empty();
        if let Some(task) = task {
            selected = task
                .borrow()
                .capabilities
                .as_ref()
                .unwrap_or(&CapSet::empty())
                .to_owned();
        }
        for capability in (!CapSet::empty()).iter() {
            select.add_item(capability.to_string(), selected.has(capability), capability);
        }
        let mut layout = LinearLayout::new(Orientation::Horizontal);
        layout.add_child(select.with_name("capabilities").scrollable());

        layout.add_child(
            TextView::new(descriptions::get_capability_description(&Cap::CHOWN)).with_name("info"),
        );
        cursive.add_layer(Dialog::around( layout)
        .title("Select capabilities, CTRL+A to check all, CTRL+U to uncheck all and CTRL+D to invert selection")
        .button("Ok",  move|s| {
            let view = s.find_name::<CheckListView<Cap>>("capabilities").unwrap();
            let mut caps = CapSet::empty();
            for item in view.iter() {
                if *item.1 {
                    caps.add(*item.2);
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
