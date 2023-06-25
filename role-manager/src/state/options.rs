use cursive::{
    event::Key,
    view::Nameable,
    views::{Dialog, SelectView, TextView},
};

use super::{
    common::{ConfirmState, InputState},
    execute,
    role::{EditRoleState, SelectRoleState},
    Cursive, DeletableItemState, ExecuteType, Input, PushableItemState, State, task::EditTaskState,
};
use crate::{
    options::{Level, OptType, OptValue},
    RoleContext, RoleManagerApp,
};

#[derive(Clone)]
pub struct SelectOptionState {
    selected: Option<usize>,
}
pub struct EditOptionState;

impl SelectOptionState {
    pub fn new() -> Self {
        SelectOptionState { selected: None }
    }
}

impl State for SelectOptionState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn delete(self: Box<Self>, _manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        Box::new(ConfirmState::new(
            self,
            "Are you sure you want to delete this option?",
            index,
        ))
    }
    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        let opttype = OptType::from_index(index);
        let title;
        match opttype {
            OptType::Path => title = "Enter binary locations (PATH) separated by commas",
            OptType::EnvChecklist => {
                title = "Enter environment variables to check separated by commas"
            }
            OptType::EnvWhitelist => {
                title = "Enter environment variables to whitelist separated by commas"
            }
            OptType::Bounding | OptType::NoRoot => {
                let mut stack = manager.get_options();
                stack.set_value(
                    opttype,
                    Some(OptValue::Bool(
                        !stack.get_from_type(opttype.to_owned()).1.as_bool(),
                    )),
                );
                return self;
            }
        }
        let value = manager.get_options().get_from_type(opttype).1.to_string();
        Box::new(InputState::new(self, title, Some(value)))
    }
    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn confirm(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        match manager.get_options().get_level() {
            Level::Global => Box::new(SelectRoleState),
            Level::Role => Box::new(EditRoleState),
            Level::Task => Box::new(EditTaskState),
            _ => self,
        }
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }
    fn render(&self, _manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = SelectView::new()
            .on_select(|s, item: &OptType| {
                let RoleManagerApp { manager, state:_ } = s.user_data().unwrap();
                let stack = manager.get_options();
                let highest_level = stack.get_level();
                let (level, value) = stack.get_from_type(item.to_owned());
                let mut leveldesc = "";
                if level != highest_level {
                    leveldesc = match level {
                        Level::Default => " (Inherited from Default)",
                        Level::Global => " (Inherited from Global)",
                        Level::Role => " (Inherited from Role)",
                        Level::Task => " (Inherited from Commands)",
                        Level::None => " (Inherited from None)",
                    };
                }
                let desc = format!("{}{}", value.to_string(), leveldesc);
                s.call_on_name("description", |view: &mut TextView| {
                    view.set_content(desc);
                });
            })
            .on_submit(|s, item: &OptType| {
                execute(s, ExecuteType::Submit(item.as_index()));
            });
        for (option, desc) in OptType::item_list_str() {
            select.add_item(desc, option);
        }
        let description = TextView::new("Select an option to edit");
        let layout = cursive::views::LinearLayout::vertical()
            .child(select.with_name("select"))
            .child(description);
        cursive.add_layer(Dialog::around(layout).button("Ok", |s| {
            execute(s, ExecuteType::Confirm);
        }));
        cursive.add_global_callback(Key::Del, |s| {
            let selected = s
                .find_name::<SelectView<OptType>>("select")
                .unwrap()
                .selection()
                .unwrap()
                .as_index();
            execute(s, ExecuteType::Delete(selected));
        });
    }
}

impl DeletableItemState for SelectOptionState {
    fn remove_selected(&mut self, manager: &mut RoleContext, index: usize) {
        manager
            .get_options()
            .set_value(OptType::from_index(index), None);
    }
}

impl PushableItemState<String> for SelectOptionState {
    fn push(&mut self, manager: &mut RoleContext, value: String) {
        if value == "" {
            manager
                .get_options()
                .set_value(OptType::from_index(self.selected.unwrap()), None)
        } else {
            manager.get_options().set_value(
                OptType::from_index(self.selected.unwrap()),
                Some(OptValue::String(value)),
            );
        }
    }
}

impl State for EditOptionState {
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
        self
    }
    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }
    fn render(&self, _manager: &mut RoleContext, _cursive: &mut Cursive) {
    }
}
