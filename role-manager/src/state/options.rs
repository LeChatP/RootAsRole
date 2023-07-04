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
    options::{Level, OptType, OptValue, Opt, OptEntry},
    RoleContext, RoleManagerApp,
};
use std::cell::RefCell;

#[derive(Clone)]
pub struct SelectOptionState<T>
where T: State + 'static {
    selected: RefCell<Option<usize>>,
    previous: T,
}


impl<T> SelectOptionState<T>
where T: State + Clone + 'static {
    pub fn new( previous : T ) -> Self {
        SelectOptionState { selected: RefCell::new(None), previous }
    }
}

impl<T> State for SelectOptionState<T>
where T: State + Clone + 'static {
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
            OptType::Path => title = "Enter binary locations (PATH) separated by semicolon",
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
        self.selected.borrow_mut().replace(index);
        Box::new(InputState::<SelectOptionState<T>,SelectOptionState<T>,String>::new(self, title, Some(value)))
    }
    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(self.previous)
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = SelectView::new()
            .on_select(|s, item: &OptType| {
                let RoleManagerApp { manager, state } = s.take_user_data().unwrap();
            let info = s.find_name::<TextView>("description");
            if let Some(mut info) = info {
                let stack = manager.get_options();
                info.set_content(stack.get_description(manager.get_options().get_level(),item.to_owned()));
            } else {
                panic!("No info view found");
            }
            s.set_user_data(RoleManagerApp { manager, state });
                
                
            })
            .on_submit(|s, item: &OptType| {
                execute(s, ExecuteType::Submit(item.as_index()));
            });
        for (option, desc) in OptType::item_list_str() {
            select.add_item(desc, option);
        }
        let stack = manager.get_options();
        let desc = stack.get_description(stack.get_level(),OptType::Path);
        let description = TextView::new(desc).with_name("description");
        let layout = cursive::views::LinearLayout::horizontal()
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

impl<T> DeletableItemState for SelectOptionState<T>
where T: State + Clone + 'static {
    fn remove_selected(&mut self, manager: &mut RoleContext, index: usize) {
        manager
            .get_options()
            .set_value(OptType::from_index(index), None);
    }
}

impl<T> PushableItemState<String> for SelectOptionState<T>
where T: State + Clone + 'static {
    fn push(&mut self, manager: &mut RoleContext, value: String) {
        if value == "" {
            manager
                .get_options()
                .set_value(OptType::from_index(self.selected.borrow().unwrap()), None)
        } else {
            manager.get_options().set_value(
                OptType::from_index(self.selected.borrow().unwrap()),
                Some(OptValue::String(value)),
            );
        }
    }
    
}
