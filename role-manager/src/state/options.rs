use cursive::{views::{EditView, SelectView, TextView, Dialog}, event::Key, view::Nameable};

use crate::{RoleManager, options::{OptType, Level, OptValue}, RoleManagerApp};
use super::{State, Input,Cursive, ExecuteType, execute, role::{SelectRoleState, EditRoleState}, command::EditCommandBlockState, common::{ConfirmState, InputState}, DeletableItemState, PushableItemState, SettableItemState};

#[derive(Clone)]
pub struct SelectOptionState{
    selected : Option<usize>,
}
pub struct EditOptionState;

impl SelectOptionState {
    pub fn new() -> Self {
        SelectOptionState {
            selected : None,
        }
    }
}

impl State for SelectOptionState {
    fn create(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        Box::new(ConfirmState::new(self, "Are you sure you want to delete this option?", index))
    }
    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        let opttype = OptType::from_index(index);
        let mut title = "";
        match opttype {
            OptType::Path => {
                title = "Enter binary locations (PATH) separated by commas"
            },
            OptType::EnvChecklist =>{
                title = "Enter environment variables to check separated by commas"
            },
            OptType::EnvWhitelist => {
                title = "Enter environment variables to whitelist separated by commas"
            },
            OptType::Bounding | OptType::NoRoot => {
                let mut stack = manager.get_optstack();
                stack.set_value(opttype, Some(OptValue::Bool(!stack.get_from_type(opttype.clone()).1.as_bool())));
                return self;
            },
        }
        let value = manager.get_optstack().get_from_type(opttype).1.to_string();
        Box::new(InputState::new(self,title,Some(value)))
    }
    fn cancel(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        match manager.get_optstack().get_level() {
            Level::Global => Box::new(SelectRoleState),
            Level::Role => Box::new(EditRoleState),
            Level::Commands => Box::new(EditCommandBlockState),
            _ => self,
        }
    }
    fn config(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        self
    }
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive){
        let mut select = SelectView::new().on_select( |s,item:&OptType| {
            let RoleManagerApp {
                manager,
                state,
            } = s.user_data().unwrap();
            let stack = manager.get_optstack();
            let highest_level = stack.get_level();
            let (level,value) = stack.get_from_type(item.clone());
            let mut leveldesc = "";
            if level != highest_level {
                leveldesc = match level {
                    Level::Default => " (Inherited from Default)",
                    Level::Global => " (Inherited from Global)",
                    Level::Role => " (Inherited from Role)",
                    Level::Commands => " (Inherited from Commands)",
                    Level::None => " (Inherited from None)",
                };
            }
            let desc = format!("{}{}",value.to_string(),leveldesc);
            s.call_on_name("description", |view: &mut TextView| {
                view.set_content(desc);
            });
        })
        .on_submit(|s,item:&OptType| {
            execute(s, ExecuteType::Submit(item.as_index()));
        });
        for (option,desc) in OptType::item_list_str() {
            select.add_item(desc,option);
        }
        let description = TextView::new("Select an option to edit");
        let layout = cursive::views::LinearLayout::vertical()
            .child(select.with_name("select"))
            .child(description);
        cursive.add_layer(Dialog::around(layout)
        .button("Ok", |s| {
            execute(s,ExecuteType::Confirm);
        }));
        cursive.add_global_callback(Key::Del, |s| {
            let selected = s.find_name::<SelectView<OptType>>("select").unwrap().selection().unwrap().as_index();
            execute(s,ExecuteType::Delete(selected));
        });

    }
}

impl DeletableItemState for SelectOptionState {
    fn remove_selected(&mut self, manager : &mut RoleManager, index : usize) {
            manager.get_optstack().set_value(OptType::from_index(index), None);
    }
}

impl PushableItemState<String> for SelectOptionState {
    fn push(&mut self, manager : &mut RoleManager, value : String) {
        if value == "" {
            manager.get_optstack().set_value(OptType::from_index(self.selected.unwrap()), None)
        }else{
            manager.get_optstack().set_value(OptType::from_index(self.selected.unwrap()), Some(OptValue::String(value)));
        }
    }
}

impl State for EditOptionState {
    fn create(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        self
    }
    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        self
    }
    fn cancel(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn confirm(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn config(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        self
    }
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive){
        let edit = EditView::new();


    }
}

