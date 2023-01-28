use cursive::views::{EditView, SelectView, TextView, Dialog};

use crate::{RoleManager, options::{OptType, OptValue, Level}, RoleManagerApp};
use super::{State, Input,Cursive, ExecuteType, execute, role::{SelectRoleState, EditRoleState}, command::EditCommandBlockState};

pub struct SelectOptionState;
pub struct EditOptionState;
pub struct DeleteOptionState;

impl State for SelectOptionState {
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
            let (level,value) = stack.get(item.clone());
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
        });
        for (option,desc) in OptType::item_list_str() {
            select.add_item(desc,option);
        }
        let description = TextView::new("Select an option to edit");
        let layout = cursive::views::LinearLayout::vertical()
            .child(select)
            .child(description);
        cursive.add_layer(Dialog::around(layout)
        .button("Ok", |s| {
            execute(s,ExecuteType::Confirm);
        }));

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

impl State for DeleteOptionState {
    fn create(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        self
    }
    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        self
    }
    fn cancel(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(SelectOptionState)
    }
    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(SelectOptionState)
    }
    fn config(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        self
    }
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive){
        let confirm = cursive::views::Dialog::around(TextView::new("Are you sure you want to delete this option?\nIf you do, the higher level option will be used instead."))
            .button("Yes", |s| {
                execute(s,ExecuteType::Confirm);
            })
            .button("No", |s| {
                execute(s,ExecuteType::Cancel);
            });
    }
}