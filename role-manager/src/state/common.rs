use std::cell::RefCell;

use cursive::{views::{EditView, Dialog}, view::Nameable};

use crate::RoleManager;

use super::{State, PushableItemState, DeletableItemState, ExecuteType, Input, execute};


#[derive(Clone)]
pub struct InputState<T> where T : State + PushableItemState<String> + 'static + Clone {
    previous_state : RefCell<T>,
    title : String,
    content : Option<String>,
}

#[derive(Clone)]
pub struct ConfirmState<T> where T : State + DeletableItemState + 'static {
    previous_state : RefCell<T>,
    title : String,
    index : usize,
}

impl<T> InputState<T> where T : State + PushableItemState<String> + 'static + Clone {
    pub fn new(previous_state : Box<T>, title : &str, content : Option<String>) -> Self {
        InputState {
            previous_state :RefCell::new(*previous_state),
            title : title.to_owned(),
            content,
        }
    }
}

impl<T> State for InputState<T> where T : State + PushableItemState<String> + Clone + 'static {
    fn create(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{self}
    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{self}
    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{self}
    fn cancel(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(self.previous_state.borrow().clone())
    }
    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{self}
    fn config(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{self}
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        self.previous_state.borrow_mut().push(manager,input.as_string());
        Box::new(self.previous_state.borrow().clone())
    }
    fn render(&self, manager : &mut crate::RoleManager, cursive : &mut cursive::Cursive) {
        let mut input = EditView::new();
        if let Some(content) = self.content.clone() {
            input.set_content(content);
        }
        cursive.add_layer(Dialog::around( input.with_name("input"))
            .title(self.title.as_str())
            .button("Cancel", |s| {
                execute(s,ExecuteType::Cancel);
            })
            .button("Confirm", |s| {
                let input = s.find_name::<EditView>("input").unwrap();
                execute(s,ExecuteType::Input( Input::String(input.get_content().as_str().into())));
            }));
    }
}

impl<T> State for ConfirmState<T> where T : State + DeletableItemState + Clone + 'static {
    fn create(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{self}
    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{self}
    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{self}
    fn cancel(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(self.previous_state.borrow().clone())
    }
    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        self.previous_state.borrow_mut().remove_selected(manager, self.index);
        Box::new(self.previous_state.borrow().clone())
    }
    fn config(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{self}
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{self}
    fn render(&self, manager : &mut crate::RoleManager, cursive : &mut cursive::Cursive) {
        cursive.add_layer(Dialog::around( cursive::views::TextView::new(self.title.as_str()))
            .title("Confirm")
            .button("Cancel", |s| {
                execute(s,ExecuteType::Cancel);
            })
            .button("Confirm", |s| {
                execute(s,ExecuteType::Confirm);
            }));
    }
}

impl<T> ConfirmState<T> where T : State + DeletableItemState {
    pub fn new(previous_state : Box<T>, title : &str, index : usize) -> Self {
        ConfirmState {
            previous_state :RefCell::new(*previous_state),
            title : title.to_owned(),
            index,
        }
    }
}