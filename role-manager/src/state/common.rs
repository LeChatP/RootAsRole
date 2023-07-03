
use cursive::{
    view::Nameable,
    views::{Dialog, EditView}, event::{Event, Key},
};

use crate::RoleContext;

use super::{execute, DeletableItemState, ExecuteType, Input, PushableItemState, State};



#[derive(Clone)]
pub struct InputState<T,V,U>
where
    V: State + Clone + 'static,
    T: State + PushableItemState<U> + Clone + 'static,
    U: From<String> + ToString + Into<String> + Clone,
{
    previous_state: V,
    next_state: T,
    title: String,
    content: Option<U>,
}

#[derive(Clone)]
pub struct ConfirmState<T>
where
    T: State + DeletableItemState + 'static,
{
    previous_state: T,
    title: String,
    index: usize,
}

impl<T,V,U> InputState<T,V,U>
where
    V: State + Clone + 'static,
    T: State + Clone + 'static + PushableItemState<U>,
    U: From<String> + ToString + Into<String> + Clone,
    Box<T>: Into<Box<V>>,
{
    pub fn new(previous_state: Box<T>, title: &str, content: Option<U>) -> Self{
        InputState::new_with_next(previous_state.clone().into(), previous_state, title, content)
    }
    pub fn new_with_next(previous_state: Box<V>, next_state: Box<T>, title: &str, content: Option<U>) -> Self {
        InputState {
            previous_state: *previous_state,
            next_state: *next_state,
            title: title.to_owned(),
            content,
        }
    }
}

impl<T,V,U> State for InputState<T,V,U>
where
    V: State + Clone + 'static,
    T: State + PushableItemState<U> + Clone + 'static,
    U: From<String> + ToString + Into<String> + Clone + 'static,
    Box<T>: Into<Box<V>>,
{
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
        Box::new(self.previous_state)
    }
    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(mut self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        self.next_state.push(manager, input.as_string().into());
        Box::new(self.next_state)
    }
    fn render(&self, _manager: &mut crate::RoleContext, cursive: &mut cursive::Cursive) {
        let mut input = EditView::new();
        if let Some(content) = self.content.clone() {
            input.set_content(content);
        }
        cursive.add_global_callback(Event::Key(Key::Enter), |s| {
            let input = s.find_name::<EditView>("input").unwrap();
                    execute(
                        s,
                        ExecuteType::Input(Input::String(input.get_content().as_str().into())),
                    );
        });
        cursive.add_layer(
            Dialog::around(input.with_name("input"))
                .title(self.title.as_str())
                .button("Cancel", |s| {
                    execute(s, ExecuteType::Cancel);
                })
                .button("Confirm", |s| {
                    let input = s.find_name::<EditView>("input").unwrap();
                    execute(
                        s,
                        ExecuteType::Input(Input::String(input.get_content().as_str().into())),
                    );
                }),
        );
    }
}

impl<T> State for ConfirmState<T>
where
    T: State + DeletableItemState + Clone + 'static,
{
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
        Box::new(self.previous_state)
    }
    fn confirm(mut self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        self.previous_state.remove_selected(manager, self.index);
        Box::new(self.previous_state)
    }
    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }
    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }
    fn render(&self, _manager: &mut RoleContext, cursive: &mut cursive::Cursive) {
        cursive.add_layer(
            Dialog::around(cursive::views::TextView::new(self.title.as_str()))
                .title("Confirm")
                .button("Cancel", |s| {
                    execute(s, ExecuteType::Cancel);
                })
                .button("Confirm", |s| {
                    execute(s, ExecuteType::Confirm);
                }),
        );
    }
}

impl<T> ConfirmState<T>
where
    T: State + DeletableItemState + Clone + 'static,
{
    pub fn new(previous_state: Box<T>, title: &str, index: usize) -> Self {
        ConfirmState {
            previous_state: *previous_state,
            title: title.to_owned(),
            index,
        }
    }
}
