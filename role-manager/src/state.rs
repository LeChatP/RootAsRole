pub mod actor;
pub mod command;
pub mod common;
pub mod options;
pub mod role;
mod task;


use cursive::{
    event::Key,
    theme::{BaseColor, Color, ColorStyle, Effect, Style},
    views::{Dialog, TextView},
    Cursive,
};

use crate::{capabilities::Caps, rolemanager::RoleContext, RoleManagerApp};

pub trait PushableItemState<T> {
    fn push(&mut self, manager: &mut RoleContext, item: T);
}

pub trait SettableItemState<T> {
    fn set(&mut self, manager: &mut RoleContext, index: usize, item: T);
}

pub trait DeletableItemState {
    fn remove_selected(&mut self, manager: &mut RoleContext, index: usize);
}

pub enum Input {
    String(String),
    Vec(Vec<String>),
    Caps(Caps),
}

pub enum ExecuteType {
    Create,
    Delete(usize),
    Submit(usize),
    Cancel,
    Confirm,
    Config,
    Input(Input),
}

impl Input {
    pub fn as_string(&self) -> String {
        match self {
            Input::String(str) => str.to_string(),
            Input::Vec(vec) => vec.join(","),
            Input::Caps(caps) => caps.to_string(),
        }
    }
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            Input::String(str) => str.split(",").map(|s| s.to_string()).collect(),
            Input::Vec(vec) => vec.to_vec(),
            Input::Caps(caps) => caps.to_owned().into(),
        }
    }
    pub fn as_caps(&self) -> Caps {
        match self {
            Input::String(str) => Caps::from(str.to_owned()),
            Input::Vec(vec) => Caps::from(vec.to_vec()),
            Input::Caps(caps) => caps.to_owned(),
        }
    }
}

pub trait State {
    fn create(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State>;
    fn delete(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State>;
    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State>;
    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State>;
    fn confirm(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State>;
    fn config(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State>;
    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State>;
    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive);
}

pub trait InitState {
    fn init(&self, manager: &mut RoleContext) -> Dialog;
}

pub fn execute(s: &mut Cursive, exec_type: ExecuteType) {
    let RoleManagerApp {
        mut manager,
        mut state,
    } = s.take_user_data().unwrap();

    state = match exec_type {
        ExecuteType::Create => state.create(&mut manager),
        ExecuteType::Delete(index) => state.delete(&mut manager, index),
        ExecuteType::Submit(index) => state.submit(&mut manager, index),
        ExecuteType::Cancel => state.cancel(&mut manager),
        ExecuteType::Confirm => state.confirm(&mut manager),
        ExecuteType::Config => state.config(&mut manager),
        ExecuteType::Input(input) => state.input(&mut manager, input),
    };
    s.pop_layer();
    s.clear_global_callbacks(Key::Del);

    state.render(&mut manager, s);
    if let Some(err) = manager.take_error() {
        let mut style = Style::from(ColorStyle::new(
            Color::Light(BaseColor::White),
            Color::Dark(BaseColor::Red),
        ));
        style.effects.insert(Effect::Bold);
        s.add_layer(Dialog::around(TextView::new(err.to_string()).style(style)).dismiss_button("Understood"));
    }
    s.set_user_data(RoleManagerApp { manager, state });
}
