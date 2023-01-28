pub mod role;
pub mod actor;
pub mod options;
pub mod command;

use cursive::{Cursive, views::Dialog};

use crate::{RoleManager, capabilities::Caps, RoleManagerApp};

pub enum Input {
    String(String),
    Vec(Vec<String>),
    Caps(Caps)
}

pub enum ExecuteType{
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
            Input::Caps(caps) => caps.clone().into(),
        }
    }
    pub fn as_caps(&self) -> Caps {
        match self {
            Input::String(str) => Caps::from(str.clone()),
            Input::Vec(vec) => Caps::from(vec.to_vec()),
            Input::Caps(caps) => caps.clone(),
        }
    }
}

pub trait State {
    fn create(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>;
    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>;
    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>;
    fn cancel(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>;
    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>;
    fn config(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>;
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>;
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive);
}

pub trait InitState {
    fn init(&self, manager : &mut RoleManager) -> Dialog;
}

pub fn execute(s : &mut Cursive, exec_type : ExecuteType) {
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
    state.render(&mut manager, s);
    s.set_user_data(RoleManagerApp {
        manager,
        state,
    });
}
