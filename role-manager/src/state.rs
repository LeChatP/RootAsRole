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

#[derive(PartialEq, Eq, Clone)]
pub enum Input {
    String(String),
    Vec(Vec<String>),
    Caps(Caps),
}

#[derive(PartialEq, Eq, Clone)]
pub enum ExecuteType {
    Create,
    Delete(usize),
    Submit(usize),
    Cancel,
    Confirm,
    Config,
    Input(Input),
    Exit,
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
            Input::String(str) => str.split(',').map(|s| s.to_string()).collect(),
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
    fn config_cursive(&self, cursive: &mut Cursive);
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
        ExecuteType::Exit => {
            manager.exit();
            state.confirm(&mut manager)
        }
    };
    s.pop_layer();
    s.clear_global_callbacks(Key::Del);
    s.clear_global_callbacks(Key::Enter);

    state.render(&mut manager, s);
    let exiting = manager.is_exiting();
    if let Some(err) = manager.take_error() {
        let mut style = Style::from(ColorStyle::new(
            Color::Light(BaseColor::White),
            Color::Dark(BaseColor::Red),
        ));
        style.effects.insert(Effect::Bold);
        s.add_layer(
            Dialog::around(TextView::new(err.to_string()).style(style)).button(
                "Understood",
                move |s| {
                    s.pop_layer();
                    if exiting {
                        s.quit();
                    }
                },
            ),
        );
    } else if exiting {
        s.quit();
    }

    s.set_user_data(RoleManagerApp { manager, state });
}

#[cfg(test)]
mod tests {

    use crate::config::structs::Roles;
    use crate::rolemanager::RoleContext;
    use crate::version::PACKAGE_VERSION;

    use super::*;

    trait Downcast {
        unsafe fn downcast<T>(&self) -> &T;
    }

    impl Downcast for dyn State {
        unsafe fn downcast<T>(&self) -> &T {
            &*(self as *const dyn State as *const T)
        }
    }

    #[derive(Debug)]
    struct TestState {
        pub i: usize,
        pub j: char,
    }

    impl TestState {
        pub fn new(i: usize, j: char) -> Self {
            Self { i, j }
        }
    }

    impl State for TestState {
        fn create(self: Box<Self>, _: &mut RoleContext) -> Box<dyn State> {
            Box::new(Self::new(self.i + 1, 'c'))
        }
        fn delete(self: Box<Self>, _: &mut RoleContext, _: usize) -> Box<dyn State> {
            Box::new(Self::new(self.i + 1, 'd'))
        }
        fn submit(self: Box<Self>, _: &mut RoleContext, _: usize) -> Box<dyn State> {
            Box::new(Self::new(self.i + 1, 's'))
        }
        fn cancel(self: Box<Self>, _: &mut RoleContext) -> Box<dyn State> {
            Box::new(Self::new(self.i + 1, 'l'))
        }
        fn confirm(self: Box<Self>, _: &mut RoleContext) -> Box<dyn State> {
            Box::new(Self::new(self.i + 1, 'm'))
        }
        fn config(self: Box<Self>, _: &mut RoleContext) -> Box<dyn State> {
            Box::new(Self::new(self.i + 1, 'g'))
        }
        fn input(self: Box<Self>, _: &mut RoleContext, _: Input) -> Box<dyn State> {
            Box::new(Self::new(self.i + 1, 'i'))
        }
        fn render(&self, _: &mut RoleContext, _: &mut Cursive) {}
    }

    #[test]
    fn test_exit_execute() {
        let mut s = Cursive::new();
        let manager = RoleContext::new(Roles::new(PACKAGE_VERSION));
        let state = Box::new(TestState::new(0, 'a'));
        s.set_user_data(RoleManagerApp { manager, state });
        execute(&mut s, ExecuteType::Exit);
        let app: RoleManagerApp = s.take_user_data().unwrap();
        assert!(app.manager.is_exiting());
    }

    fn test_dyn_state(state: &Box<dyn State>, i: usize, j: char) {
        unsafe {
            let state = state.downcast::<TestState>();
            assert_eq!(state.i, i);
            assert_eq!(state.j, j);
        }
    }

    fn execute_and_test(s: &mut Cursive, exec_type: ExecuteType, i: usize, j: char) {
        execute(s, exec_type);
        let RoleManagerApp { state, manager } = s.take_user_data().unwrap();
        test_dyn_state(&state, i, j);
        s.set_user_data(RoleManagerApp { manager, state });
    }

    #[test]
    fn test_execute() {
        let mut s = Cursive::new();
        let manager = RoleContext::new(Roles::new(PACKAGE_VERSION));
        let state = Box::new(TestState::new(0, 'a'));
        s.set_user_data(RoleManagerApp { manager, state });
        execute_and_test(&mut s, ExecuteType::Cancel, 1, 'l');
        execute_and_test(&mut s, ExecuteType::Confirm, 2, 'm');
        execute_and_test(&mut s, ExecuteType::Config, 3, 'g');
        execute_and_test(&mut s, ExecuteType::Create, 4, 'c');
        execute_and_test(&mut s, ExecuteType::Delete(0), 5, 'd');
        execute_and_test(
            &mut s,
            ExecuteType::Input(Input::String("test".to_string())),
            6,
            'i',
        );
        execute_and_test(&mut s, ExecuteType::Submit(0), 7, 's');
    }

    #[test]
    fn test_input_string() {
        let input = Input::String("cap_dac_override,cap_sys_admin".to_string());
        assert_eq!(
            input.as_vec(),
            vec!["cap_dac_override".to_string(), "cap_sys_admin".to_string()]
        );
        assert_eq!(input.as_caps(), Caps::V2(2097154));
        assert_eq!(input.as_string(), "cap_dac_override,cap_sys_admin");
    }

    #[test]
    fn test_input_vec() {
        let input = Input::Vec(vec![
            "cap_dac_override".to_string(),
            "cap_sys_admin".to_string(),
        ]);
        assert_eq!(input.as_string(), "cap_dac_override,cap_sys_admin");
        assert_eq!(
            input.as_vec(),
            vec!["cap_dac_override".to_string(), "cap_sys_admin".to_string()]
        );
        assert_eq!(input.as_caps(), Caps::V2(2097154));
    }

    #[test]
    fn test_input_caps() {
        let input = Input::Caps(Caps::V2(2097154));
        assert_eq!(
            input.as_vec(),
            vec!["cap_dac_override".to_string(), "cap_sys_admin".to_string()]
        );
        assert_eq!(input.as_string(), "cap_dac_override,cap_sys_admin");
        assert_eq!(input.as_caps(), Caps::V2(2097154));
    }

    #[test]
    fn test_error() {
        let mut s = Cursive::new();
        let mut manager = RoleContext::new(Roles::new(PACKAGE_VERSION));
        let state = Box::new(TestState::new(0, 'a'));
        manager.set_error("err_test".into());
        // asssert that error is set
        assert!(manager.take_error().is_some());
        manager.set_error("err_test".into());

        s.set_user_data(RoleManagerApp { manager, state });
        execute(&mut s, ExecuteType::Exit);
        let mut app: RoleManagerApp = s.take_user_data().unwrap();
        assert!(app.manager.take_error().is_none());
    }
}
