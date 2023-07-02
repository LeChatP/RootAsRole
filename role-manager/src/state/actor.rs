use std::{ffi::CStr};

use cursive::{
    view::Nameable,
    views::{Dialog, SelectView},
    Cursive,
};
use libc::{endgrent, endpwent, getgrent, getpwent, setgrent, setpwent};

use crate::{checklist::CheckListView, ActorType, RoleContext};

use super::{
    common::{ConfirmState, InputState},
    execute,
    role::EditRoleState,
    DeletableItemState, ExecuteType, Input, PushableItemState, State,
};

#[derive(Clone)]
pub struct SelectUserState {
    checklist: bool,
    uid_list: Vec<String>,
}

impl SelectUserState {
    /**
     * Returns a list of all users in system and the one not in the list, merge them and return
     */
    fn complete_list(selected: Option<Vec<String>>) -> Vec<String> {
        let mut users = get_users();
        if let Some(selected) = selected {
            for user in selected {
                if !users.contains(&user) {
                    users.push(user.to_string());
                }
            }
        }
        users
    }

    pub fn new(checklist: bool, selected: Option<Vec<String>>) -> Self {
        SelectUserState {
            checklist,
            uid_list: Self::complete_list(selected),
        }
    }
}

#[derive(Clone)]
pub struct SelectGroupState;

#[derive(Clone)]

pub struct EditGroupState<T>
where
    T: State + Clone + 'static,
{
    gid_list: Vec<String>,
    previous_state: Box<T>,
}

fn get_groups() -> Vec<String> {
    let mut groups = Vec::new();
    unsafe { setgrent() };
    let mut group = unsafe { getgrent().as_mut() };
    while !group.is_none() {
        let gr = group.unwrap();
        groups.push(unsafe { CStr::from_ptr(gr.gr_name).to_str().unwrap().to_string() });
        group = unsafe { getgrent().as_mut() };
    }
    unsafe { endgrent() };
    groups
}

fn get_users() -> Vec<String> {
    let mut users = Vec::new();
    unsafe { setpwent() };
    let mut pwentry = unsafe { getpwent().as_mut() };
    while !pwentry.is_none() {
        let user = pwentry.unwrap();
        users.push(unsafe { CStr::from_ptr(user.pw_name).to_str().unwrap().to_string() });
        pwentry = unsafe { getpwent().as_mut() };
    }
    unsafe { endpwent() };
    users
}

fn add_actors(
    actortype: ActorType,
    view: &mut CheckListView<String>,
    already_in_list: Option<Vec<String>>,
) {
    let actors = match actortype {
        ActorType::User => get_users(),
        ActorType::Group => get_groups(),
        _ => panic!("Invalid state"),
    };
    let some = already_in_list.is_some();
    for user in actors {
        view.add_item(
            user.to_owned(),
            some && already_in_list.as_ref().unwrap().contains(&user),
            user,
        );
    }
}

fn add_actors_select(actortype: ActorType, view: &mut SelectView<String>) {
    let actors = match actortype {
        ActorType::User => get_users(),
        ActorType::Group => get_groups(),
    };
    for user in actors {
        view.add_item(&user, user.to_owned());
    }
}

impl State for SelectUserState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(InputState::<SelectUserState,SelectUserState>::new(self, "Enter username or uid", None))
    }

    fn delete(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditRoleState)
    }

    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        let _commands = manager.get_role().unwrap().as_ref().borrow_mut().users = input.as_vec();
        Box::new(EditRoleState)
    }

    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        if self.checklist {
            let mut select = CheckListView::<String>::new().autojump();
            add_actors(
                ActorType::User,
                &mut select,
                Some(
                    manager
                        .get_role()
                        .unwrap()
                        .as_ref()
                        .borrow()
                        .users
                        .to_vec()
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
                ),
            );
            cursive.add_layer(
                Dialog::around(select.with_name("users"))
                    .title("Select User")
                    .button("Input new user", |s| {
                        execute(s, ExecuteType::Create);
                    })
                    .button("Cancel", |s| {
                        execute(s, ExecuteType::Cancel);
                    })
                    .button("Ok", |s| {
                        let select = s.find_name::<CheckListView<String>>("users").unwrap();
                        let items = select.get_checked_item();
                        let users = items.iter().map(|x| x.1.clone()).collect();
                        execute(s, ExecuteType::Input(Input::Vec(users)));
                    }),
            );
        } else {
            let mut select = SelectView::<String>::new().autojump();
            add_actors_select(ActorType::User, &mut select);
            cursive.add_layer(
                Dialog::around(select.with_name("users"))
                    .title("Select User")
                    .button("Input new user", |s| {
                        execute(s, ExecuteType::Create);
                    })
                    .button("Cancel", |s| {
                        execute(s, ExecuteType::Cancel);
                    })
                    .button("Ok", |s| {
                        let select = s.find_name::<SelectView<String>>("users").unwrap();
                        let user = select.selection().unwrap();
                        execute(s, ExecuteType::Input(Input::String(user.to_string())));
                    }),
            );
        }
    }
}

impl PushableItemState<String> for SelectUserState {
    fn push(&mut self, manager: &mut RoleContext, item: String) {
        manager
            .get_role()
            .unwrap()
            .as_ref()
            .borrow_mut()
            .users
            .push(item);
    }
}

impl State for SelectGroupState {
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditGroupState::<Self>::new(self, None))
    }

    fn delete(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        if let Err(err) =  manager.select_groups(index){
            manager.set_error(err);
            return self;
        }
        Box::new(EditGroupState::<Self>::new(self, manager.get_group()))
    }

    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        // todo rollback
        Box::new(EditRoleState)
    }

    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditRoleState)
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }

    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = SelectView::<usize>::new().autojump().on_submit(|s, item| {
            execute(s, ExecuteType::Submit(*item));
        });
        for (index, group) in manager
            .get_role()
            .unwrap()
            .as_ref()
            .borrow()
            .groups
            .iter()
            .enumerate()
        {
            select.add_item(group.join(" & "), index);
        }
        cursive.add_layer(
            Dialog::around(select)
                .title("Select Group List to Edit")
                .button("Cancel", |s| {
                    execute(s, ExecuteType::Cancel);
                })
                .button("Add", move |s| {
                    execute(s, ExecuteType::Create);
                })
                .button("Ok" , move |s| {
                    execute(s, ExecuteType::Confirm);
                }),
        );
    }
}

impl<T> EditGroupState<T>
where
    T: State + Clone + 'static,
{
    /**
     * Returns a list of all groups in system and the one not in the list, merge them and return
     */
    fn complete_list(selected: Option<Vec<String>>) -> Vec<String> {
        let mut groups = get_groups();
        if let Some(selected) = selected {
            for group in selected {
                if !groups.contains(&group) {
                    groups.push(group.clone());
                }
            }
        }
        groups
    }

    pub fn new(previous_state: Box<T>, selected: Option<Vec<String>>) -> Self {
        EditGroupState {
            gid_list: Self::complete_list(selected),
            previous_state,
        }
    }
}

impl<T> State for EditGroupState<T>
where
    T: State + Clone + 'static,
{
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(InputState::<EditGroupState<T>,EditGroupState<T>>::new(self, "Input new group", None))
    }

    fn delete(self: Box<Self>, _manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        Box::new(ConfirmState::new(self, "Confirm delete group", index))
    }

    fn submit(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(SelectGroupState)
    }

    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        if manager.get_group().is_some() {
            if let Err(err) = manager.set_group(input.as_vec()) {
                manager.set_error(err);
            }
        }else {
            if let Err(err) = manager.add_group(input.as_vec()) {
                manager.set_error(err);
            }
        }
        Box::new(SelectGroupState)
    }

    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = CheckListView::<String>::new().autojump();
        if let Some(group_list) = manager.get_group() {
            add_actors(ActorType::Group, &mut select, Some(group_list.to_vec()));
        } else {
            add_actors(ActorType::Group, &mut select, None);
        }

        cursive.add_layer(
            Dialog::around(select.with_name("select"))
                .title("Select Groups combination")
                .button("Input new group", |s| {
                    execute(s, ExecuteType::Create);
                })
                .button("Cancel", |s| {
                    execute(s, ExecuteType::Cancel);
                })
                .button("Ok", |s| {
                    let mut res = None;
                    s.call_on_name("select", |view: &mut CheckListView<String>| {
                        res = Some(Input::Vec(
                            view.iter()
                                .filter_map(|(_, checked, group)| {
                                    if *checked {
                                        Some(group.to_string())
                                    } else {
                                        None
                                    }
                                })
                                .collect(),
                        ));
                    });
                    execute(s, ExecuteType::Input(res.expect("No input")));
                }),
        );
    }
}

impl<T> PushableItemState<String> for EditGroupState<T>
where
    T: State + Clone + 'static,
{
    fn push(&mut self, _manager: &mut RoleContext, item: String) {
        if !self.gid_list.contains(&item) {
            self.gid_list.push(item);
        }
    }
}

impl<T> DeletableItemState for EditGroupState<T>
where
    T: State + Clone + 'static,
{
    fn remove_selected(&mut self, _manager: &mut RoleContext, index: usize) {
        self.gid_list.remove(index);
    }
}
