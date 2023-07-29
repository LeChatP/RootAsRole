use std::{cell::RefCell, collections::HashSet, ffi::CStr, rc::Rc};

use cursive::{
    view::{Nameable, Scrollable},
    views::{Dialog, SelectView},
    Cursive,
};
use libc::{endgrent, endpwent, getgrent, getpwent, setgrent, setpwent};

use crate::{
    checklist::CheckListView, config::structs::Groups, ActorType, RoleContext, RoleManagerApp,
};

use super::{
    common::{ConfirmState, InputState},
    execute, DeletableItemState, ExecuteType, Input, PushableItemState, State,
};

#[derive(Clone)]
pub struct Users {
    pub name: Rc<RefCell<Vec<String>>>,
}

impl Default for Users {
    fn default() -> Self {
        Users {
            name: RefCell::new(Vec::new()).into(),
        }
    }
}

impl FromIterator<String> for Users {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Users {
        let mut users = Vec::new();
        for user in iter {
            users.push(user);
        }
        Users {
            name: RefCell::new(users.to_vec()).into(),
        }
    }
}

impl From<Users> for Vec<String> {
    fn from(val: Users) -> Self {
        val.name.as_ref().borrow().to_vec()
    }
}

impl From<String> for Users {
    fn from(name: String) -> Self {
        let vname = vec![name];
        Users {
            name: RefCell::new(vname).into(),
        }
    }
}
impl ToString for Users {
    fn to_string(&self) -> String {
        self.name.borrow().join(",")
    }
}
impl From<Users> for String {
    fn from(val: Users) -> Self {
        val.name.borrow().join(",")
    }
}

impl From<Vec<String>> for Users {
    fn from(name: Vec<String>) -> Self {
        Users {
            name: RefCell::new(name).into(),
        }
    }
}

#[derive(Clone)]
pub struct SelectUserState<T, V>
where
    T: State + Clone + PushableItemState<Users> + 'static,
    V: State + Clone + 'static,
{
    previous_state: V,
    next_state: T,
    checklist: bool,
    selected: Users,
}

impl<T, V> SelectUserState<T, V>
where
    T: State + Clone + PushableItemState<Users> + 'static,
    V: State + Clone + 'static,
{
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

    pub fn new(previous_state: V, next_state: T, checklist: bool, selected: Option<Users>) -> Self {
        SelectUserState {
            checklist,
            selected: selected.unwrap_or_default(),
            previous_state,
            next_state,
        }
    }
}

#[derive(Clone)]
pub struct SelectGroupState<T, V>
where
    T: State + Clone + PushableItemState<Vec<Groups>> + 'static,
    V: State + Clone + 'static,
{
    previous_state: V,
    next_state: T,
    groups: Vec<Groups>,
}

#[derive(Clone)]

pub struct EditGroupState<T, V>
where
    T: State + Clone + 'static,
    V: State + Clone + PushableItemState<Groups> + 'static,
{
    gid_list: Vec<String>,
    previous_state: T,
    next_state: V,
    selected: Option<Groups>,
}

fn get_groups() -> Vec<String> {
    let mut groups = Vec::new();
    unsafe { setgrent() };
    let mut group = unsafe { getgrent().as_mut() };
    while group.is_some() {
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
    while pwentry.is_some() {
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
    };
    let some = already_in_list.is_some();
    for user in actors.iter().cloned() {
        view.add_item(
            user.to_string(),
            some && already_in_list.as_ref().unwrap().contains(&user),
            user,
        );
    }
    let Some(already_in_list) = already_in_list else { return };
    for user in already_in_list
        .iter()
        .map(|x| x.to_string())
        .collect::<HashSet<String>>()
        .difference(
            &actors
                .iter()
                .map(|x| x.to_string())
                .collect::<HashSet<String>>(),
        )
    {
        view.add_item(user.to_string(), true, user.to_string());
    }
}

fn add_actors_select(actortype: ActorType, view: &mut SelectView<String>) {
    let actors = match actortype {
        ActorType::User => get_users(),
        ActorType::Group => get_groups(),
    };
    for user in actors {
        view.add_item(&user, user.to_string());
    }
}

impl<T, V> State for SelectUserState<T, V>
where
    T: State + Clone + PushableItemState<Users> + 'static,
    V: State + Clone + 'static,
{
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(InputState::<
            SelectUserState<T, V>,
            SelectUserState<T, V>,
            String,
        >::new(*self, "Enter username or uid", None))
    }

    fn delete(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        manager.selected_actors = None;
        Box::new(self.previous_state)
    }

    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn input(mut self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        self.next_state.push(manager, input.as_vec().into());
        manager.selected_actors = None;
        Box::new(self.next_state)
    }

    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        if manager.selected_actors.is_none() {
            manager.selected_actors = Some(Rc::new(RefCell::new(
                self.selected
                    .name
                    .as_ref()
                    .borrow()
                    .clone()
                    .into_iter()
                    .collect::<HashSet<String>>(),
            )));
        }
        if self.checklist {
            let mut select = CheckListView::<String>::new()
                .on_submit(|s, _b, i| {
                    let RoleManagerApp { manager, state } = s.take_user_data().unwrap();
                    if let Some(selected) = manager.selected_actors.as_ref() {
                        selected.as_ref().borrow_mut().insert(i.to_string());
                    }
                    s.set_user_data(RoleManagerApp { manager, state });
                })
                .autojump();
            add_actors(
                ActorType::User,
                &mut select,
                manager
                    .selected_actors
                    .clone()
                    .map(|e| e.as_ref().borrow().iter().cloned().collect::<Vec<String>>()),
            );
            cursive.add_layer(
                Dialog::around(select.with_name("users").scrollable())
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
            let mut select =
                SelectView::<String>::new()
                    .autojump()
                    .on_submit(|s, user: &String| {
                        execute(s, ExecuteType::Input(Input::String(user.to_string())));
                    });
            add_actors_select(ActorType::User, &mut select);
            cursive.add_layer(
                Dialog::around(select.scrollable().with_name("users"))
                    .title("Select User")
                    .button("Input new user", |s| {
                        execute(s, ExecuteType::Create);
                    })
                    .button("Cancel", |s| {
                        execute(s, ExecuteType::Cancel);
                    }),
            );
        }
    }
}

impl<T, V> PushableItemState<String> for SelectUserState<T, V>
where
    T: State + Clone + PushableItemState<Users> + 'static,
    V: State + Clone + 'static,
{
    fn push(&mut self, manager: &mut RoleContext, item: String) {
        if let Some(selected) = manager.selected_actors.as_ref() {
            selected.as_ref().borrow_mut().insert(item);
        }
    }
}

impl<T, V> SelectGroupState<T, V>
where
    T: State + Clone + PushableItemState<Vec<Groups>> + 'static,
    V: State + Clone + 'static,
{
    pub fn new(previous_state: V, next_state: T, groups: Vec<Groups>) -> Self {
        Self {
            previous_state,
            next_state,
            groups,
        }
    }
}

impl<T, V> State for SelectGroupState<T, V>
where
    T: State + Clone + PushableItemState<Vec<Groups>> + 'static,
    V: State + Clone + 'static,
{
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(EditGroupState::<Self, Self>::new(
            *self.clone(),
            *self,
            None,
        ))
    }

    fn delete(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn submit(self: Box<Self>, _manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        Box::new(EditGroupState::<Self, Self>::new(
            *self.clone(),
            *self.clone(),
            self.groups.get(index).map(|x| x.to_owned()),
        ))
    }

    fn cancel(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        // todo rollback
        Box::new(self.previous_state)
    }

    fn confirm(mut self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        self.next_state.push(manager, self.groups);
        Box::new(self.next_state)
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn input(self: Box<Self>, _manager: &mut RoleContext, _input: Input) -> Box<dyn State> {
        self
    }

    fn render(&self, _manager: &mut RoleContext, cursive: &mut Cursive) {
        let mut select = SelectView::<usize>::new().autojump().on_submit(|s, item| {
            execute(s, ExecuteType::Submit(*item));
        });
        for (index, group) in self.groups.iter().enumerate() {
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
                .button("Ok", move |s| {
                    execute(s, ExecuteType::Confirm);
                }),
        );
    }
}

impl<T, V> EditGroupState<T, V>
where
    T: State + Clone + 'static,
    V: State + Clone + PushableItemState<Groups> + 'static,
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

    pub fn new(previous_state: T, next_state: V, selected: Option<Groups>) -> Self {
        let a = Self::complete_list(selected.to_owned().map(Into::<Vec<String>>::into));
        EditGroupState {
            gid_list: a,
            previous_state,
            next_state,
            selected,
        }
    }
}

impl<T, V> State for EditGroupState<T, V>
where
    T: State + Clone + 'static,
    V: State + Clone + PushableItemState<Groups> + 'static,
{
    fn create(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        Box::new(InputState::<
            EditGroupState<T, V>,
            EditGroupState<T, V>,
            String,
        >::new(*self, "Input new group", None))
    }

    fn delete(self: Box<Self>, _manager: &mut RoleContext, index: usize) -> Box<dyn State> {
        Box::new(ConfirmState::new(*self, "Confirm delete group", index))
    }

    fn submit(self: Box<Self>, _manager: &mut RoleContext, _index: usize) -> Box<dyn State> {
        self
    }

    fn cancel(self: Box<Self>, manager: &mut RoleContext) -> Box<dyn State> {
        manager.selected_actors = None;
        Box::new(self.previous_state)
    }

    fn confirm(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn config(self: Box<Self>, _manager: &mut RoleContext) -> Box<dyn State> {
        self
    }

    fn input(mut self: Box<Self>, manager: &mut RoleContext, input: Input) -> Box<dyn State> {
        self.next_state.push(manager, input.as_vec().into());
        manager.selected_actors = None;
        Box::new(self.next_state)
    }

    fn render(&self, manager: &mut RoleContext, cursive: &mut Cursive) {
        if manager.selected_actors.is_none() {
            if let Some(selected) = &self.selected {
                manager.selected_actors = Some(Rc::new(RefCell::new(selected.groups.to_owned())));
            } else {
                manager.selected_actors = Some(Rc::new(RefCell::new(HashSet::new())));
            }
        }
        let mut select = CheckListView::<String>::new()
            .autojump()
            .on_submit(|s, _, i| {
                if !i.is_empty() {
                    let RoleManagerApp { manager, state } = s.take_user_data().unwrap();
                    if let Some(selected) = manager.selected_actors.as_ref() {
                        selected.as_ref().borrow_mut().insert(i.to_owned());
                    }
                    s.set_user_data(RoleManagerApp { manager, state });
                }
            });
        if let Some(group_list) = &manager.selected_actors {
            add_actors(
                ActorType::Group,
                &mut select,
                Some(group_list.as_ref().borrow().iter().cloned().collect()),
            );
        } else {
            add_actors(ActorType::Group, &mut select, None);
        }

        cursive.add_layer(
            Dialog::around(select.with_name("select").scrollable())
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

impl<T, V> PushableItemState<String> for EditGroupState<T, V>
where
    T: State + Clone + 'static,
    V: State + Clone + PushableItemState<Groups> + 'static,
{
    fn push(&mut self, manager: &mut RoleContext, item: String) {
        if let Some(selected) = manager.selected_actors.as_ref() {
            selected.as_ref().borrow_mut().insert(item);
        }
    }
}

impl<T, V> PushableItemState<Groups> for SelectGroupState<T, V>
where
    V: State + Clone + 'static,
    T: State + Clone + PushableItemState<Vec<Groups>> + 'static,
{
    fn push(&mut self, _manager: &mut RoleContext, item: Groups) {
        if !item.groups.is_empty() {
            self.groups.push(item);
        }
    }
}

impl<T, V> DeletableItemState for EditGroupState<T, V>
where
    T: State + Clone + 'static,
    V: State + Clone + PushableItemState<Groups> + 'static,
{
    fn remove_selected(&mut self, _manager: &mut RoleContext, index: usize) {
        self.gid_list.remove(index);
    }
}
#[cfg(test)]
mod tests {
    use crate::state::tests::TestState;

    use super::*;

    #[test]
    fn test_to_string() {
        let users = Users {
            name: RefCell::new(vec!["Alice".to_string(), "Bob".to_string()]).into(),
        };
        assert_eq!(users.to_string(), "Alice,Bob");
    }

    #[test]
    fn test_from() {
        let users = Users::from(vec!["Alice".to_string(), "Bob".to_string()]);
        assert_eq!(users.to_string(), "Alice,Bob");
        let string = String::from(users.clone());
        assert_eq!(string, "Alice,Bob");
    }
}
