use cursive::{views::{SelectView, Dialog, TextView, LinearLayout, EditView}, view::{Scrollable, Nameable}, direction::Orientation};

use super::{State, Input, role::EditRoleState, options::SelectOptionState, ExecuteType, execute};
use crate::{RoleManager, Cursive, RoleManagerApp, capabilities::{self, Caps}, checklist::CheckListView};


pub struct SelectCommandBlockState;
pub struct DeleteCommandBlockState;
pub struct EditCommandBlockState;

pub struct EditCapabilitiesState;

pub struct EditCommandState;
pub struct DeleteCommandState;

impl State for SelectCommandBlockState {
    fn create(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(EditCommandBlockState)
    }
    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        self
    }
    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        manager.set_selected_command_group(index);
        Box::new(EditCommandBlockState)
    }
    fn cancel(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(EditRoleState)
    }
    fn config(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        self
    }
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive){
        let mut select = SelectView::new().on_submit(|s,item|{
            execute(s,ExecuteType::Submit(*item));
        });
        manager.selected_role().as_ref().borrow().get_commands_list().iter().enumerate().for_each(|(index, e)| {
            let commands = e.as_ref().borrow();
            if commands.has_id() {
                select.add_item(commands.get_id(), index);
            } else {
                select.add_item(format!("Block #{}",index), index);
            }
        });
        cursive.add_layer(
        Dialog::around(select.scrollable())
        .button("Add", |s| {
            execute(s,ExecuteType::Create);
        })
        .button("Ok", |s| {
            execute(s,ExecuteType::Confirm);
        }))
    }
}

impl State for DeleteCommandBlockState {
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
        Box::new(SelectCommandBlockState)
    }
    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        manager.delete_selected_commands_block();
        Box::new(SelectCommandBlockState)
    }
    fn config(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        self
    }
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive) {
        let binding = manager.selected_command_group();
        let command_block = binding.as_ref().borrow();
        let name = if command_block.has_id() {
            command_block.get_id().to_string()
        } else {
            format!("Block #{}", manager.selected_command_group_index()).to_string()
        };
        cursive.add_layer(Dialog::around( TextView::new(format!("Are you sure you want to delete {} ?", name)))
            .title("Confirm delete command block")
            .button("Yes",  move|s| {
                execute(s,ExecuteType::Confirm);
            })
            .button("No",  move|s| {
                execute(s,ExecuteType::Cancel);
            })
        );
    }
}

/**
 * This State is used to edit a command block
 * Add command with add button (with Dialog)
 * Delete command with delete Key (Backspace or Delete)
 * Also used to set capabilities on the command block (with Dialog)
 * And used to set the id of the command block (with Dialog)
 * And used to set options on the command block (with Dialog)
 */
impl State for EditCommandBlockState {
    fn create(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(EditCommandState)
    }
    fn delete(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        manager.set_selected_command(index);
        Box::new(DeleteCommandState)
    }
    fn submit(self: Box<Self>, manager : &mut RoleManager, index : usize) -> Box<dyn State>{
        manager.set_selected_command(index);
        Box::new(EditCommandState)
    }
    fn cancel(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(SelectCommandBlockState)
    }
    fn confirm(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn config(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(SelectOptionState)
    }
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        self
    }
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive) {
        let binding = manager.selected_command_group();
        let command_block = binding.as_ref().borrow();
        let name = if command_block.has_id() {
            command_block.get_id().to_string()
        } else {
            format!("Block #{}", manager.selected_command_group_index()).to_string()
        };
        let mut select = SelectView::new().on_submit(|s,item|{
            execute(s,ExecuteType::Submit(*item));
        });
        command_block.get_commands_list().iter().enumerate().for_each(|(index, e)| {
            select.add_item(e, index);
        });
        cursive.add_layer(
        Dialog::around(select.scrollable())
        .title(format!("Edit {}", name))
        .button("Add", |s| {
            execute(s,ExecuteType::Create);
        })
        .button("Options", |s| {
            execute(s,ExecuteType::Config);
        })
        .button("Capabilities", |s| {
            execute(s,ExecuteType::Config);
        })
        .button("Ok", |s| {
            execute(s,ExecuteType::Confirm);
        }))
    }
}

impl State for EditCapabilitiesState {
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
        Box::new(EditCommandBlockState)
    }
    fn confirm(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn config(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        manager.selected_command_group().borrow_mut().set_capabilities(input.as_caps());
        Box::new(SelectCommandBlockState)
    }
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive){
        let mut select = CheckListView::<(&str,&str)>::new().autojump()
        .on_select(|s, item| {
            let info = s.find_name::<TextView>("info");
            if let Some(mut info) = info {
                info.set_content(item.1);
            }
        });
    let selected = manager.selected_command_group().as_ref().borrow().get_capabilities();
    let mut pos = 0;
    for capability in capabilities::POSITIONS {
        select.add_item(capability.0.clone(), selected.clone() & (1 << pos) != 0.into(), capability);
        pos+=1;
    }
    let mut layout = LinearLayout::new(Orientation::Horizontal);
    layout.add_child(select.with_name("capabilities").scrollable());
    
    layout.add_child(TextView::new(capabilities::POSITIONS[0].1).with_name("info"));
    cursive.add_layer(Dialog::around( layout)
        .title("Select capabilities, CTRL+A to check all, CTRL+U to uncheck all and CTRL+D to invert selection")
        .button("Ok",  move|s| {
            let view = s.find_name::<CheckListView<(&str, &str)>>("capabilities").unwrap();
            let mut caps = Caps::V2(0);
            for (pos, item) in view.iter().enumerate() {
                if *item.1 {
                    caps |= 1 << pos;
                }
            }
            execute(s,ExecuteType::Input( Input::Caps(caps)));
        }));
    }
}

impl State for EditCommandState {
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
        Box::new(EditCommandBlockState)
    }
    fn confirm(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn config(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        if manager.selected_command_index().is_some() {
            manager.selected_command_group().borrow_mut().set_command(manager.selected_command_index().unwrap(), &input.as_string());
        } else {
            manager.selected_command_group().borrow_mut().add_command(&input.as_string());
        }
        Box::new(EditCommandBlockState)
    }
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive){
        let mut edit = EditView::new();
        if manager.selected_command().is_some() {
            edit.set_content(manager.selected_command().unwrap());
        }
        cursive.add_layer(Dialog::around(edit.with_name("edit"))
        .title("Edit command")
        .button("Ok",  move|s| {
            let view = s.find_name::<EditView>("edit").unwrap();
            execute(s,ExecuteType::Input( Input::String(view.get_content().to_string())));
        })
        .button("Cancel",  move|s| {
            execute(s,ExecuteType::Cancel);
        }));
    }
}

impl State for DeleteCommandState {
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
        Box::new(EditCommandBlockState)
    }
    fn confirm(self: Box<Self>, manager : &mut RoleManager) -> Box<dyn State>{
        Box::new(EditCommandBlockState)
    }
    fn config(self: Box<Self>, _manager : &mut RoleManager) -> Box<dyn State>{
        self
    }
    fn input(self: Box<Self>, manager : &mut RoleManager, input : Input) -> Box<dyn State>{
        self
    }
    fn render(&self, manager : &mut RoleManager, cursive : &mut Cursive){
        let text = format!("Are you sure to delete {}?", manager.selected_command().unwrap());
        cursive.add_layer(Dialog::around(TextView::new(text))
        .title("Delete command")
        .button("Yes",  move|s| {
            execute(s,ExecuteType::Confirm);
        })
        .button("No",  move|s| {
            execute(s,ExecuteType::Cancel);
        }));
    }
}
