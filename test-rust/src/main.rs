use std::cell::RefCell;
use std::rc::Rc;
use std::rc::Weak;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Level {
    None,
    Default,
    Global,
    Role,
    Task,
}

#[derive(Debug, Clone)]
pub struct Opt {
    level: Level,
    pub path: Option<String>,
    pub env_whitelist: Option<String>,
    pub env_checklist: Option<String>,
    pub no_root: Option<bool>,
    pub bounding: Option<bool>,
}

#[derive(Clone, Debug)]
pub enum Caps {
    V2(u64), // this will evolve
}



#[derive(Clone, Debug)]
pub enum IdTask {
    Name(String),
    Number(usize),
}

impl PartialEq for IdTask {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (IdTask::Name(a), IdTask::Name(b)) => a == b,
            (IdTask::Number(a), IdTask::Number(b)) => a == b,
            _ => false,
        }
    }
}

type Groups = Vec<String>;


#[derive(Clone, Debug)]
pub struct Task<'a> {
    role: Weak<RefCell<Role<'a>>>,
    pub id: IdTask,
    pub options: Option<Rc<RefCell<Opt>>>,
    pub commands: Vec<String>,
    pub capabilities: Option<Caps>,
    pub setuid: Option<String>,
    pub setgid: Option<Groups>,
}

#[derive(Debug, Clone)]
pub struct Role<'a> {
    roles: Option<Weak<RefCell<Roles<'a>>>>,
    pub name: String,
    pub users: Vec<String>,
    pub groups: Vec<Groups>,
    pub tasks: Vec<Rc<RefCell<Task<'a>>>>,
    pub options: Option<Rc<RefCell<Opt>>>,
}

#[derive(Debug, Clone)]
pub struct Roles<'a> {
    pub roles: Vec<Rc<RefCell<Role<'a>>>>,
    pub options: Option<Rc<RefCell<Opt>>>,
    pub version: &'a str,
}

#[derive(Debug)]
pub struct OptStack {
    pub(crate) stack: [Option<Rc<RefCell<Opt>>>; 5],
}

impl<'a> Roles<'a> {
    pub fn new(version : &str) -> Rc<RefCell<Roles>> {
        Rc::new(Roles {
            roles: Vec::new(),
            options: None,
            version: version,
        }.into())
    }

    pub fn get_role(&'a self, name: &str) -> Option<Rc<RefCell<Role<'a>>>> {
        for r in self.roles.iter() {
            if r.as_ref().borrow().name == name {
                return Some(r.clone());
            }
        }
        None
    }
}

impl<'a> Role<'a> {
    pub fn new(name: String) -> Rc<RefCell<Role<'a>>> {
        Rc::new(Role {
            roles: None,
            name,
            users: Vec::new(),
            groups: Vec::new(),
            tasks: Vec::new(),
            options: None,
        }.into())
    }
    pub fn set_parent(&mut self, roles: Weak<RefCell<Roles<'a>>>) {
        self.roles = Some(roles);
    }
    pub fn get_task(&'a self, id: &IdTask) -> Option<Rc<RefCell<Task<'a>>>> {
        for t in self.tasks.iter() {
            //test if they are in same enum
            if t.as_ref().borrow().id == *id {
                return Some(t.clone());
            }
        }
        None
    }
    pub fn get_parent(&'a self) -> Option<Rc<RefCell<Roles<'a>>>> {
        match &self.roles {
            Some(r) => r.upgrade(),
            None => None,
        }
    }
}

impl<'a> Task<'a> {
    pub fn new(id: IdTask, role: Weak<RefCell<Role<'a>>>) -> Rc<RefCell<Task<'a>>> {
        Rc::new(Task {
            role,
            id,
            options: None,
            commands: Vec::new(),
            capabilities: None,
            setuid: None,
            setgid: None,
        }.into())
    }
    pub fn get_parent(&'a self) -> Option<Rc<RefCell<Role<'a>>>> {
        self.role.upgrade()
    }

}

fn main() {
    let roles = Roles::new("1.0");
    let role = Role::new("test".to_string());
    let task = Task::new(IdTask::Name("test".to_string()), Rc::downgrade(&role));

    task.borrow_mut().commands.push("test".to_string());
    role.borrow_mut().tasks.push(task);
    role.borrow_mut().set_parent(Rc::downgrade(&roles));
    roles.borrow_mut().roles.push(role);

    println!("{:?}", roles);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roles() {
        let roles = Roles::new("1.0");
        let role = Role::new("test".to_string());
        let task = Task::new(IdTask::Name("test".to_string()), Rc::downgrade(&role));

        task.borrow_mut().commands.push("test".to_string());
        role.borrow_mut().tasks.push(task);
        role.borrow_mut().set_parent(Rc::downgrade(&roles));
        roles.borrow_mut().roles.push(role);

        println!("{:?}", roles);
    }

    #[test]
    fn test_get_task() {
        let roles = Roles::new("1.0");
        let role = Role::new("role_test".to_string());
        let task = Task::new(IdTask::Name("task_test".to_string()), Rc::downgrade(&role));

        task.borrow_mut().commands.push("test".to_string());
        role.borrow_mut().tasks.push(task);
        role.borrow_mut().set_parent(Rc::downgrade(&roles));
        roles.borrow_mut().roles.push(role);
        let binding = roles.borrow().clone();
        let role = binding.get_role("role_test").unwrap().clone();
        let binding = role.borrow().clone();
        let task = binding.get_task(&IdTask::Name("task_test".to_string())).unwrap().clone();
        println!("{:?}", task);
    }
}