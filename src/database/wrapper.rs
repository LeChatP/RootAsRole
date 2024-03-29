use std::{cell::RefCell, rc::Rc};

use super::{options::Opt, structs::{SConfig,SRole, STask}};
pub type RcRefCell<T> = Rc<RefCell<T>>;

pub type SConfigWrapper = RcRefCell<SConfig>;
pub type SRoleWrapper = RcRefCell<SRole>;
pub type STaskWrapper = RcRefCell<STask>;
pub type OptWrapper = Option<RcRefCell<Opt>>;

pub trait DefaultWrapper {
    fn default() -> Self;
}

impl DefaultWrapper for SConfigWrapper {
    fn default() -> Self {
        Rc::new(RefCell::new(SConfig::default()))
    }
}

impl DefaultWrapper for SRoleWrapper {
    fn default() -> Self {
        Rc::new(RefCell::new(SRole::default()))
    }
}

impl DefaultWrapper for STaskWrapper {
    fn default() -> Self {
        Rc::new(RefCell::new(STask::default()))
    }
}

impl DefaultWrapper for OptWrapper {
    fn default() -> Self {
        None
    }
}