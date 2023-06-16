use pest::iterators::Pair;
use crate::grammar::{Rule,AstNode};


pub trait AstHandler {
    fn execute(&mut self, pair: &Pair<Rule>) -> Option<AstNode> {
        if let Some(node) = self.handle(pair) {
            return Some(node);
        } else if let Some(next) = &mut self.next() {
            return next.execute(pair);
        }
        None
    }
    fn handle(&mut self, pair: &Pair<Rule>) -> Option<AstNode>;
    fn next(&mut self) -> Option<Box<dyn AstHandler>>;
}

pub(self) fn into_next(
    handler: impl AstHandler + Sized + 'static,
) -> Option<Box<dyn AstHandler>> {
    Some(Box::new(handler))
}

pub struct AliasHandler {
    next: Option<Box<dyn AstHandler>>,
}

impl AstHandler for AliasHandler {
    fn handle(&mut self, pair: &Pair<Rule>) -> Option<AstNode> {
        None
    }
    fn next(&mut self) -> Option<Box<dyn AstHandler>> {
        self.next.take()
    }
}

pub struct DefaultsHandler {
    next: Option<Box<dyn AstHandler>>,
}

impl AstHandler for DefaultsHandler {
    fn handle(&mut self, pair: &Pair<Rule>) -> Option<AstNode> {
        None
    }
    fn next(&mut self) -> Option<Box<dyn AstHandler>> {
        self.next.take()
    }
}

pub struct UserSpecHandler {
    next: Option<Box<dyn AstHandler>>,
}

impl AstHandler for UserSpecHandler {
    fn handle(&mut self, pair: &Pair<Rule>) -> Option<AstNode> {
        None
    }
    fn next(&mut self) -> Option<Box<dyn AstHandler>> {
        self.next.take()
    }
}

pub struct IncludeHandler {
    next: Option<Box<dyn AstHandler>>,
}

impl AstHandler for IncludeHandler {
    fn handle(&mut self, pair: &Pair<Rule>) -> Option<AstNode> {
        None
    }
    fn next(&mut self) -> Option<Box<dyn AstHandler>> {
        self.next.take()
    }
}
