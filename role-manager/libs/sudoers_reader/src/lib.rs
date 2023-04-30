use grammar::{Rule,AstNode};
use pest::error::Error;

mod asthandler;
pub mod grammar;

#[macro_use]
extern crate pest_derive;
extern crate pest;



fn parse_sudoers(contents: &str) -> Result<Vec<AstNode>, Error<Rule>> {
    Ok(vec![])
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sudoers() {
        parse_sudoers("");
    }
}