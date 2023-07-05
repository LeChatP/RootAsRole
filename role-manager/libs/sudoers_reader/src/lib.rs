use core::num::dec2flt::parse;

use grammar::{AstNode, Rule};
use pest::Parser;
use std::{error::Error, string::ParseError};

mod asthandler;
pub mod grammar;

#[macro_use]
extern crate pest_derive;
extern crate pest;

pub fn parse_sudoers_file(path: &str) -> Result<AstNode, Box<dyn Error>> {
    let contents = std::fs::read_to_string(path)?;
    return parse_sudoers(&contents);
}

pub fn parse_sudoers(contents: &str) -> Result<AstNode, Box<dyn Error>> {
    let mut defaults = vec![];
    let mut aliases = vec![];
    let mut user_spec = vec![];
    let pairs = grammar::SudoersParser::parse(Rule::sudoers, contents)?;
    for pair in pairs {
        match pair.as_rule() {
            Rule::Default_Entry => {
                defaults.extend(asthandler::transform_defaults(pair));
            }
            Rule::Alias => {
                aliases.extend(asthandler::transform_alias(pair));
            }
            Rule::User_Spec => {
                user_spec.push(asthandler::transform_user_spec(pair));
            }
            Rule::Include => {
                let path = asthandler::transform_include(pair);
                let mut parsed = parse_sudoers_file(&path);
                match parsed {
                    Ok(v) => {
                        if let AstNode::SudoersConfig {
                            defaults: sdefaults,
                            aliases: saliases,
                            user_spec: suser_spec,
                        } = v
                        {
                            defaults.extend(sdefaults);
                            aliases.extend(saliases);
                            user_spec.extend(suser_spec);
                        } else {
                            println!("Unexpected included node type: {:?}", v);
                        }
                    }
                    Err(e) => {
                        println!("Error parsing included file: {}", e);
                    }
                }
            }
            Rule::EOI => {
                return Ok(AstNode::SudoersConfig {
                    defaults,
                    aliases,
                    user_spec,
                });
            }
            _ => {
                println!("Unexpected rule: {:?}", pair.as_rule());
            }
        }
    }
    return Err("Unexpected end of input")?;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sudoers() {
        parse_sudoers("");
    }
}
