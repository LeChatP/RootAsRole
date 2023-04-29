extern crate pest;

use pest::{Parser, Token, iterators::Pair};

#[derive(Parser)]
#[grammar = "../../resources/sudoers.pest"]
pub struct SudoersParser;

pub enum AstNode {
    Print(Box<AstNode>),
    Alias {
        alias_type: AliasType,
        dict_vec: Vec<AstNode>,
    },
    Alias_Entry {
        alias_name: String,
        alias_values: Vec<AstNode>,
    },
    Str(String),
    Bool(bool),
    Int(i64),
    
}

enum AliasType {
    HostAlias,
    UserAlias,
    RunAsAlias,
    CmndAlias,
}

/**
 * Input pair is at Alias token 
 */
fn discover_alias(pair: pest::iterators::Pair<Rule>) -> (AliasType, String, Vec<String>) {
    let mut alias_type;
    let mut alias_name = String::new();
    let mut alias_values = Vec::new();
    match rule {
            Rule::User_Alias_Spec => {
                alias_type = AliasType::UserAlias;

            },
            Rule::Runas_Alias_Spec => {
                alias_type = AliasType::RunAsAlias;
            },
            Rule::Host_Alias_Spec => {
                alias_type = AliasType::HostAlias;
            },
            Rule::Cmnd_Alias_Spec => {
                alias_type = AliasType::CmndAlias;
            },
            _ => unreachable!(),
        }

    (alias_type, alias_name, alias_values)
}

fn parse_sudoers(contents: &str) -> Result<Vec<AstNode>, Error<Rule>> {
    let parse_result = 
    let mut ast = vec![];

    let pairs = SudoersParser::parse(Rule::sudoers, contents)?;
    for pair in pairs {
        match pair.as_rule() {
            Rule::expr => {
                ast.push(Print(Box::new(build_ast_from_expr(pair))));
            }
            _ => {}
        }
    }

    Ok(ast)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sudoers() {
        parse_sudoers("");
    }
}