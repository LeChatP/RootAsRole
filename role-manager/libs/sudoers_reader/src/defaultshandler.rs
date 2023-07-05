use std::error::Error;

use pest::iterators::Pair;
use crate::grammar::{Rule,AstNode,DefaultsType, HostType};

pub struct DefaultHandler;

pub fn transform_defaults(r : Pair<Rule>) -> Result<AstNode, Box<dyn Error>> {
    let mut defaults_type = None;
    let mut defaults_params = vec![];
    for pair in r.into_inner() {
        match pair.as_rule() {
            Rule::Default_Type => {
                defaults_type = Some(Box::new(transform_defaults_type(pair)?));
            },
            _ => {
                return Ok(AstNode::Defaults { defaults_type, defaults_params });
            }
        }
    }
    return Ok(AstNode::Defaults { defaults_type, defaults_params });
}

fn transform_defaults_type(r: Pair<Rule>) -> Result<AstNode, Box<dyn Error>> {
    for pair in r.into_inner() {
        match pair.as_rule() {
            Rule::Host_List => {
                return Ok(AstNode::DefaultsType{ default_type: DefaultsType::DefaultsHost, default_params: transform_host_list(pair)? });
            },
            _ => {
                println!("Unexpected rule: {:?}", pair.as_rule());
                return Err("Unexpected rule".into());
            }
        }
    }
    return Err("No inner rules".into());
}

fn transform_host_list(r: Pair<Rule>) -> Result<Vec<AstNode>, Box<dyn Error>> {
    let mut host_list = vec![];
    for pair in r.into_inner() {
        match pair.as_rule() {
            Rule::Host => {
                host_list.push(transform_host(pair)?);
            },
            Rule::Host_List => {
                host_list.extend(transform_host_list(pair)?);
            },
            _ => {
                println!("Unexpected rule: {:?}", pair.as_rule());
                return Err("Unexpected rule".into());
            }
        }
    }
    Ok(host_list)
}

fn transform_host(r: Pair<Rule>) -> Result<AstNode, Box<dyn Error>> {
    let not = false;
    for pair in r.into_inner() {
        match pair.as_rule() {
            Rule::Negate => {
                not != not;
            },
            Rule::Domain_Name => {
                return Ok(AstNode::Host{not, hostaddr:AstNode::Str(pair.as_str().to_owned()), domain: None, user : None});
            },
            Rule::ip_addr => {
                return Ok(AstNode::Host{not, hostaddr:AstNode::Str(pair.as_str().to_owned()), domain: None, user : None});
            },
            Rule::netgroup => {
                return transform_netgroup(pair, not);
            },
            _ => {
                println!("Unexpected rule: {:?}", pair.as_rule());
                return Err("Unexpected rule".into());
            }
        }
    }
    return Err("No inner rules".into());
}

fn transform_netgroup(r: Pair<Rule>, not : bool) -> Result<AstNode, Box<dyn Error>> {
    let hostaddr = None;
    let domain = None;
    let user = None;
    for pair in r.into_inner() {
        match pair.as_rule() {
            Rule::netgroup_host => {
                hostaddr = Some(pair.as_str().to_owned());
            },
            Rule::netgroup_domain => {
                domain = Some(pair.as_str().to_owned());
            },
            Rule::netgroup_user => {
                user = Some(pair.as_str().to_owned());
            },
            _ => {
                println!("Unexpected rule: {:?}", pair.as_rule());
                return Err("Unexpected rule".into());
            }
        }
    }
    return Ok(AstNode::Host{not, hostaddr, domain, user});
}