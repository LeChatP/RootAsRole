#[derive(Parser)]
#[grammar = "../grammar/sudoers.pest"]
pub struct SudoersParser;

pub enum AstNode {
    Print(Box<AstNode>),
    Array(Vec<AstNode>),
    Alias {
        alias_type: AliasType,
        dict_vec: Vec<AstNode>,
    },
    Entry {
        alias_name: String,
        alias_values: Vec<AstNode>,
    },
    Host(String),
    User(String),
    Cmnd(String),
    Flag(String),
    Str(String),
    Bool(bool),
    Int(i64),
    Defaults {
        defaults_type: Box<AstNode>, // AstNode::DefaultsType
        defaults_params: Vec<AstNode>, // Vec<AstNode::Entry>
    },
    DefaultsType {
        default_type: DefaultsType,
        default_params: Vec<AstNode>, // Vec<AstNode::User|AstNode::Cmnd|AstNode::Host>
    },
    UserSpec {
        user_list: Vec<AstNode>, // Vec<AstNode::User>
        host_cmnd_list: Vec<AstNode>, // Vec<AstNode::HostCmndSpec>
    },
    HostCmndSpec {
        host_list: Vec<AstNode>, // Vec<AstNode::Host>
        cmnd_spec_list: Vec<AstNode>, // Vec<AstNode::Cmnd_Spec>
    },
    CmndSpec {
        runas_user_list: Vec<AstNode>, // Vec<AstNode::User>
        runas_group_list: Vec<AstNode>, // Vec<AstNode::User>
        tag_list: Vec<AstNode>, // Vec<AstNode::Flag>
        cmnd_list: Vec<AstNode>, // Vec<AstNode::Cmnd>
        optoin_list: Vec<AstNode>, // Vec<AstNode::OptionSpec> WIP
    },

}

pub enum AliasType {
    HostAlias,
    UserAlias,
    RunAsAlias,
    CmndAlias,
}

pub enum DefaultsType {
    DefaultsHost,
    DefaultsUser,
    DefaultsRunAs,
    DefaultsCmnd,
}