use std::{collections::HashMap, error::Error, str::FromStr};

use capctl::{Cap, CapSet};
use chrono::Duration;
use linked_hash_set::LinkedHashSet;
use log::{debug, warn};
use pest::iterators::Pair;

use crate::cli::data::{RoleType, TaskType};
use rar_common::database::{
    actor::{SActor, SGroupType},
    options::{
        EnvBehavior, OptType, PathBehavior, SAuthentication, SBounding, SPrivileged, TimestampType,
    },
    structs::{IdTask, SetBehavior},
};

use super::data::*;

type MatchingFunction = dyn Fn(&Pair<Rule>, &mut Inputs) -> Result<(), Box<dyn Error>>;

fn recurse_pair_with_action(
    pair: Pair<Rule>,
    inputs: &mut Inputs,
    do_matching: &MatchingFunction,
) -> Result<(), Box<dyn Error>> {
    for inner_pair in pair.into_inner() {
        do_matching(&inner_pair, inputs)?;
        recurse_pair(inner_pair, inputs)?;
    }
    Ok(())
}

pub fn recurse_pair(pair: Pair<Rule>, inputs: &mut Inputs) -> Result<(), Box<dyn Error>> {
    recurse_pair_with_action(pair, inputs, &match_pair)
}

fn match_pair(pair: &Pair<Rule>, inputs: &mut Inputs) -> Result<(), Box<dyn Error>> {
    match pair.as_rule() {
        Rule::help => {
            inputs.action = InputAction::Help;
        }
        Rule::list => {
            inputs.action = InputAction::List;
        }
        Rule::set => {
            inputs.action = InputAction::Set;
        }
        Rule::add | Rule::grant => {
            inputs.action = InputAction::Add;
        }
        Rule::del | Rule::revoke => {
            inputs.action = InputAction::Del;
        }
        Rule::purge => {
            inputs.action = InputAction::Purge;
        }
        Rule::whitelist => {
            inputs.setlist_type = Some(SetListType::White);
        }
        Rule::blacklist => {
            inputs.setlist_type = Some(SetListType::Black);
        }
        Rule::checklist => {
            inputs.setlist_type = Some(SetListType::Check);
        }
        Rule::setlist => {
            inputs.setlist_type = Some(SetListType::Set);
        }
        // === setpolicies ===
        Rule::cmd_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "deny-all" {
                inputs.cmd_policy = Some(SetBehavior::None);
            } else if pair.as_str() == "allow-all" {
                inputs.cmd_policy = Some(SetBehavior::All);
            } else {
                unreachable!("Unknown cmd policy: {}", pair.as_str())
            }
        }
        Rule::caps_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "deny-all" {
                inputs.cred_policy = Some(SetBehavior::None);
            } else if pair.as_str() == "allow-all" {
                inputs.cred_policy = Some(SetBehavior::All);
            } else {
                unreachable!("Unknown caps policy: {}", pair.as_str())
            }
        }
        Rule::path_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "delete-all" {
                inputs.options_path_policy = Some(PathBehavior::Delete);
            } else if pair.as_str() == "keep-safe" {
                inputs.options_path_policy = Some(PathBehavior::KeepSafe);
            } else if pair.as_str() == "keep-unsafe" {
                inputs.options_path_policy = Some(PathBehavior::KeepUnsafe);
            } else if pair.as_str() == "inherit" {
                inputs.options_path_policy = Some(PathBehavior::Inherit);
            } else {
                unreachable!("Unknown path policy: {}", pair.as_str())
            }
        }
        Rule::env_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "delete-all" {
                inputs.options_env_policy = Some(EnvBehavior::Delete);
            } else if pair.as_str() == "keep-all" {
                inputs.options_env_policy = Some(EnvBehavior::Keep);
            } else if pair.as_str() == "inherit" {
                inputs.options_env_policy = Some(EnvBehavior::Inherit);
            } else {
                unreachable!("Unknown env policy: {}", pair.as_str())
            }
        }
        // === timeout ===
        Rule::time => {
            let mut reversed = pair.as_str().split(':').rev();
            let mut duration: Duration =
                Duration::try_seconds(reversed.next().unwrap().parse::<i64>().unwrap_or(0))
                    .unwrap_or_default();
            if let Some(mins) = reversed.next() {
                duration = duration
                    .checked_add(
                        &Duration::try_minutes(mins.parse::<i64>().unwrap_or(0))
                            .unwrap_or_default(),
                    )
                    .expect("Invalid minutes");
                if let Some(hours) = reversed.next() {
                    duration = duration
                        .checked_add(
                            &Duration::try_hours(hours.parse::<i64>().unwrap_or(0))
                                .unwrap_or_default(),
                        )
                        .expect("Invalid hours");
                }
            }
            inputs.timeout_duration = Some(duration);
        }
        Rule::opt_timeout_type => {
            if pair.as_str() == "tty" {
                inputs.timeout_type = Some(TimestampType::TTY);
            } else if pair.as_str() == "ppid" {
                inputs.timeout_type = Some(TimestampType::PPID);
            } else if pair.as_str() == "uid" {
                inputs.timeout_type = Some(TimestampType::UID);
            } else {
                unreachable!("Unknown timeout type: {}", pair.as_str())
            }
        }
        Rule::opt_timeout_t_arg => {
            let mut timeout_arg = inputs.timeout_arg.unwrap_or_default();
            timeout_arg[TimeoutOpt::Type as usize] = true;
            inputs.timeout_arg.replace(timeout_arg);
        }
        Rule::opt_timeout_d_arg => {
            let mut timeout_arg = inputs.timeout_arg.unwrap_or_default();
            timeout_arg[TimeoutOpt::Duration as usize] = true;
            inputs.timeout_arg.replace(timeout_arg);
        }
        Rule::opt_timeout_m_arg => {
            let mut timeout_arg = inputs.timeout_arg.unwrap_or_default();
            timeout_arg[TimeoutOpt::MaxUsage as usize] = true;
            inputs.timeout_arg.replace(timeout_arg);
        }
        Rule::opt_timeout_max_usage => {
            inputs.timeout_max_usage = Some(pair.as_str().parse::<u64>().unwrap());
        }
        // === roles ===
        Rule::role_id => {
            inputs.role_id = Some(pair.as_str().to_string());
        }
        Rule::role_type_arg => {
            if pair.as_str() == "all" {
                inputs.role_type = Some(RoleType::All);
            } else if pair.as_str() == "actors" {
                inputs.role_type = Some(RoleType::Actors);
            } else if pair.as_str() == "tasks" {
                inputs.role_type = Some(RoleType::Tasks);
            } else {
                unreachable!("Unknown role type: {}", pair.as_str())
            }
        }
        // === actors ===
        Rule::user => {
            if inputs.actors.is_none() {
                inputs.actors = Some(Vec::new());
            }
            for pair in pair.clone().into_inner() {
                debug!("user {:?}", pair.as_str());
                inputs
                    .actors
                    .as_mut()
                    .unwrap()
                    .push(SActor::user(pair.as_str()).build());
            }
        }
        Rule::group => {
            if inputs.actors.is_none() {
                inputs.actors = Some(Vec::new());
            }
            let mut vec: Vec<String> = Vec::new();
            fn inner_recurse(pair: Pair<Rule>, vec: &mut Vec<String>) {
                for pair in pair.clone().into_inner() {
                    if pair.as_rule() == Rule::actor_name {
                        vec.push(pair.as_str().into());
                    }
                    inner_recurse(pair, vec);
                }
            }
            for pair in pair.clone().into_inner() {
                inner_recurse(pair.clone(), &mut vec);
            }
            if vec.is_empty() {
                warn!("No group specified");
            } else if vec.len() == 1 {
                if inputs.actors.is_none() {
                    inputs.actors = Some(Vec::new());
                }
                inputs
                    .actors
                    .as_mut()
                    .unwrap()
                    .push(SActor::group(vec[0].as_str()).build());
            } else {
                inputs.actors.as_mut().unwrap().push(
                    SActor::group(
                        vec.iter()
                            .map(|s| SGroupType::from(s.as_str()))
                            .collect::<Vec<_>>(),
                    )
                    .build(),
                );
            }
            debug!("actors: {:?}", inputs.actors);
        }
        // === tasks ===
        Rule::task_id => {
            inputs.task_id = Some(IdTask::Name(pair.as_str().to_string()));
        }
        Rule::task_type_arg => {
            if pair.as_str() == "all" {
                inputs.task_type = Some(TaskType::All);
            } else if pair.as_str() == "commands" || pair.as_str() == "cmd" {
                inputs.task_type = Some(TaskType::Commands);
            } else if pair.as_str().starts_with("cred") {
                inputs.task_type = Some(TaskType::Credentials);
            } else {
                unreachable!("Unknown task type: {}", pair.as_str());
            }
        }
        // === commands ===
        Rule::cmd => {
            inputs.cmd_id = Some(shell_words::split(pair.as_str())?);
        }
        // === credentials ===
        Rule::capability => {
            if inputs.cred_caps.is_none() {
                let caps = CapSet::empty();
                inputs.cred_caps = Some(caps);
            }
            if let Ok(cap) = Cap::from_str(pair.as_str()) {
                inputs.cred_caps.as_mut().unwrap().add(cap);
            } else {
                warn!("Unknown capability: {}", pair.as_str())
            }
        }
        Rule::cred_u => {
            inputs.cred_setuid = Some(
                pair.as_str()
                    .chars()
                    .skip(9)
                    .collect::<String>()
                    .as_str()
                    .into(),
            );
        }
        Rule::cred_g => {
            let mut vec: Vec<SGroupType> = Vec::new();
            for pair in pair.clone().into_inner() {
                if pair.as_rule() == Rule::actor_name {
                    vec.push(pair.as_str().into());
                }
            }
            if vec.is_empty() {
                warn!("No group specified");
            }
            inputs.cred_setgid = Some(vec.into());
        }
        // === options ===
        Rule::options_operations => {
            inputs.options = true;
        }
        Rule::opt_env => {
            inputs.options_type = Some(OptType::Env);
        }
        Rule::opt_env_listing => {
            inputs.options_key_env = Some(LinkedHashSet::new());
        }
        Rule::opt_env_setlisting => {
            inputs.setlist_type = Some(SetListType::Set);
            inputs.options_env_values = Some(HashMap::new());
            inputs.options_key_env = Some(LinkedHashSet::new());
        }
        Rule::opt_env_keep => {
            inputs.action = InputAction::Set;
            inputs.options_env_policy = Some(EnvBehavior::Delete);
            inputs.options_key_env = Some(LinkedHashSet::new());
        }
        Rule::opt_env_delete => {
            inputs.action = InputAction::Set;
            inputs.options_env_policy = Some(EnvBehavior::Keep);
            inputs.options_key_env = Some(LinkedHashSet::new());
        }
        Rule::opt_env_set => {
            inputs.action = InputAction::Set;
            inputs.setlist_type = Some(SetListType::Set);
            inputs.options_env_values = Some(HashMap::new());
        }

        Rule::opt_path => {
            inputs.options_type = Some(OptType::Path);
        }
        Rule::opt_show_arg => {
            if pair.as_str() == "all" {
                inputs.options_type = None;
            } else if pair.as_str() == "path" {
                inputs.options_type = Some(OptType::Path);
            } else if pair.as_str() == "env" {
                inputs.options_type = Some(OptType::Env);
            } else if pair.as_str() == "root" {
                inputs.options_type = Some(OptType::Root);
            } else if pair.as_str() == "bounding" {
                inputs.options_type = Some(OptType::Bounding);
            } else if pair.as_str() == "wildcard-denied" {
                inputs.options_type = Some(OptType::Wildcard);
            } else if pair.as_str() == "timeout" {
                inputs.options_type = Some(OptType::Timeout);
            } else {
                unreachable!("Unknown option type: {}", pair.as_str())
            }
        }
        Rule::path => {
            inputs.options_path = Some(pair.as_str().to_string());
        }
        Rule::env_key_value => {
            if let Some(options_env_values) = inputs.options_env_values.as_mut() {
                let mut inner = pair.clone().into_inner();
                let key = inner.next().unwrap().as_str().to_string();
                let value = inner
                    .next()
                    .unwrap()
                    .into_inner()
                    .next()
                    .unwrap()
                    .as_str()
                    .to_string();
                debug!("env_key_value: {}={}", key, value);
                options_env_values.insert(key, value);
            }
        }
        Rule::env_key => {
            if let Some(options_env) = inputs.options_key_env.as_mut() {
                options_env.insert_if_absent(pair.as_str().into());
            }
        }
        Rule::opt_root_args => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "privileged" {
                inputs.options_root = Some(SPrivileged::Privileged);
            } else if pair.as_str() == "user" {
                inputs.options_root = Some(SPrivileged::User);
            } else if pair.as_str() == "inherit" {
                inputs.options_root = Some(SPrivileged::Inherit);
            } else {
                unreachable!("Unknown root type: {}", pair.as_str());
            }
        }
        Rule::opt_bounding_args => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "strict" {
                inputs.options_bounding = Some(SBounding::Strict);
            } else if pair.as_str() == "ignore" {
                inputs.options_bounding = Some(SBounding::Ignore);
            } else if pair.as_str() == "inherit" {
                inputs.options_bounding = Some(SBounding::Inherit);
            } else {
                unreachable!("Unknown bounding type: {}", pair.as_str());
            }
        }
        Rule::opt_skip_auth_args => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "skip" {
                inputs.options_auth = Some(SAuthentication::Skip);
            } else if pair.as_str() == "perform" {
                inputs.options_auth = Some(SAuthentication::Perform);
            } else if pair.as_str() == "inherit" {
                inputs.options_auth = Some(SAuthentication::Inherit);
            } else {
                unreachable!("Unknown authentication type: {}", pair.as_str());
            }
        }
        Rule::wildcard_value => {
            inputs.options_wildcard = Some(pair.as_str().to_string());
        }
        Rule::all => {
            if inputs.role_id.is_some() && inputs.task_id.is_none() {
                inputs.role_type = Some(RoleType::All);
            } else if inputs.task_id.is_some() {
                inputs.task_type = Some(TaskType::All);
            }
        }
        _ => {
            debug!("Unmatched rule: {:?}", pair.as_rule());
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use pest::Parser;

    use crate::{
        cli::{
            data::RoleType,
            pair::{recurse_pair, Cli, InputAction, Rule},
        },
        util::underline,
    };

    use rar_common::{
        database::actor::SActor,
        util::{BOLD, RED, RST},
    };

    use super::Inputs;

    fn make_args(args: &str) -> String {
        shell_words::join(shell_words::split(args).unwrap())
    }

    fn get_inputs(args: &str) -> Inputs {
        let binding = make_args(args);
        println!("{}", binding);
        let args = Cli::parse(Rule::cli, &binding);
        let args = match args {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{RED}{BOLD}Unrecognized command line:\n| {RST}{}{RED}{BOLD}\n| {}\n= {}{RST}",
                    e.line(),
                    underline(&e),
                    e.variant.message(),
                    RED = RED,
                    BOLD = BOLD,
                    RST = RST
                );
                panic!("Error parsing args");
            }
        };
        let mut inputs = Inputs::default();
        for pair in args {
            assert!(recurse_pair(pair, &mut inputs).is_ok());
        }
        inputs
    }

    #[test]
    fn test_grant() {
        let inputs = get_inputs("role r1 grant -u u1 -u u2 -g g1,g2");
        assert_eq!(inputs.role_id, Some("r1".to_string()));
        assert_eq!(inputs.action, InputAction::Add);
        assert_eq!(
            inputs.actors,
            Some(vec![
                SActor::user("u1").build(),
                SActor::user("u2").build(),
                SActor::group(["g1", "g2"]).build()
            ])
        );
    }

    #[test]
    fn test_list_roles() {
        let inputs = get_inputs("list");
        assert_eq!(inputs.action, InputAction::List);
    }

    #[test]
    fn test_list_role() {
        let inputs = get_inputs("role r1 show");
        assert_eq!(inputs.action, InputAction::List);
        assert_eq!(inputs.role_id, Some("r1".to_string()));
    }

    #[test]
    fn test_list_role_actors() {
        let inputs = get_inputs("r r1 l actors");
        assert_eq!(inputs.action, InputAction::List);
        assert_eq!(inputs.role_id, Some("r1".to_string()));
        assert_eq!(inputs.role_type, Some(RoleType::Actors));
    }

    #[test]
    fn test_list_role_tasks() {
        let inputs = get_inputs("r r1 l tasks");
        assert_eq!(inputs.action, InputAction::List);
        assert_eq!(inputs.role_id, Some("r1".to_string()));
        assert_eq!(inputs.role_type, Some(RoleType::Tasks));
    }

    #[test]
    fn test_list_role_all() {
        let inputs = get_inputs("r r1 l all");
        assert_eq!(inputs.action, InputAction::List);
        assert_eq!(inputs.role_id, Some("r1".to_string()));
        assert_eq!(inputs.role_type, Some(RoleType::All));
    }
}
