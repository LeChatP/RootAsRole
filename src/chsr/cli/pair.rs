use std::{collections::HashMap, error::Error, num::NonZeroU8, str::FromStr};

use capctl::Cap;
use indexmap::IndexSet;
use jiff::SignedDuration;
use log::{debug, warn};
use pest::iterators::Pair;

use crate::cli::data::{Convertion, RoleType, TaskType};
use rootasrole_core::{
    database::{
        actor::{SActor, SGroupType},
        command::{regex_arguments, split_command},
        options::{
            EnvBehavior, EnvKey, OptType, PathBehavior, SUMask, TimestampType, WorkdirBehavior,
        },
        structs::{GroupsFrom, IdTask, SetBehavior},
    },
    util::{StorageMethod, is_valid_env_name},
};

use super::data::{
    EnvOverride, InputAction, Inputs, PasswordOpt, RoleLink, Rule, SetListType, TimeoutOpt,
};

type MatchingFunction = dyn Fn(&Pair<Rule>, &mut Inputs) -> Result<(), Box<dyn Error>>;

/// The command line to write in the policy for the command that the user typed.
///
/// A regular expression on the arguments is kept as typed: dosr reads it as written, and shell
/// splitting would quote each of its words, so that it never matches. Any other command is
/// normalized as a shell splits it.
///
/// # Errors
/// When the command has an unterminated quote.
pub fn policy_command_line(typed: &str) -> Result<String, shell_words::ParseError> {
    if let Some((path, args)) = split_command(typed)
        && let Some(regex) = regex_arguments(args)
    {
        return Ok(format!("{path} {regex}"));
    }
    Ok(shell_words::join(shell_words::split(typed)?))
}

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

/// The actor names under `pair`, at any depth: a combination of groups nests them.
fn actor_names(pair: &Pair<Rule>) -> Vec<String> {
    pair.clone()
        .into_inner()
        .flat_map(|inner| {
            if inner.as_rule() == Rule::actor_name {
                vec![inner.as_str().to_string()]
            } else {
                actor_names(&inner)
            }
        })
        .collect()
}

/// A duration written `ss`, `mm:ss` or `hh:mm:ss`: a field that does not fit, or a duration
/// that does not, is an error, never 0 nor a panic.
fn parse_time(time: &str) -> Result<SignedDuration, Box<dyn Error>> {
    let mut seconds: i64 = 0;
    for field in time.split(':') {
        let value: i64 = field
            .parse()
            .map_err(|_| format!("Invalid duration: {time}"))?;
        seconds = seconds
            .checked_mul(60)
            .and_then(|seconds| seconds.checked_add(value))
            .ok_or_else(|| format!("Duration too long: {time}"))?;
    }
    Ok(SignedDuration::from_secs(seconds))
}

#[allow(clippy::too_many_lines)]
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
        Rule::convert => {
            inputs.action = InputAction::Convert;
        }
        Rule::to => {
            let mut inner = pair.clone().into_inner();
            let temp_convertion = Convertion::default();
            let convertion = inputs.convertion.get_or_insert(temp_convertion);
            convertion.to_type = inner
                .next()
                .ok_or("No type specified for convertion")?
                .as_str()
                .to_lowercase()
                .parse()
                .inspect_err(|e| {
                    warn!(
                        "Unknown type {}, types available : {}",
                        e,
                        StorageMethod::VARIANTS.join(", ")
                    );
                })?;
            convertion.to = inner.next().ok_or("to_value not found")?.as_str().into();
        }
        Rule::from => {
            let mut inner = pair.clone().into_inner();
            let temp_convertion = Convertion::default();
            let convertion = inputs.convertion.get_or_insert(temp_convertion);
            convertion.from_type = Some(
                inner
                    .next()
                    .ok_or("a type is needed")?
                    .as_str()
                    .to_lowercase()
                    .parse()
                    .inspect_err(|e| {
                        warn!(
                            "Unknown type {}, types available : {}",
                            e,
                            StorageMethod::VARIANTS.join(", ")
                        );
                    })?,
            );
            convertion.from = Some(inner.next().ok_or("--from needs a path")?.as_str().into());
        }
        Rule::convert_reconfigure => {
            inputs.convert_reconfigure = true;
        }
        Rule::upgrade => {
            inputs.action = InputAction::Upgrade;
        }
        Rule::upgrade_check => {
            inputs.upgrade_check = true;
        }
        // === setpolicies ===
        Rule::cmd_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "deny-all" {
                inputs.cmd_policy = Some(SetBehavior::None);
            } else if pair.as_str() == "allow-all" {
                inputs.cmd_policy = Some(SetBehavior::All);
            } else {
                return Err(format!("Unknown cmd policy: {}", pair.as_str()).into());
            }
        }
        Rule::caps_policy => {
            inputs.action = InputAction::Set;
            if pair.as_str() == "deny-all" {
                inputs.cred_policy = Some(SetBehavior::None);
            } else if pair.as_str() == "allow-all" {
                inputs.cred_policy = Some(SetBehavior::All);
            } else {
                return Err(format!("Unknown caps policy: {}", pair.as_str()).into());
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
                return Err(format!("Unknown path policy: {}", pair.as_str()).into());
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
                return Err(format!("Unknown env policy: {}", pair.as_str()).into());
            }
        }
        Rule::workdir_policy => {
            inputs.action = InputAction::Set;
            inputs.options_workdir_policy = Some(WorkdirBehavior::const_parse(pair.as_str()));
        }
        // === timeout ===
        Rule::time => {
            inputs.timeout_duration = Some(parse_time(pair.as_str())?);
        }
        Rule::opt_timeout_type => {
            if pair.as_str() == "tty" {
                inputs.timeout_type = Some(TimestampType::TTY);
            } else if pair.as_str() == "ppid" {
                inputs.timeout_type = Some(TimestampType::PPID);
            } else if pair.as_str() == "uid" {
                inputs.timeout_type = Some(TimestampType::UID);
            } else {
                return Err(format!("Unknown timeout type: {}", pair.as_str()).into());
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
            inputs.timeout_max_usage = Some(pair.as_str().parse::<u64>()?);
        }
        Rule::opt_password_t_arg => {
            let mut password_arg = inputs.password_arg.unwrap_or_default();
            password_arg[PasswordOpt::Tries as usize] = true;
            inputs.password_arg.replace(password_arg);
        }
        Rule::opt_password_d_arg => {
            let mut password_arg = inputs.password_arg.unwrap_or_default();
            password_arg[PasswordOpt::Delay as usize] = true;
            inputs.password_arg.replace(password_arg);
        }
        Rule::opt_password_tries => {
            let tries = pair
                .as_str()
                .parse::<u8>()
                .ok()
                .and_then(NonZeroU8::new)
                .ok_or_else(|| format!("The tries must be 1 to 255: {}", pair.as_str()))?;
            inputs.password_tries = Some(tries);
        }
        Rule::opt_password_delay => {
            inputs.password_delay = Some(parse_time(pair.as_str())?);
        }
        // === file ===
        Rule::file => {
            inputs.policy = true;
        }
        Rule::policy_path => {
            inputs.policy_path = Some(pair.as_str().to_string());
        }
        // === roles ===
        Rule::role_id => {
            inputs.role_id = Some(pair.as_str().to_string());
        }
        Rule::role_link_kind => {
            inputs.role_link = Some(if pair.as_str() == "ssd" {
                RoleLink::Ssd
            } else {
                RoleLink::Parents
            });
        }
        Rule::linked_role => {
            inputs
                .role_links
                .get_or_insert_default()
                .push(pair.as_str().to_string());
        }
        Rule::purpose_keyword => {
            inputs.purpose = true;
        }
        Rule::purpose_text => {
            // the words of the purpose, unquoted like the arguments of a command
            inputs.task_purpose = Some(shell_words::split(pair.as_str())?.join(" "));
        }
        Rule::cmd_hash => {
            let mut inner = pair.clone().into_inner();
            let kind = inner
                .next()
                .ok_or("a hash type is needed")?
                .as_str()
                .trim_start_matches('-')
                .to_string();
            let hash = inner
                .next()
                .ok_or("a hash is needed")?
                .as_str()
                .to_ascii_lowercase();
            let length = match kind.as_str() {
                "sha224" => 56,
                "sha256" => 64,
                "sha384" => 96,
                "sha512" => 128,
                other => return Err(format!("Unknown hash type: {other}").into()),
            };
            if !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("A {kind} hash is hexadecimal: {hash}").into());
            }
            if hash.len() != length {
                return Err(format!(
                    "A {kind} hash has {length} hexadecimal digits, this one has {}",
                    hash.len()
                )
                .into());
            }
            inputs.cmd_checks.hash = Some((kind, hash));
        }
        Rule::cmd_check_flag => {
            if pair.as_str() == "--read-only" {
                inputs.cmd_checks.read_only = true;
            } else {
                inputs.cmd_checks.immutable = true;
            }
        }
        Rule::opt_env_override => {
            // unset, unless a value follows
            inputs.options_env_override = Some(EnvOverride::Unset);
        }
        Rule::env_override_value => {
            inputs.action = InputAction::Set;
            inputs.options_env_override = Some(if pair.as_str() == "allow" {
                EnvOverride::Allow
            } else {
                EnvOverride::Deny
            });
        }
        Rule::role_type_arg => {
            if pair.as_str() == "all" {
                inputs.role_type = Some(RoleType::All);
            } else if pair.as_str() == "actors" {
                inputs.role_type = Some(RoleType::Actors);
            } else if pair.as_str() == "tasks" {
                inputs.role_type = Some(RoleType::Tasks);
            } else {
                return Err(format!("Unknown role type: {}", pair.as_str()).into());
            }
        }
        // === actors ===
        Rule::user => {
            for pair in pair.clone().into_inner() {
                debug!("user {:?}", pair.as_str());
                inputs
                    .actors
                    .get_or_insert_default()
                    .push(SActor::user(pair.as_str()).build());
            }
        }

        Rule::group => {
            fn inner_recurse(pair: &Pair<Rule>, vec: &mut Vec<String>) {
                for pair in pair.clone().into_inner() {
                    if pair.as_rule() == Rule::actor_name {
                        vec.push(pair.as_str().into());
                    }
                    inner_recurse(&pair, vec);
                }
            }
            let mut vec: Vec<String> = Vec::new();
            for pair in pair.clone().into_inner() {
                inner_recurse(&pair, &mut vec);
            }
            if vec.is_empty() {
                warn!("No group specified");
            } else if vec.len() == 1 {
                inputs
                    .actors
                    .get_or_insert_default()
                    .push(SActor::group(vec[0].as_str()).build());
            } else {
                inputs.actors.get_or_insert_default().push(
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
                return Err(format!("Unknown task type: {}", pair.as_str()).into());
            }
        }
        // === commands ===
        Rule::cmd => {
            inputs.cmd_id = Some(policy_command_line(pair.as_str())?);
        }
        // === credentials ===
        Rule::capability => {
            if let Ok(cap) = Cap::from_str(pair.as_str()) {
                inputs.cred_caps.get_or_insert_default().add(cap);
            } else {
                warn!("Unknown capability: {}", pair.as_str());
            }
        }
        Rule::cred_u => {
            let user = actor_names(pair)
                .into_iter()
                .next()
                .ok_or("--setuid needs a user")?;
            inputs.cred_setuid = Some(user.as_str().into());
        }
        Rule::groups_from => {
            inputs.cred_groups_from = Some(if pair.as_str() == "caller" {
                GroupsFrom::Caller
            } else {
                GroupsFrom::Target
            });
        }
        Rule::cred_g => {
            let groups: Vec<SGroupType> = actor_names(pair)
                .iter()
                .map(|name| name.as_str().into())
                .collect();
            if groups.is_empty() {
                return Err("--setgid needs a group".into());
            }
            inputs.cred_setgid = Some(groups.into());
        }
        // === options ===
        Rule::options_operations => {
            inputs.options = true;
        }
        Rule::opt_env => {
            inputs.options_type = Some(OptType::Env);
        }
        Rule::opt_env_listing => {
            inputs.options_key_env = Some(IndexSet::new());
        }
        Rule::opt_env_setlisting => {
            inputs.setlist_type = Some(SetListType::Set);
            inputs.options_env_values = Some(HashMap::new());
            inputs.options_key_env = Some(IndexSet::new());
        }
        Rule::opt_env_keep => {
            inputs.action = InputAction::Set;
            inputs.options_env_policy = Some(EnvBehavior::Delete);
            inputs.options_key_env = Some(IndexSet::new());
        }
        Rule::opt_env_delete => {
            inputs.action = InputAction::Set;
            inputs.options_env_policy = Some(EnvBehavior::Keep);
            inputs.options_key_env = Some(IndexSet::new());
        }
        Rule::opt_env_set => {
            inputs.action = InputAction::Set;
            inputs.setlist_type = Some(SetListType::Set);
            inputs.options_env_values = Some(HashMap::new());
        }

        Rule::opt_path => {
            inputs.options_type = Some(OptType::Path);
        }
        Rule::opt_workdir => {
            inputs.options_type = Some(OptType::Workdir);
        }
        Rule::opt_show_arg => {
            inputs.options_type = match pair.as_str() {
                "all" => None,
                "path" => Some(OptType::Path),
                "env" => Some(OptType::Env),
                "root" => Some(OptType::Root),
                "bounding" => Some(OptType::Bounding),
                "timeout" => Some(OptType::Timeout),
                "password" => Some(OptType::Password),
                "authentication" | "auth" => Some(OptType::Authentication),
                "execinfo" | "info" => Some(OptType::ExecInfo),
                "umask" | "mask" => Some(OptType::UMask),
                "workdir" => Some(OptType::Workdir),
                other => return Err(format!("Unknown option: {other}").into()),
            };
        }
        Rule::path => {
            inputs.options_path = Some(pair.as_str().to_string());
        }
        Rule::env_key_value => {
            if let Some(options_env_values) = inputs.options_env_values.as_mut() {
                let mut inner = pair.clone().into_inner();
                let key = inner
                    .next()
                    .expect("env_key_value parsing must have a key, implementation error")
                    .as_str()
                    .to_string();
                let value = inner
                    .next()
                    .expect("env_key_value parsing must have a value, implementation error")
                    .into_inner()
                    .next()
                    .expect("env_key_value parsing must have a value, implementation error")
                    .as_str()
                    .to_string();
                debug!("env_key_value: {key}={value}");
                // the set list gives a value to a variable: a name, never a pattern
                if !is_valid_env_name(&key) {
                    return Err(
                        format!("{key} is not a variable name, `*` is not allowed here").into(),
                    );
                }
                options_env_values.insert(key, value);
            }
        }
        Rule::env_key => {
            if let Some(options_env) = inputs.options_key_env.as_mut() {
                options_env.insert(EnvKey::new(pair.as_str().to_string())?);
            }
        }
        Rule::opt_root_args => {
            inputs.action = InputAction::Set; // If del it will be overwritten by the parse loop
            inputs.options_root = Some(pair.as_str().parse().unwrap_or_default());
        }
        Rule::opt_bounding_args => {
            inputs.action = InputAction::Set; // If del it will be overwritten by the parse loop
            inputs.options_bounding = Some(pair.as_str().parse().unwrap_or_default());
        }
        Rule::opt_skip_auth_args => {
            inputs.action = InputAction::Set; // If del it will be overwritten by the parse loop
            inputs.options_auth = Some(pair.as_str().parse().unwrap_or_default());
        }
        Rule::opt_execinfo_args => {
            inputs.action = InputAction::Set; // If del it will be overwritten by the parse loop
            inputs.options_execinfo = Some(pair.as_str().parse().unwrap_or_default());
        }
        Rule::opt_mask_args => {
            inputs.action = InputAction::Set; // If del it will be overwritten by the parse loop
            let value = pair.as_str();
            inputs.options_umask = Some(if value.bytes().all(|b| b.is_ascii_digit()) {
                u16::from_str_radix(value, 8)
                    .ok()
                    .filter(|umask| *umask <= 0o777)
                    .map(SUMask)
                    .ok_or_else(|| format!("The umask is octal, 000 to 777: {value}"))?
            } else {
                // del: the value is not used
                SUMask::default()
            });
        }
        Rule::all => {
            if inputs.role_id.is_some() && inputs.task_id.is_none() {
                inputs.role_type = Some(RoleType::All);
            } else if inputs.task_id.is_some() {
                inputs.task_type = Some(TaskType::All);
            }
        }
        Rule::editor => {
            debug!("Editor mode enabled");
            inputs.editor = true;
        }
        Rule::editor_type => {
            let mut inner = pair.clone().into_inner();
            inputs.editor_type = Some(
                inner
                    .next()
                    .ok_or("a type is needed")?
                    .as_str()
                    .to_lowercase()
                    .parse()
                    .inspect_err(|e| {
                        warn!(
                            "Unknown type {}, types available : {}",
                            e,
                            StorageMethod::VARIANTS.join(", ")
                        );
                    })?,
            );
        }
        Rule::editor_path => {
            inputs.editor_path = Some(pair.as_str().into());
        }
        _ => {
            debug!("Unmatched rule: {:?}", pair.as_rule());
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{
        cli::{
            data::{Cli, RoleType},
            pair::{InputAction, Rule, recurse_pair},
        },
        util::underline,
    };
    use pest::Parser;

    use rootasrole_core::{
        database::actor::SActor,
        util::{BOLD, RED, RST},
    };

    use super::{Inputs, parse_time};
    use jiff::SignedDuration;

    fn make_args(args: &str) -> String {
        shell_words::join(shell_words::split(args).expect("Failed to split args"))
    }

    fn get_inputs(args: &str) -> Inputs {
        let binding = make_args(args);
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
    fn test_parse_time() {
        assert_eq!(parse_time("5").unwrap(), SignedDuration::from_secs(5));
        assert_eq!(parse_time("5:00").unwrap(), SignedDuration::from_secs(300));
        assert_eq!(
            parse_time("01:02:03").unwrap(),
            SignedDuration::from_secs(3723)
        );
        // too long: an error, never 0 nor a panic
        assert!(parse_time("99999999999999999999").is_err());
        assert!(parse_time("153722867280912930:59:59").is_err());
    }

    #[test]
    fn test_timeout_duration_too_long_is_an_error() {
        let binding = make_args("o timeout set --duration 153722867280912930:59:59");
        let pairs = Cli::parse(Rule::cli, &binding).unwrap();
        let mut inputs = Inputs::default();
        assert!(
            pairs
                .into_iter()
                .try_for_each(|pair| recurse_pair(pair, &mut inputs))
                .is_err()
        );
        assert_eq!(inputs.timeout_duration, None);
    }

    #[test]
    fn test_list_role_all() {
        let inputs = get_inputs("r r1 l all");
        assert_eq!(inputs.action, InputAction::List);
        assert_eq!(inputs.role_id, Some("r1".to_string()));
        assert_eq!(inputs.role_type, Some(RoleType::All));
    }
}
