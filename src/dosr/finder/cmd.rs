use log::{debug, info, warn};
use rootasrole_core::{
    database::score::{CmdMin, CmdOrder},
    util::{all_paths_from_env, match_single_path},
};
use std::path::{Path, PathBuf};

/// Path of the command to run when a task allows every command, or for the `**` pattern.
/// A name without `/` is only searched in PATH, never in the current directory (like a shell),
/// otherwise a file named like the command in the current directory would be run instead.
/// A path is made absolute without resolving symbolic links: multi-call binaries
/// (e.g. `pkill` -> `pgrep`) rely on the name they are run with.
pub(super) fn resolve_any_command(cmd_path: &Path, env_path: &[&str]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    if cmd_path.as_os_str().as_bytes().contains(&b'/') {
        std::path::absolute(cmd_path).ok()
    } else {
        all_paths_from_env(env_path, cmd_path).into_iter().next()
    }
}

fn match_path(
    env_path: &[&str],
    user_path: &Path,
    role_path: &String,
    previous_min: CmdMin,
    final_path: &mut Option<PathBuf>,
) -> CmdMin {
    if role_path == "**" {
        // any binary: the command of the user, resolved like with the "all" default behavior
        let min = CmdMin::builder()
            .matching()
            .order(CmdOrder::FullWildcardPath)
            .build();
        resolve_any_command(user_path, env_path).map_or_else(CmdMin::empty, |path| {
            if min.better(previous_min) {
                *final_path = Some(path);
            }
            min
        })
    } else if user_path.is_absolute() {
        debug!("match_path: user absolute path");
        let min = match_single_path(user_path, role_path);
        if min.better(previous_min) {
            info!("match_path: found better match {min:?}");
            *final_path = Some(user_path.to_path_buf());
        }
        min
    } else {
        debug!("match_path: user relative path");
        let mut curmin = CmdMin::empty();
        all_paths_from_env(env_path, user_path)
            .iter()
            .find_map(|cmd_path| {
                let min = match_single_path(cmd_path, role_path);
                if min.better(previous_min) && min.better(curmin) {
                    *final_path = Some(cmd_path.clone());
                    curmin = min;
                    Some(min)
                } else {
                    None
                }
            })
            .inspect(|m| {
                debug!(
                    "match_path: found better match {:?} with {}",
                    m,
                    final_path.get_or_insert_default().display()
                );
            })
            .unwrap_or_default()
    }
}

/// Check if input args is matching with role args and return the score
/// role args can contains regex
/// input args is the command line args
pub(super) fn match_args(
    input_args: &[String],
    role_args: &str,
) -> Result<CmdMin, Box<dyn std::error::Error>> {
    if role_args == "'^.*$'" {
        return Ok(CmdMin::builder()
            .matching()
            .order(CmdOrder::FullRegexArgs)
            .build());
    }
    let commandline = shell_words::join(input_args);
    if role_args.starts_with("\'^") && role_args.ends_with("$\'") {
        evaluate_regex_cmd(role_args.trim_matches('\''), &commandline).inspect_err(|e| {
            debug!("{e:?},No match for args {input_args:?}");
        })
    } else if commandline == role_args {
        Ok(CmdMin::builder().matching().build())
    } else {
        Ok(CmdMin::builder().build())
    }
}

/// The regex crate matches in linear time: a pattern of the policy cannot make the matching of
/// the user's arguments take exponential time.
#[cfg(feature = "regex")]
fn evaluate_regex_cmd(
    role_args: &str,
    commandline: &str,
) -> Result<CmdMin, Box<dyn std::error::Error>> {
    let regex = regex::Regex::new(role_args)?;
    if regex.is_match(commandline) {
        Ok(CmdMin::builder()
            .matching()
            .order(CmdOrder::RegexArgs)
            .build())
    } else {
        Ok(CmdMin::builder().build())
    }
}

#[cfg(not(feature = "regex"))]
fn evaluate_regex_cmd(
    _role_args: &str,
    _commandline: &str,
) -> Result<CmdMin, Box<dyn std::error::Error>> {
    Ok(CmdMin::empty())
}

/// Check if input command line is matching with role command line and return the score
fn match_command_line(
    env_path: &[&str],
    user_path: &Path,
    user_args: &[String],
    role_command: &[String],
    previous_min: CmdMin,
    final_path: &mut Option<PathBuf>,
) -> CmdMin {
    debug!(
        "match_command_line: env_path={:?}, user_path={}, user_args={:?}, role_command={:?}, previous_min={:?}, final_path={:?}",
        env_path,
        user_path.display(),
        user_args,
        role_command,
        previous_min,
        final_path
    );
    if role_command.is_empty() {
        return CmdMin::empty();
    }
    let mut result = match_path(
        env_path,
        user_path,
        &role_command[0],
        previous_min,
        final_path,
    );
    if result.is_empty() || role_command.len() == 1 {
        debug!("preresult : {result:?}");
        return result;
    }
    match match_args(user_args, &shell_words::join(&role_command[1..])) {
        Ok(args_result) => {
            if args_result.is_empty() {
                return CmdMin::empty();
            }
            result.union_order(args_result.order);
        }
        Err(err) => {
            debug!("Error: {err}");
            return CmdMin::empty();
        }
    }
    debug!("result : {result:?}");
    result
}

pub fn evaluate_command_match(
    env_path: &[&str],
    cmd_path: &Path,
    cmd_args: &[String],
    role_cmd: &str,
    previous_min: CmdMin,
    final_path: &mut Option<PathBuf>,
) -> CmdMin {
    match shell_words::split(role_cmd).map_err(Into::<Box<dyn std::error::Error>>::into) {
        Ok(role_cmd) => match_command_line(
            env_path,
            cmd_path,
            cmd_args,
            &role_cmd,
            previous_min,
            final_path,
        ),
        Err(err) => {
            warn!("Error: {err}");
            CmdMin::empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_log::test;

    #[test]
    fn test_match_path_full_wildcard() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let role_path = String::from("**");
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_path(
            &env_path,
            &cmd_path,
            &role_path,
            previous_min,
            &mut final_path,
        );
        assert_eq!(
            result,
            CmdMin::builder()
                .matching()
                .order(CmdOrder::FullWildcardPath)
                .build()
        );
        // the command of the user is resolved in PATH
        assert_eq!(final_path, Some(PathBuf::from("/usr/bin/ls")));
    }

    #[test]
    fn test_match_path() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let role_path = String::from("/bin/ls");
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_path(
            &env_path,
            &cmd_path,
            &role_path,
            previous_min,
            &mut final_path,
        );
        assert!(result.matching());
        assert_eq!(final_path, Some(PathBuf::from("/bin/ls")));
    }

    #[test]
    fn test_match_path_absolute_no_match() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("/usr/local/bin/ls");
        let role_path = String::from("/bin/ls");
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_path(
            &env_path,
            &cmd_path,
            &role_path,
            previous_min,
            &mut final_path,
        );
        assert!(!result.matching());
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_match_path_absolute_match() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("/bin/ls");
        let role_path = String::from("/bin/ls");
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_path(
            &env_path,
            &cmd_path,
            &role_path,
            previous_min,
            &mut final_path,
        );
        assert!(result.matching());
        assert_eq!(final_path, Some(PathBuf::from("/bin/ls")));
    }

    #[test]
    fn test_match_path_not_found_in_env() {
        let env_path = ["/usr/local/sbin"];
        let cmd_path = PathBuf::from("ls");
        let role_path = String::from("/bin/ls");
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_path(
            &env_path,
            &cmd_path,
            &role_path,
            previous_min,
            &mut final_path,
        );
        assert!(!result.matching());
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_match_args() {
        let input_args = vec!["-l".to_string(), "/tmp".to_string()];
        let role_args = "-l /tmp";
        let result = match_args(&input_args, role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::MATCH);
    }

    #[cfg(feature = "regex")]
    #[test]
    fn test_match_args_full_regex() {
        let input_args = vec!["foo".to_string(), "bar".to_string()];
        let role_args = "'^.*$'";
        let result = match_args(&input_args, role_args);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            CmdMin::builder()
                .matching()
                .order(CmdOrder::FullRegexArgs)
                .build()
        );
    }

    #[cfg(feature = "regex")]
    #[test]
    fn test_match_args_full_regex_empty_input() {
        let input_args: Vec<String> = vec![];
        let role_args = "'^.*$'";
        let result = match_args(&input_args, role_args);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            CmdMin::builder()
                .matching()
                .order(CmdOrder::FullRegexArgs)
                .build()
        );
    }

    #[cfg(feature = "regex")]
    #[test]
    fn test_match_args_regex_args() {
        let input_args: Vec<String> = vec!["a".to_string(), "A".to_string()];
        let role_args = "'^[Aa ]*$'";
        let result = match_args(&input_args, role_args);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            CmdMin::builder()
                .matching()
                .order(CmdOrder::RegexArgs)
                .build()
        );
        let role_args = "'^[Aa]*$'";
        let result = match_args(&input_args, role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::empty());
    }

    #[test]
    fn test_match_args_no_match() {
        let input_args = vec!["-a".to_string()];
        let role_args = "-l";
        let result = match_args(&input_args, role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::empty());
    }

    #[test]
    fn test_match_args_input_longer_than_role() {
        let input_args = vec!["-l".to_string(), "/tmp".to_string(), "extra".to_string()];
        let role_args = "-l /tmp";
        let result = match_args(&input_args, role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::empty());
    }

    #[test]
    fn test_match_args_input_shorter_than_role() {
        let input_args = vec!["-l".to_string()];
        let role_args = "-l /tmp";
        let result = match_args(&input_args, role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::empty());
    }

    #[test]
    fn test_match_command_line() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args = vec!["-l".to_string(), "/tmp".to_string()];
        let role_command = vec!["/bin/ls".to_string(), "-l".to_string(), "/tmp".to_string()];
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_command_line(
            &env_path,
            &cmd_path,
            &cmd_args,
            &role_command,
            previous_min,
            &mut final_path,
        );
        assert!(result.matching());
        assert_eq!(final_path, Some(PathBuf::from("/bin/ls")));
    }

    #[cfg(feature = "regex")]
    #[test]
    fn test_match_command_line_args_mismatch() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args = vec!["-a".to_string()];
        let role_command = vec!["/bin/ls".to_string(), "-l".to_string()];
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_command_line(
            &env_path,
            &cmd_path,
            &cmd_args,
            &role_command,
            previous_min,
            &mut final_path,
        );
        assert!(!result.matching());
        assert_eq!(final_path, Some(PathBuf::from("/bin/ls")));
    }

    #[test]
    fn test_match_command_line_empty_cmd_args_multi_role_args() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args: Vec<String> = vec![];
        let role_command = vec!["/bin/ls".to_string(), "-l".to_string(), "/tmp".to_string()];
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_command_line(
            &env_path,
            &cmd_path,
            &cmd_args,
            &role_command,
            previous_min,
            &mut final_path,
        );
        assert!(!result.matching());
        assert_eq!(final_path, Some(PathBuf::from("/bin/ls")));
    }

    #[test]
    fn test_match_command_line_single_arg() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args: Vec<String> = vec![];
        let role_command = vec!["/bin/ls".to_string()];
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_command_line(
            &env_path,
            &cmd_path,
            &cmd_args,
            &role_command,
            previous_min,
            &mut final_path,
        );
        assert!(result.matching());
        assert_eq!(final_path, Some(PathBuf::from("/bin/ls")));
    }

    #[test]
    fn test_match_command_line_empty_role_command() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args: Vec<String> = vec![];
        let role_command: Vec<String> = vec![];
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_command_line(
            &env_path,
            &cmd_path,
            &cmd_args,
            &role_command,
            previous_min,
            &mut final_path,
        );
        assert!(!result.matching());
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_match_command_line_role_command_only_args() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args = vec!["-l".to_string()];
        let role_command = vec!["-l".to_string()];
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_command_line(
            &env_path,
            &cmd_path,
            &cmd_args,
            &role_command,
            previous_min,
            &mut final_path,
        );
        // Should not match, as the binary is not specified
        assert!(!result.matching());
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_match_command_line_role_command_only_wildcard() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args: Vec<String> = vec![];
        let role_command = vec!["**".to_string()];
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_command_line(
            &env_path,
            &cmd_path,
            &cmd_args,
            &role_command,
            previous_min,
            &mut final_path,
        );
        assert_eq!(
            result,
            CmdMin::builder()
                .matching()
                .order(CmdOrder::FullWildcardPath)
                .build()
        );
        // the command of the user is resolved in PATH
        assert_eq!(final_path, Some(PathBuf::from("/usr/bin/ls")));
    }

    #[test]
    fn test_match_command_line_previous_min_set() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args: Vec<String> = vec!["-l".to_string()];
        let role_command = vec!["/bin/l*".to_string(), "^.*$".to_string()];
        let previous_min = CmdMin::MATCH; // better than regex
        let mut final_path = Some("/usr/bin/ls".into());
        let result = match_command_line(
            &env_path,
            &cmd_path,
            &cmd_args,
            &role_command,
            previous_min,
            &mut final_path,
        );
        assert_eq!(result, CmdMin::empty());
        assert_eq!(final_path, Some("/usr/bin/ls".into()));
    }

    #[test]
    fn test_evaluate_command_match() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args = vec!["-l".to_string(), "/tmp".to_string()];
        let role_cmd = "/bin/ls -l /tmp";
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = evaluate_command_match(
            &env_path,
            &cmd_path,
            &cmd_args,
            role_cmd,
            previous_min,
            &mut final_path,
        );
        assert!(result.matching());
        assert_eq!(final_path, Some(PathBuf::from("/bin/ls")));
    }

    #[test]
    fn test_evaluate_command_match_invalid_role_cmd() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args = vec!["-l".to_string(), "/tmp".to_string()];
        let role_cmd = "\"unterminated string";
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = evaluate_command_match(
            &env_path,
            &cmd_path,
            &cmd_args,
            role_cmd,
            previous_min,
            &mut final_path,
        );
        assert!(!result.matching());
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_argument_with_quotes_matches_a_quoted_rule() {
        let env_path = ["/usr/bin"];
        let matches = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(ToString::to_string).collect();
            let mut final_path = None;
            evaluate_command_match(
                &env_path,
                Path::new("/usr/bin/echo"),
                &args,
                r#"/usr/bin/echo '"a"'"#,
                CmdMin::empty(),
                &mut final_path,
            )
            .matching()
        };
        // the rule is written with shell quoting, the argument holds the quotes
        assert!(matches(&["\"a\""]));
        assert!(!matches(&["a"]));
    }

    #[test]
    fn test_evaluate_command_match_only_wildcard() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args: Vec<String> = vec![];
        let role_cmd = "**";
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = evaluate_command_match(
            &env_path,
            &cmd_path,
            &cmd_args,
            role_cmd,
            previous_min,
            &mut final_path,
        );
        assert_eq!(
            result,
            CmdMin::builder()
                .matching()
                .order(CmdOrder::FullWildcardPath)
                .build()
        );
        // the command of the user is resolved in PATH
        assert_eq!(final_path, Some(PathBuf::from("/usr/bin/ls")));
    }
}
