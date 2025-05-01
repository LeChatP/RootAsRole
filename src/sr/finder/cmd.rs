use std::path::PathBuf;
use log::{debug, warn};
use rar_common::{database::score::CmdMin, util::{all_paths_from_env, match_single_path}};

fn match_path(
    env_path: &[&str],
    cmd_path: &PathBuf,
    role_path: &String,
    previous_min: &CmdMin,
    final_path: &mut Option<PathBuf>,
) -> CmdMin {
    if role_path == "**" {
         return CmdMin::FullWildcardPath;
    }else if cmd_path.is_absolute() {
        let min = match_single_path(cmd_path, role_path);
        if previous_min.better(&min) {
            *final_path = Some(cmd_path.clone());
        }
        return min;
    } else {
        all_paths_from_env(env_path,cmd_path).iter().find_map(|cmd_path| {
            let min = match_single_path(cmd_path, role_path);
            if previous_min.better(&min) {
                *final_path = Some(cmd_path.clone());
                Some(min)
            } else {
                None
            }
        }).unwrap_or_default()
    }
    
}

/// Check if input args is matching with role args and return the score
/// role args can contains regex
/// input args is the command line args
pub(super) fn match_args(
    input_args: &[String],
    role_args: &str,
) -> Result<CmdMin, Box<dyn std::error::Error>> {
    let commandline = shell_words::join(input_args);
    if role_args.starts_with('^') && role_args.ends_with('$') {
        evaluate_regex_cmd(role_args, commandline).inspect_err(|e| {
            debug!("{:?},No match for args {:?}", e, input_args);
        })
    } else if commandline == role_args {
        Ok(CmdMin::Match)
    } else {
        Ok(CmdMin::empty())
    }
}

#[cfg(feature = "pcre2")]
fn evaluate_regex_cmd(
    role_args: String,
    commandline: String,
) -> Result<CmdMin, Box<dyn std::error::Error>> {
    let regex = RegexBuilder::new().build(&role_args)?;
    if regex.is_match(commandline.as_bytes())? {
        Ok(CmdMin::RegexArgs)
    } else {
        Ok(CmdMin::empty())
    }
}

#[cfg(not(feature = "pcre2"))]
fn evaluate_regex_cmd(
    _role_args: &str,
    _commandline: String,
) -> Result<CmdMin, Box<dyn std::error::Error>> {
    Ok(CmdMin::empty())
}

/// Check if input command line is matching with role command line and return the score
fn match_command_line(
    env_path: &[&str],
    cmd_path: &PathBuf,
    cmd_args: &[String],
    role_command: &[String],
    previous_min: &CmdMin,
    final_path: &mut Option<PathBuf>,
) -> CmdMin {
    if role_command.is_empty() {
        return CmdMin::empty();
    }
    let mut result = match_path(env_path, &cmd_path, &role_command[0], previous_min, final_path);
    if result.is_empty() || role_command.len() == 1 {
        return result;
    }
    match match_args(cmd_args, &shell_words::join(&role_command[1..])) {
        Ok(args_result) => {
            if args_result.is_empty() {
                return CmdMin::empty();
            }
            result |= args_result;
        }
        Err(err) => {
            debug!("Error: {}", err);
            return CmdMin::empty();
        }
    }
    result
}

pub fn evaluate_command_match(
    env_path: &[& str],
    cmd_path: &PathBuf,
    cmd_args: &[String],
    role_cmd: &str,
    previous_min: &CmdMin,
    final_path: &mut Option<PathBuf>,
) -> CmdMin {
    match shell_words::split(role_cmd).map_err(|e| Into::<Box<dyn std::error::Error>>::into(e)) {
        Ok(role_cmd) => match_command_line(env_path, cmd_path, cmd_args, &role_cmd, previous_min, final_path),
        Err(err) => {
            warn!("Error: {}", err);
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
        let result = match_path(&env_path, &cmd_path, &role_path, &previous_min, &mut final_path);
        assert_eq!(result, CmdMin::FullWildcardPath);
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_match_path() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let role_path = String::from("/bin/ls");
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_path(&env_path, &cmd_path, &role_path, &previous_min, &mut final_path);
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
        let result = match_path(&env_path, &cmd_path, &role_path, &previous_min, &mut final_path);
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
        let result = match_path(&env_path, &cmd_path, &role_path, &previous_min, &mut final_path);
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
        let result = match_path(&env_path, &cmd_path, &role_path, &previous_min, &mut final_path);
        assert!(!result.matching());
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_match_args() {
        let input_args = vec!["-l".to_string(), "/tmp".to_string()];
        let role_args = "-l /tmp";
        let result = match_args(&input_args, &role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::Match);
    }

    #[cfg(feature = "pcre2")]
    #[test]
    fn test_match_args_full_regex() {
        let input_args = vec!["foo".to_string(), "bar".to_string()];
        let role_args = "^.*$";
        let result = match_args(&input_args, &role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::FullRegexArgs);
    }

    #[cfg(feature = "pcre2")]
    #[test]
    fn test_match_args_full_regex_empty_input() {
        let input_args: Vec<String> = vec![];
        let role_args = "^.*$";
        let result = match_args(&input_args, &role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::FullRegexArgs);
    }

    #[test]
    fn test_match_args_no_match() {
        let input_args = vec!["-a".to_string()];
        let role_args = "-l";
        let result = match_args(&input_args, &role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::empty());
    }

    #[test]
    fn test_match_args_input_longer_than_role() {
        let input_args = vec!["-l".to_string(), "/tmp".to_string(), "extra".to_string()];
        let role_args = "-l /tmp";
        let result = match_args(&input_args, &role_args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), CmdMin::empty());
    }

    #[test]
    fn test_match_args_input_shorter_than_role() {
        let input_args = vec!["-l".to_string()];
        let role_args = "-l /tmp";
        let result = match_args(&input_args, &role_args);
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
        let result = match_command_line(&env_path, &cmd_path, &cmd_args, &role_command, &previous_min, &mut final_path);
        assert!(result.matching());
        assert_eq!(final_path, Some(PathBuf::from("/bin/ls")));
    }

    #[cfg(feature = "pcre2")]
    #[test]
    fn test_match_command_line_args_mismatch() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args = vec!["-a".to_string()];
        let role_command = vec!["/bin/ls".to_string(), "-l".to_string()];
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = match_command_line(&env_path, &cmd_path, &cmd_args, &role_command, &previous_min, &mut final_path);
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
        let result = match_command_line(&env_path, &cmd_path, &cmd_args, &role_command, &previous_min, &mut final_path);
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
        let result = match_command_line(&env_path, &cmd_path, &cmd_args, &role_command, &previous_min, &mut final_path);
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
        let result = match_command_line(&env_path, &cmd_path, &cmd_args, &role_command, &previous_min, &mut final_path);
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
        let result = match_command_line(&env_path, &cmd_path, &cmd_args, &role_command, &previous_min, &mut final_path);
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
        let result = match_command_line(&env_path, &cmd_path, &cmd_args, &role_command, &previous_min, &mut final_path);
        assert_eq!(result, CmdMin::FullWildcardPath);
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_match_command_line_previous_min_set() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args: Vec<String> = vec![];
        let role_command = vec!["/bin/ls".to_string()];
        let previous_min = CmdMin::FullWildcardPath; // higher than empty
        let mut final_path = None;
        let result = match_command_line(&env_path, &cmd_path, &cmd_args, &role_command, &previous_min, &mut final_path);
        // Should still match, but final_path should not be set because previous_min is better
        assert_eq!(result, CmdMin::empty());
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_evaluate_command_match() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args = vec!["-l".to_string(), "/tmp".to_string()];
        let role_cmd = "/bin/ls -l /tmp";
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = evaluate_command_match(&env_path, &cmd_path, &cmd_args, role_cmd, &previous_min, &mut final_path);
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
        let result = evaluate_command_match(&env_path, &cmd_path, &cmd_args, role_cmd, &previous_min, &mut final_path);
        assert!(!result.matching());
        assert_eq!(final_path, None);
    }

    #[test]
    fn test_evaluate_command_match_only_wildcard() {
        let env_path = ["/usr/bin", "/bin"];
        let cmd_path = PathBuf::from("ls");
        let cmd_args: Vec<String> = vec![];
        let role_cmd = "**";
        let previous_min = CmdMin::empty();
        let mut final_path = None;
        let result = evaluate_command_match(&env_path, &cmd_path, &cmd_args, role_cmd, &previous_min, &mut final_path);
        assert_eq!(result, CmdMin::FullWildcardPath);
        assert_eq!(final_path, None);
    }
}