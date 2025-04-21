use std::path::PathBuf;
use log::{debug, warn};
use rar_common::{database::score::CmdMin, util::{all_paths_from_env, match_single_path}};

fn match_path(
    env_path: &[PathBuf],
    cmd_path: &PathBuf,
    role_path: &String,
    final_path: &mut PathBuf,
) -> CmdMin {
    all_paths_from_env(env_path,cmd_path).iter().find_map(|cmd_path| {
        let min = match_single_path(cmd_path, role_path);
        if min.matching() {
            *final_path = cmd_path.clone();
            Some(min)
        } else {
            None
        }
    }).unwrap_or_default()
}

/// Check if input args is matching with role args and return the score
/// role args can contains regex
/// input args is the command line args
pub(super) fn match_args(
    input_args: &[String],
    role_args: &[String],
) -> Result<CmdMin, Box<dyn std::error::Error>> {
    if role_args[0] == ".*" {
        return Ok(CmdMin::FullRegexArgs);
    }
    let commandline = input_args.join(" ");
    let role_args = role_args.join(" ");
    debug!("Matching args {:?} with {:?}", commandline, role_args);
    let res = if commandline != role_args {
        debug!("test regex");
        evaluate_regex_cmd(role_args, commandline).inspect_err(|e| {
            debug!("{:?},No match for args {:?}", e, input_args);
        })
    } else {
        Ok(CmdMin::Match)
    };
    res
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
    _role_args: String,
    _commandline: String,
) -> Result<CmdMin, Box<dyn std::error::Error>> {
    Ok(CmdMin::empty())
}

/// Check if input command line is matching with role command line and return the score
fn match_command_line(
    env_path: &[PathBuf],
    cmd_path: &PathBuf,
    cmd_args: &[String],
    role_command: &[String],
    final_path: &mut PathBuf,
) -> CmdMin {
    let mut result = match_path(env_path, &cmd_path, &role_command[0], final_path);
    if result.is_empty() || role_command.len() == 1 {
        return result;
    }
    match match_args(cmd_args, &role_command[1..]) {
        Ok(args_result) => result |= args_result,
        Err(err) => {
            debug!("Error: {}", err);
            return CmdMin::empty();
        }
    }
    result
}

pub fn evaluate_command_match(
    env_path: &[PathBuf],
    cmd_path: &PathBuf,
    cmd_args: &[String],
    role_cmd: &str,
    final_path: &mut PathBuf,
) -> CmdMin {
    match shell_words::split(role_cmd).map_err(|e| Into::<Box<dyn std::error::Error>>::into(e)) {
        Ok(command) => match_command_line(env_path, cmd_path, cmd_args, &command, final_path),
        Err(err) => {
            warn!("Error: {}", err);
            CmdMin::empty()
        }
    }
}
