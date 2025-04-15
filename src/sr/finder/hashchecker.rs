use std::{error::Error, fs::File, io::Read, os::fd::AsRawFd, path::PathBuf};

use glob::Pattern;
use libc::FS_IOC_GETFLAGS;
use log::{debug, warn};
use nix::unistd::{access, AccessFlags};
use rar_common::{database::finder::{CmdMin, MatchError}, util::{final_path, open_with_privileges}};
use ::serde::{Deserialize, Serialize};
use serde_json::to_value;
use sha2::Digest;


use super::api::{Api, ApiEvent, EventKey};

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[serde(rename_all = "lowercase", untagged)]
pub enum HashElement {
    SHA224 {
        #[serde(rename = "sha224")]
        sha224: String,
    },
    SHA256 {
        #[serde(rename = "sha256")]
        sha256: String,
    },
    SHA384 {
        #[serde(rename = "sha384")]
        sha384: String,
    },
    SHA512 {
        #[serde(rename = "sha512")]
        sha512: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
struct HashChecker {
    #[serde(flatten)]
    hash: Option<HashElement>,
    #[serde(alias = "read-only")]
    read_only: Option<bool>,
    immutable: Option<bool>,
    command: String,
}

fn new_complex_command(event: &mut ApiEvent) -> Result<(), Box<dyn Error>> {
    if let ApiEvent::NewComplexCommand(value, cmd_path, cmd_args, cmd_min) = event {
        let hash_checker: HashChecker = serde_json::from_value(to_value(value)?)?;
        return process_hash_check(cmd_path, cmd_args,  cmd_min, hash_checker);
    }
    Ok(())
}

fn evaluate_hash(hashtype: &HashElement, hash: &[u8]) -> bool {
    match hashtype {
        HashElement::SHA224 { sha224} => {
            let mut hasher = sha2::Sha224::new();
            hasher.update(hash);
            hasher.finalize().to_vec() == hex::decode(sha224).unwrap()
        }
        HashElement::SHA256 { sha256} => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(hash);
            hasher.finalize().to_vec() == hex::decode(sha256).unwrap()
        }
        HashElement::SHA384 { sha384} => {
            let mut hasher = sha2::Sha384::new();
            hasher.update(hash);
            hasher.finalize().to_vec() == hex::decode(sha384).unwrap()
        }
        HashElement::SHA512 { sha512} => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(hash);
            hasher.finalize().to_vec() == hex::decode(sha512).unwrap()
        }
    }
}


const FS_IMMUTABLE_FL: u32 = 0x00000010;

fn is_immutable(file: &File) -> Result<bool, Box<dyn std::error::Error>> {
    let mut val = 0;
    let fd = file.as_raw_fd();
    if unsafe { nix::libc::ioctl(fd, FS_IOC_GETFLAGS, &mut val) } < 0 {
        debug!("Error getting flags {:?}", std::io::Error::last_os_error());
        return Err("Error getting flags".into());
    }
    Ok(val & FS_IMMUTABLE_FL != 0)
}

#[cfg(feature = "pcre2")]
fn evaluate_regex_cmd(role_args: String, commandline: String) -> Result<CmdMin, Box<dyn std::error::Error>> {
    let regex = RegexBuilder::new().build(&role_args)?;
    if regex.is_match(commandline.as_bytes())? {
        Ok(CmdMin::RegexArgs)
    } else {
        Err(Box::new(MatchError::NoMatch(
            "Regex for command does not match".to_string(),
        )))
    }
}

#[cfg(not(feature = "pcre2"))]
fn evaluate_regex_cmd(_role_args: String, _commandline: String) -> Result<CmdMin, Box<dyn std::error::Error>> {

    Err(Box::new(MatchError::NoMatch("No match found".to_string())))
}

fn match_path(checker: &HashChecker, input_path: &PathBuf, role_path: &str) -> Result<CmdMin, Box<dyn std::error::Error>> {
    if role_path == "*" {
        return Ok(CmdMin::WildcardPath);
    }
    if role_path == "**" {
        return Ok(CmdMin::FullWildcardPath);
    }
    let mut match_status = CmdMin::empty();
    if !role_path.ends_with(input_path.file_name().unwrap().to_str().unwrap()) {
        // the files could not be the same
        return Ok(CmdMin::empty());
    }
    let new_path = final_path(input_path);
    let role_path = final_path(role_path);
    
    debug!("Matching path {:?} with {:?}", new_path, role_path);
    if new_path == role_path {
        match_status |= CmdMin::Match;
    } else if let Ok(pattern) = Pattern::new(role_path.to_str().unwrap()) {
        if pattern.matches_path(&new_path) {
            match_status |= CmdMin::WildcardPath;
        }
    }
    if match_status.is_empty() {
        debug!(
            "No match for path ``{:?}`` for evaluated path : ``{:?}``",
            new_path, role_path
        );
    } else {
        if checker.read_only.is_some_and(|read_only| read_only) {
            if access(&new_path, AccessFlags::W_OK).is_ok() {
                warn!("File should be read only but has write access");
                return Ok(CmdMin::empty());
            }
            warn!("Executor has write access to the executable, this could lead to a race condition vulnerability");
        }
        let mut open = open_with_privileges(&new_path)?;
        if checker.immutable.is_some_and(|immutable| immutable) {
            if !is_immutable(&open)? {
                warn!("File should be immutable but is not");
                return Ok(CmdMin::empty());
            }
        }
        if let Some(hash_element) = &checker.hash {
            let mut buf = Vec::new();
            open.read_to_end(&mut buf)?;
            if !evaluate_hash(&hash_element, &buf) {
                warn!("Hash does not match");
                return Ok(CmdMin::empty());
            }
        }
    } 
    Ok(match_status)
}

/// Check if input args is matching with role args and return the score
/// role args can contains regex
/// input args is the command line args
fn match_args(input_args: &[String], role_args: &[String]) -> Result<CmdMin, Box<dyn std::error::Error>> {
    if role_args[0] == ".*" {
        return Ok(CmdMin::FullRegexArgs);
    }
    let commandline = input_args.join(" ");
    let role_args = role_args.join(" ");
    debug!("Matching args {:?} with {:?}", commandline, role_args);
    if commandline != role_args {
        debug!("test regex");
        evaluate_regex_cmd(role_args, commandline).inspect_err(|e| {
            debug!("{:?},No match for args {:?}", e, input_args);
        })
    } else {
        Ok(CmdMin::Match)
    }
}

fn match_command_line(checker: &HashChecker, cmd_path: &PathBuf, cmd_args : &[String], role_command: &[String]) -> Result<CmdMin, Box<dyn std::error::Error>> {
    let mut result = match_path(checker, cmd_path, &role_command[0])?;
    if result.is_empty() || role_command.len() == 1 {
        return Ok(result);
    }
    match match_args(cmd_args, &role_command[1..]) {
        Ok(args_result) => result |= args_result,
        Err(err) => {
            if err.downcast_ref::<MatchError>().is_none() {
                warn!("Error: {}", err);
            }
            return Ok(CmdMin::empty());
        }
    }
    Ok(result)
}

fn process_hash_check(cmd_path: &PathBuf, cmd_args: &[String], min_score: &mut CmdMin, checker: HashChecker) -> Result<(), Box<dyn Error>> {
    match shell_words::split(&checker.command).map_err(|e| Into::<Box<dyn std::error::Error>>::into(e)) {
        Ok(command) => {
            let new_score = match_command_line(&checker, cmd_path, cmd_args, &command)?;
            debug!("Score for command {:?} is {:?}", command, new_score);
            if !new_score.is_empty() && (min_score.is_empty() || (new_score < *min_score)) {
                debug!("New min score for command {:?} is {:?}", command, new_score);
                *min_score = new_score;
            }
        }
        Err(err) => {
            warn!("Error: {}", err);
        }
    }
    Ok(())
}


pub fn register() {
    Api::register(EventKey::NewComplexCommand, new_complex_command);
}