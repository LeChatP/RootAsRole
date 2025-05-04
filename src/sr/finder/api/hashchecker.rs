use std::{error::Error, fs::File, io::Read, os::fd::AsRawFd, path::PathBuf};

use ::serde::{Deserialize, Serialize};
use libc::FS_IOC_GETFLAGS;
use log::{debug, warn};
use nix::unistd::{access, AccessFlags};
use rar_common::{
    database::score::CmdMin,
    util::{all_paths_from_env, match_single_path, open_with_privileges},
};
use serde_json::to_value;
use sha2::Digest;

use crate::finder::cmd::match_args;

use super::{Api, ApiEvent, EventKey};

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
    if let ApiEvent::ProcessComplexCommand(
        value,
        env_path,
        cmd_path,
        cmd_args,
        cmd_min,
        final_path,
    ) = event
    {
        let hash_checker: HashChecker = serde_json::from_value(to_value(value)?)?;
        process_hash_check(
            hash_checker,
            env_path,
            cmd_path,
            cmd_args,
            *cmd_min,
            *final_path,
        );
    }
    Ok(())
}

fn evaluate_hash(hashtype: &HashElement, hash: &[u8]) -> bool {
    match hashtype {
        HashElement::SHA224 { sha224 } => {
            let mut hasher = sha2::Sha224::new();
            hasher.update(hash);
            hasher.finalize().to_vec() == hex::decode(sha224).unwrap()
        }
        HashElement::SHA256 { sha256 } => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(hash);
            hasher.finalize().to_vec() == hex::decode(sha256).unwrap()
        }
        HashElement::SHA384 { sha384 } => {
            let mut hasher = sha2::Sha384::new();
            hasher.update(hash);
            hasher.finalize().to_vec() == hex::decode(sha384).unwrap()
        }
        HashElement::SHA512 { sha512 } => {
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

fn match_path(
    checker: &HashChecker,
    env_path: &[&str],
    cmd_path: &PathBuf,
    role_path: &String,
    final_path: &mut Option<PathBuf>,
) -> CmdMin {
    all_paths_from_env(env_path,cmd_path).iter().find_map(|cmd_path| {
        let min = match_single_path(cmd_path, role_path);
        if min.matching() {
            if checker.read_only.is_some_and(|read_only| read_only) {
                if access(cmd_path, AccessFlags::W_OK).is_ok() {
                    warn!("File should be read only but has write access");
                    return None;
                }
                warn!("Executor has write access to the executable, this could lead to a race condition vulnerability");
            }
            let open = open_with_privileges(cmd_path);
            if open.is_err() {
                return None;
            }
            let mut open = open.unwrap();
            if checker.immutable.is_some_and(|immutable| immutable) {
                let is_immutable = is_immutable(&open);
                if is_immutable.is_err() {
                    return None;
                }
                if !is_immutable.unwrap() {
                    warn!("File should be immutable but is not");
                    return None;
                }
            }
            if let Some(hash_element) = &checker.hash {
                let mut buf = Vec::new();
                let res = open.read_to_end(&mut buf);
                if res.is_err() {
                    warn!("Error reading file {:?}", res);
                    return None;
                }
                if !evaluate_hash(&hash_element, &buf) {
                    warn!("Hash does not match");
                    return None;
                }
            }
            *final_path = Some(cmd_path.clone());
            Some(min)
        } else {
            None
        }
    }).unwrap_or_default()
}

/// Check if input command line is matching with role command line and return the score
fn match_command_line(
    checker: &HashChecker,
    env_path: &[&str],
    cmd_path: &PathBuf,
    cmd_args: &[String],
    role_command: &[String],
    cmd_min: &mut CmdMin,
    final_path: &mut Option<PathBuf>,
) {
    let mut result = match_path(checker, env_path, cmd_path, &role_command[0], final_path);
    if result.is_empty() || role_command.len() == 1 {
        return;
    }
    match match_args(cmd_args, &shell_words::join(&role_command[1..])) {
        Ok(args_result) => result |= args_result,
        Err(err) => {
            debug!("Error: {}", err);
            return;
        }
    }
    *cmd_min = result;
}

fn process_hash_check(
    checker: HashChecker,
    env_path: &[&str],
    cmd_path: &PathBuf,
    cmd_args: &[String],
    min_score: &mut CmdMin,
    final_path: &mut Option<PathBuf>,
) {
    match shell_words::split(&checker.command)
        .map_err(|e| Into::<Box<dyn std::error::Error>>::into(e))
    {
        Ok(command) => {
            match_command_line(
                &checker, env_path, cmd_path, cmd_args, &command, min_score, final_path,
            );
        }
        Err(err) => {
            warn!("Error: {}", err);
        }
    }
}

pub fn register() {
    Api::register(EventKey::NewComplexCommand, new_complex_command);
}
