use serde::{Deserialize, Serialize};
use sha1::Digest;

use crate::{command::{find_executable_in_path, parse_conf_command}, common::{api::{PluginManager, PluginPosition}, database::structs::SCommand}};

use md5;

#[derive(Debug, Serialize, Deserialize)]
pub enum HashType {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Debug, Serialize, Deserialize)]
struct HashChecker {
    hash_type: HashType,
    hash: String,
    command: SCommand,
}

fn compute(hashtype : &HashType, hash: &str) -> Vec<u8> {
    match hashtype {
        HashType::MD5 => md5::compute(hash).0.to_vec(),
        HashType::SHA1 => {
            let mut hasher = sha1::Sha1::new();
            hasher.update(hash);
            hasher.finalize().to_vec()
        },
        HashType::SHA224 => {
            let mut hasher = sha2::Sha224::new();
            hasher.update(hash);
            hasher.finalize().to_vec()
        },
        HashType::SHA256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(hash);
            hasher.finalize().to_vec()
        },
        HashType::SHA384 => {
            let mut hasher = sha2::Sha384::new();
            hasher.update(hash);
            hasher.finalize().to_vec()
        },
        HashType::SHA512 => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(hash);
            hasher.finalize().to_vec()
        },
    }
}

fn complex_command_parse(command: &serde_json::Value) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let checker = serde_json::from_value::<HashChecker>(command.clone());
    
    match checker {
        Ok(checker) => {
            let path;
            if let SCommand::Simple(command) = &checker.command {
                let opath = find_executable_in_path(&command);
                if opath.is_none() {
                    return Err("Command not found".into());
                }
                path = opath.unwrap();
            } else {
                return Err("Invalid command".into());
            }
            return if compute(&checker.hash_type, &String::from_utf8(std::fs::read(&path)?)?) == compute(&checker.hash_type, &checker.hash) {
                parse_conf_command(&checker.command)
            } else {
                Err("Hashes do not match".into())
            };
        },
        Err(e) => Err(Box::new(e))
    }
}

pub fn register() {
    PluginManager::subscribe_complex_command_parser(complex_command_parse, PluginPosition::Beginning)
}