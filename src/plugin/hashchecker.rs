use serde::{Deserialize, Serialize};
use tracing::debug;
use tracing_subscriber::field::debug;

use crate::common::{
    api::PluginManager,
    database::{
        finder::{final_path, find_executable_in_path, parse_conf_command},
        structs::SCommand,
    },
};

use sha2::Digest;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashType {
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

fn compute(hashtype: &HashType, hash: &[u8]) -> Vec<u8> {
    match hashtype {
        HashType::SHA224 => {
            let mut hasher = sha2::Sha224::new();
            hasher.update(hash);
            hasher.finalize().to_vec()
        }
        HashType::SHA256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(hash);
            hasher.finalize().to_vec()
        }
        HashType::SHA384 => {
            let mut hasher = sha2::Sha384::new();
            hasher.update(hash);
            hasher.finalize().to_vec()
        }
        HashType::SHA512 => {
            let mut hasher = sha2::Sha512::new();
            hasher.update(hash);
            hasher.finalize().to_vec()
        }
    }
}

fn complex_command_parse(
    command: &serde_json::Value,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let checker = serde_json::from_value::<HashChecker>(command.clone());
    debug!("Checking command {:?}", checker);
    match checker {
        Ok(checker) => {
            let cmd = parse_conf_command(&checker.command)?;
            let path = final_path(&cmd[0]);
            debug!("Checking path {:?}", path);
            let hash = compute(&checker.hash_type, &std::fs::read(path)?);
            let config_hash = hex::decode(checker.hash.as_bytes())?;
            if hash == config_hash {
                debug!("Hashes match");
                parse_conf_command(&checker.command)
            } else {
                debug!("Hashes do not match");
                Err("Hashes do not match".into())
            }
        }
        Err(e) => {
            debug!("Error parsing command {:?}", e);
            Err(Box::new(e))
        }
    }
}

pub fn register() {
    PluginManager::subscribe_complex_command_parser(complex_command_parse)
}

#[cfg(test)]
mod tests {

    use std::rc::Rc;

    use nix::unistd::{Pid, User};

    use super::*;
    use crate::{
        common::database::{
            finder::{Cred, TaskMatcher},
            structs::{IdTask, SActor, SCommand, SCommands, SConfig, SRole, STask},
        },
        rc_refcell,
    };

    #[test]
    fn test_plugin_implemented() {
        register();
        let config = rc_refcell!(SConfig::default());
        let role1 = rc_refcell!(SRole::default());
        role1.as_ref().borrow_mut()._config = Some(Rc::downgrade(&config));
        role1.as_ref().borrow_mut().name = "role1".to_string();
        let task1 = rc_refcell!(STask::default());
        task1.as_ref().borrow_mut()._role = Some(Rc::downgrade(&role1));
        task1.as_ref().borrow_mut().name = IdTask::Name("task1".to_string());
        let mut command = SCommands::default();
        command.add.push(SCommand::Complex(serde_json::json!({
            "hash_type": "sha256",
            "hash": "3b77deacba25588129debfb3b9603d7e7187c29d7f6c14bdb667426b7be91761",
            "command": "/usr/bin/cat /etc/passwd"
        })));
        task1.as_ref().borrow_mut().commands = command;
        role1.as_ref().borrow_mut().tasks.push(task1);
        role1
            .as_ref()
            .borrow_mut()
            .actors
            .push(SActor::from_user_id(0));

        config.as_ref().borrow_mut().roles.push(role1);

        let cred = Cred {
            user: User::from_uid(0.into()).unwrap().unwrap(),
            groups: vec![],
            ppid: Pid::parent(),
            tty: None,
        };

        let matching = config
            .matches(
                &cred,
                &vec!["/usr/bin/cat".to_string(), "/etc/passwd".to_string()],
            )
            .unwrap();
        assert!(matching.fully_matching())
    }
}
