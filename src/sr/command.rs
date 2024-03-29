use std::{
    env::var, error::Error, path::{Path, PathBuf}
};

use shell_words::ParseError;

use crate::common::{api::PluginManager, database::structs::SCommand};

fn get_command_abspath_and_args(content: &str) -> Result<Vec<String>, ParseError> {
    shell_words::split(content)
}

pub fn find_executable_in_path(executable: &str) -> Option<PathBuf> {
    let path = var("PATH").unwrap_or("".to_string());
    for dir in path.split(':') {
        let path = Path::new(dir).join(executable);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

pub fn parse_conf_command(command: &SCommand) -> Result<Vec<String>, Box<dyn Error>> {
    match command {
        SCommand::Simple(command) => {
            if command == "ALL" {
                return Ok(vec!["**".to_string(), ".*".to_string()]);
            }
            Ok(shell_words::split(command)?)
        },
        SCommand::Complex(command) => {
            if let Some(array) = command.as_array() {
                let mut result = Vec::new();
                if ! array.iter().all(|item| {
                    // if it is a string
                    item.is_string() && {
                        //add to result
                        result.push(item.as_str().unwrap().to_string());
                        true // continue
                    }
                    
                }) { // if any of the items is not a string
                    return Err("Invalid command".into());
                }
                Ok(result)
            } else {
                // call PluginManager
                PluginManager::notify_complex_command_parser(command)
            }

        }
    }
    
}
