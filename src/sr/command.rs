use std::{path::{PathBuf, Path}, env::var};

use shell_words::ParseError;


fn get_command_abspath_and_args(content : &str) -> Result<Vec<String>,ParseError> {
    shell_words::split(content)
}

fn find_executable_in_path(executable : &str) -> Option<PathBuf> {
    let path = var("PATH").unwrap_or("".to_string());
    for dir in path.split(":") {
        let path = Path::new(dir).join(executable);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

pub fn parse_conf_command(command : &str) -> Result<Vec<String>,ParseError> {
    if command == "ALL" {
        return Ok(vec!["**".to_string(), ".*".to_string()])
    }
    shell_words::split(command)
}
