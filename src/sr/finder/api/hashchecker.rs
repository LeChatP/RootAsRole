use std::{error::Error, fs::File, io::Read, os::fd::AsRawFd, path::PathBuf};

use ::serde::{Deserialize, Serialize};
use libc::FS_IOC_GETFLAGS;
use log::{debug, warn};
use nix::unistd::{access, AccessFlags};
use rar_common::{
    database::score::{CmdMin, CmdOrder},
    util::{all_paths_from_env, match_single_path, read_with_privileges},
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
    if role_path == "**" {
        return CmdMin::builder()
            .matching()
            .order(CmdOrder::FullWildcardPath)
            .build();
    } else if cmd_path.is_absolute() {
        let min = match_single_path(cmd_path, role_path);
        verify_executable_conditions(checker, final_path, cmd_path, min).unwrap_or_default()
    } else {
        all_paths_from_env(env_path, cmd_path)
            .iter()
            .find_map(|cmd_path| {
                let min = match_single_path(cmd_path, role_path);
                verify_executable_conditions(checker, final_path, cmd_path, min)
            })
            .unwrap_or_default()
    }
}

fn verify_executable_conditions(
    checker: &HashChecker,
    final_path: &mut Option<PathBuf>,
    cmd_path: &PathBuf,
    min: CmdMin,
) -> Option<CmdMin> {
    if min.matching() {
        if checker.read_only.is_some_and(|read_only| read_only) {
            if access(cmd_path, AccessFlags::W_OK).is_ok() {
                warn!("File should be read only but has write access");
                return None;
            }
            warn!("Executor has write access to the executable, this could lead to a race condition vulnerability");
        }
        let open = read_with_privileges(cmd_path);
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
    if !result.matching() || role_command.len() == 1 {
        *cmd_min = result;
        return;
    }
    match match_args(cmd_args, &shell_words::join(&role_command[1..])) {
        Ok(args_result) => result = args_result,
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

#[cfg(test)]
mod tests {
    use std::{
        fs::File, io::{self, Read}, os::fd::AsRawFd, path::{Path, PathBuf}
    };

    use capctl::{Cap, CapSet, CapState};
    use libc::{FS_IOC_GETFLAGS, FS_IOC_SETFLAGS};
    use log::debug;
    use nix::sys::stat::{fchmodat, Mode};
    use rar_common::{
        database::score::CmdMin, util::{has_privileges, immutable_required_privileges},
    };
    use serde::de::DeserializeSeed;
    use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

    use crate::finder::{api::hashchecker::{register, FS_IMMUTABLE_FL}, de::DCommandDeserializer};
    pub struct Defer<F: FnOnce()>(Option<F>);

    impl<F: FnOnce()> Defer<F> {
        pub fn new(f: F) -> Self {
            Defer(Some(f))
        }
    }

    impl<F: FnOnce()> Drop for Defer<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f();
            }
        }
    }

    pub fn defer<F: FnOnce()>(f: F) -> Defer<F> {
        Defer::new(f)
    }

    fn set_read_only(path: &Path) -> nix::Result<()> {
        // Set permissions to read-only for owner, group, and others
        fchmodat(
            None, // Relative to the current directory
            path,
            Mode::S_IRUSR        // Owner read
                | Mode::S_IRGRP  // Group read
                | Mode::S_IROTH, // Others read
            nix::sys::stat::FchmodatFlags::NoFollowSymlink, // No special flags
        )?;
        Ok(())
    }

    #[test]
    fn test_dcommand_seed_hashchecker() {
        register();
        let filename = "test.sh";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(filename)
                .canonicalize()
                .unwrap_or(filename.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        //create the file
        File::create(&filename).unwrap();
        let filename = PathBuf::from(filename).canonicalize().unwrap();
        //call sha256sum on the file

        let mut file = File::open(&filename).unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        let mut sha224hasher = Sha224::new();
        sha224hasher.update(&buffer);
        let sha224 = sha224hasher.finalize();
        let json = format!(
            r#"{{"sha224": "{:x}", "command": "{} -l"}}"#,
            sha224,
            &filename.display()
        );
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        assert_eq!(final_path, Some(PathBuf::from(&filename)));
        assert_eq!(cmd_min, CmdMin::MATCH);

        let mut sha256hasher = Sha256::new();
        sha256hasher.update(&buffer);
        let sha256 = sha256hasher.finalize();

        let json = format!(
            r#"{{"sha256": "{:x}", "command": "{} -l"}}"#,
            sha256,
            &filename.display()
        );
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        assert_eq!(final_path, Some(PathBuf::from(&filename)));
        assert_eq!(cmd_min, CmdMin::MATCH);

        let mut sha384hasher = Sha384::new();
        sha384hasher.update(&buffer);
        let sha384 = sha384hasher.finalize();

        let json = format!(
            r#"{{"sha384": "{:x}", "command": "{} -l"}}"#,
            sha384,
            &filename.display()
        );
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        assert_eq!(final_path, Some(PathBuf::from(&filename)));
        assert_eq!(cmd_min, CmdMin::MATCH);

        let mut sha512hasher = Sha512::new();
        sha512hasher.update(&buffer);
        let sha512 = sha512hasher.finalize();
        let json = format!(
            r#"{{"sha512": "{:x}", "command": "{} -l"}}"#,
            sha512,
            &filename.display()
        );
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        assert!(result.is_ok());
        assert_eq!(final_path, Some(PathBuf::from(&filename)));
        assert_eq!(cmd_min, CmdMin::MATCH);
    }

    #[test]
    fn test_read_only_immutable() {
        register();
        // remove root privileges
        let current = CapState::get_current();
        let mut current = current.unwrap();
        current.effective = CapSet::empty();
        current.permitted = CapSet::empty();
        current.inheritable = CapSet::empty();
        current.set_current().unwrap();
        let filename = "/tmp/test_ro.sh";
        let _cleanup = defer(|| {
            let filename = PathBuf::from(filename)
                .canonicalize()
                .unwrap_or(filename.into());
            if std::fs::remove_file(&filename).is_err() {
                debug!("Failed to delete the file: {}", filename.display());
            }
        });
        //create the file
        File::create(&filename).unwrap();

        let filename = PathBuf::from(filename).canonicalize().unwrap();
        //call sha256sum on the file

        let json = format!(
            r#"{{"read-only": true, "immutable": true, "command": "{}"}}"#,
            &filename.display()
        );
        debug!("json: {}", json);
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        if let Err(e) = &result {
            debug!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(final_path, None);
        assert_eq!(cmd_min, CmdMin::empty());

        let json = format!(
            r#"{{"read-only": true, "immutable": false, "command": "{}"}}"#,
            &filename.display()
        );
        debug!("json: {}", json);
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        if let Err(e) = &result {
            debug!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(final_path, None);
        assert_eq!(cmd_min, CmdMin::empty());

        let json = format!(
            r#"{{"read-only": false, "immutable": true, "command": "{}"}}"#,
            &filename.display()
        );
        debug!("json: {}", json);
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        if let Err(e) = &result {
            debug!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(final_path, None);
        assert_eq!(cmd_min, CmdMin::empty());

        let json = format!(
            r#"{{"read-only": false, "immutable": false, "command": "{}"}}"#,
            &filename.display()
        );
        debug!("json: {}", json);
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        if let Err(e) = &result {
            debug!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(final_path, PathBuf::from(&filename).canonicalize().ok());
        assert_eq!(cmd_min, CmdMin::MATCH);

        set_read_only(filename.as_path()).unwrap();

        let json = format!(
            r#"{{"read-only": true, "immutable": false, "command": "{}"}}"#,
            &filename.display()
        );
        debug!("json: {}", json);
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        if let Err(e) = &result {
            debug!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(final_path, PathBuf::from(&filename).canonicalize().ok());
        assert_eq!(cmd_min, CmdMin::MATCH);

        let json = format!(
            r#"{{"read-only": true, "immutable": true, "command": "{}"}}"#,
            &filename.display()
        );
        debug!("json: {}", json);
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        if let Err(e) = &result {
            debug!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(final_path, None);
        assert_eq!(cmd_min, CmdMin::empty());

        let json = format!(
            r#"{{"read-only": true, "immutable": true, "command": "{}"}}"#,
            &filename.display()
        );
        debug!("json: {}", json);
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        if let Err(e) = &result {
            debug!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(final_path, None);
        assert_eq!(cmd_min, CmdMin::empty());

        let mut immutable = false;
        if has_privileges(&[Cap::LINUX_IMMUTABLE]).is_ok_and(|b| b) {
            toggle_immutable_config(&filename, false).unwrap();
            immutable = true;
        }
        let json = format!(
            r#"{{"read-only": true, "immutable": {}, "command": "{}"}}"#,
            immutable,
            &filename.display()
        );
        debug!("json: {}", json);
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        if let Err(e) = &result {
            debug!("Error: {}", e);
        }
        assert!(result.is_ok());
        assert_eq!(final_path, PathBuf::from(&filename).canonicalize().ok());
        assert_eq!(cmd_min, CmdMin::MATCH);

        let json = format!(
            r#"{{"read-only": true, "immutable": true, "command": "{}"}}"#,
            &filename.display()
        );
        debug!("json: {}", json);
        let mut final_path = None;
        let mut cmd_min = CmdMin::default();
        let deserializer = DCommandDeserializer {
            env_path: &["/usr/bin"],
            cmd_path: &PathBuf::from(&filename).canonicalize().unwrap(),
            cmd_args: &vec!["-l".to_string()],
            final_path: &mut final_path,
            cmd_min: &mut cmd_min,
        };
        let result = deserializer.deserialize(&mut serde_json::Deserializer::from_str(&json));
        if let Err(e) = &result {
            debug!("Error: {}", e);
        }
        assert!(result.is_ok());
        if immutable {
            assert_eq!(final_path, PathBuf::from(&filename).canonicalize().ok());
            assert_eq!(cmd_min, CmdMin::MATCH);
        } else {
            assert_eq!(final_path, None);
            assert_eq!(cmd_min, CmdMin::empty());
        }
    }

    fn toggle_immutable_config(path : &impl AsRef<Path>, lock: bool) -> io::Result<()> {
        let file = File::open(path)?;
        let mut val = 0;
        if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut val) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if lock {
            val |= FS_IMMUTABLE_FL;
        } else {
            val &= !(FS_IMMUTABLE_FL);
        }
        immutable_required_privileges(&file, || {
            if unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_SETFLAGS, &mut val) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
    }
}
