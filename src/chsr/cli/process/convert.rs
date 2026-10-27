use rootasrole_core::println_ignore_io_error;
use std::{
    cell::RefCell,
    error::Error,
    path::{Path, PathBuf},
    rc::Rc,
};

use log::{debug, error, warn};
use rootasrole_core::{
    database::{structs::SPolicy, versionning::Versioning},
    file::{FileSettings, LockedSettingsFile},
    util::{RAR_CFG_TYPE, StorageMethod, with_mutable_dir},
};

use crate::{cli::data::Convertion, util::RAR_CFG_IMMUTABLE};

/// A policy, with the file that holds it.
type PolicyAndFile = (Rc<RefCell<SPolicy>>, PathBuf);

/// The policy that `chsr convert` converts without `--from`, with the file that holds it: the
/// root file, or the one policy file that the root file names. A policy directory holds several
/// files, which are converted one by one with `--from`.
fn current_policy(settings: &FileSettings) -> Result<PolicyAndFile, Box<dyn Error>> {
    if in_a_directory(settings) {
        return Err(
            "the policy is a directory of files: convert one of them with --from <type> <file>"
                .into(),
        );
    }
    Ok(match settings.policy_files().next() {
        Some((path, policy)) => (policy.clone(), path.to_path_buf()),
        None => (
            settings.get_root().config.clone(),
            settings.root_path().to_path_buf(),
        ),
    })
}

/// Whether the root file names a directory of policy files.
fn in_a_directory(settings: &FileSettings) -> bool {
    settings
        .get_root()
        .storage
        .settings
        .as_ref()
        .and_then(|storage| storage.path.as_ref())
        .is_some_and(|path| path.is_dir())
}

/// Write `config` in a new file `to`, in the format `to_type`.
fn write_policy(
    to: &Path,
    to_type: StorageMethod,
    config: &Rc<RefCell<SPolicy>>,
) -> Result<(), Box<dyn Error>> {
    debug!("Writing the policy to {}", to.display());
    // the destination may be a new file in an immutable policy directory
    let parent = to
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut file = with_mutable_dir(&parent, || {
        LockedSettingsFile::open_write(to, |_, _| Ok(Versioning::new(config.clone())))
    })?;
    file.save(to_type, RAR_CFG_IMMUTABLE)?;
    Ok(())
}

/// `chsr convert`: write the policy in the format `convertion.to_type`, in the file
/// `convertion.to`. With `--reconfigure`, the root file then names that file, so that dosr reads
/// it; naming the root file itself puts the policy back into it.
pub fn convert(
    settings: &mut FileSettings,
    convertion: Convertion,
    convert_reconfigure: bool,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr convert");
    let root_path = settings.root_path().to_path_buf();
    let (config, from) = match convertion.from {
        Some(ref from) => {
            debug!("Convert from: {}", from.display());
            let from_type = convertion.from_type.ok_or("--from needs a type")?;
            if from == &convertion.to {
                error!("The source and destination paths are the same");
                return Ok(false);
            }
            if from == &root_path {
                (settings.get_root().config.clone(), from.clone())
            } else if let Some(policy) = settings.get(from) {
                (policy.clone(), from.clone())
            } else {
                (
                    FileSettings::read_policy(from, from_type)?.data.data,
                    from.clone(),
                )
            }
        }
        None => current_policy(settings)?,
    };
    println_ignore_io_error!(
        "Config : {}",
        serde_json::to_string_pretty(&Versioning::new(config.clone()))?
    );
    if convert_reconfigure && in_a_directory(settings) {
        return Err("a policy directory cannot be reconfigured into one file: convert its files one by one with --from, then change the root file".into());
    }
    if convertion.to == root_path {
        if !convert_reconfigure {
            error!(
                "You are overwriting the root settings file but you did not specify the reconfigure (-r) option, this would break the current configuration"
            );
            return Ok(false);
        }
        if convertion.to_type != RAR_CFG_TYPE {
            error!(
                "The general settings file cannot be converted to another format than {RAR_CFG_TYPE}\nThis file is used to determine the policy location and format. Please specify another path.",
            );
            return Ok(false);
        }
        // the policy comes back into the root file, which dosr reads
        let root = settings.get_root_mut();
        root.config = config;
        root.storage.method = convertion.to_type;
        root.storage
            .settings
            .get_or_insert_default()
            .path
            .replace(root_path);
        return Ok(true);
    }
    if convertion.to == from || settings.get(&convertion.to).is_some() {
        error!(
            "{} is a file of the current policy: write the converted policy to another file",
            convertion.to.display()
        );
        return Ok(false);
    }
    write_policy(&convertion.to, convertion.to_type, &config)?;
    if convert_reconfigure {
        debug!("The root settings now name {}", convertion.to.display());
        if from != root_path && settings.get(&from).is_none() {
            warn!(
                "The policy is now the one of {}, converted: the current policy is not used anymore",
                from.display()
            );
        }
        // the policy is in that file now: the root file only says where it is, and its format
        let root = settings.get_root_mut();
        root.config = Rc::new(RefCell::new(SPolicy::default()));
        root.storage.method = convertion.to_type;
        root.storage
            .settings
            .get_or_insert_default()
            .path
            .replace(convertion.to);
    }
    Ok(true)
}
