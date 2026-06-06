use std::{
    error::Error,
    path::{Path, PathBuf},
};

use log::{debug, error};
use rar_common::{
    RemoteStorageSettings,
    database::versionning::Versioning,
    file::{FileSettings, LockedSettingsFile},
    util::RAR_CFG_TYPE,
};

use crate::{
    cli::data::Convertion,
    util::{RAR_CFG_IMMUTABLE, RAR_CFG_PATH},
};

pub fn convert(
    settings: &mut FileSettings,
    convertion: Convertion,
    convert_reconfigure: bool,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr convert");
    let default = RemoteStorageSettings::default();
    let binding = PathBuf::from(RAR_CFG_PATH);
    let rar_data_path = settings
        .get_root()
        .storage
        .settings
        .as_ref()
        .unwrap_or(&default)
        .path
        .as_ref()
        .unwrap_or(&binding);
    let config = match convertion.from {
        Some(ref from) => {
            debug!("Convert from: {}", from.display());
            let from_type = convertion.from_type.expect("Impossible state");
            if from == &convertion.to {
                error!("The source and destination paths are the same");
                return Ok(false);
            }
            if from == rar_data_path {
                settings
                    .get_root()
                    .config
                    .as_ref()
                    .expect("A configuration should be loaded")
                    .clone()
            } else {
                FileSettings::read_policy(from, from_type)?.data.data
            }
        }
        None => settings
            .get_root()
            .config
            .as_ref()
            .expect("A configuration should be loaded")
            .clone(),
    };
    println!(
        "Config : {}",
        serde_json::to_string_pretty(&Versioning::new(config.clone()))?
    );
    if !convert_reconfigure && convertion.to != *rar_data_path {
        debug!(
            "Writing configuration to new file : {}",
            convertion.to.display()
        );
        let mut c = LockedSettingsFile::open_write(convertion.to, |_, _| {
            Ok(Versioning::new(config.clone()))
        })?;
        c.save(convertion.to_type, RAR_CFG_IMMUTABLE)?;

        Ok(true)
    } else if convert_reconfigure {
        if convertion.to_type != RAR_CFG_TYPE && convertion.to == Path::new(RAR_CFG_PATH) {
            error!(
                "The general settings file cannot be converted to another format than {RAR_CFG_TYPE}\nThis file is used to determine the policy location and format. Please specify another path.",
            );
            return Ok(false);
        }
        debug!("Overwriting current configuration file");
        settings.get_root_mut().storage.method = convertion.to_type;
        settings
            .get_root_mut()
            .storage
            .settings
            .get_or_insert_default()
            .path
            .replace(convertion.to);
        Ok(true)
    } else {
        error!(
            "You are overwriting the current configuration file but you not specified the reconfigure (-r) option, this would break the current configuration"
        );
        Ok(false)
    }
}
