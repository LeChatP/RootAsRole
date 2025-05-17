use std::{
    cell::RefCell,
    error::Error,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
    rc::Rc,
};

use log::{debug, error};
use rar_common::{retrieve_sconfig, FullSettingsFile, StorageMethod};

use crate::{cli::data::Convertion, ROOTASROLE};

pub fn convert(
    settings: &Rc<RefCell<FullSettingsFile>>,
    convertion: Convertion,
    convert_reconfigure: bool,
) -> Result<bool, Box<dyn Error>> {
    debug!("chsr convert");
    let mut settings = settings.borrow_mut();
    let default = Default::default();
    let default_path = Default::default();
    let path = settings
        .storage
        .settings
        .as_ref()
        .unwrap_or(&default)
        .path
        .as_ref()
        .unwrap_or(&default_path);
    let config = match convertion.from {
        Some(ref from) => {
            debug!("Convert from: {:?}", from);
            let from_type = convertion.from_type.expect("Impossible state");
            if from == &convertion.to {
                error!("The source and destination paths are the same");
                return Ok(false);
            }
            if from != path {
                retrieve_sconfig(&from_type, from)?
            } else {
                settings
                    .config
                    .as_ref()
                    .expect("A configuration should be loaded")
                    .clone()
            }
        }
        None => settings
            .config
            .clone()
            .expect("A configuration should be loaded"),
    };
    if !convert_reconfigure && convertion.to != *path {
        write_config_file(&convertion, config)
    } else if convert_reconfigure {
        if convertion.to_type != StorageMethod::JSON && convertion.to == Path::new(ROOTASROLE) {
            error!("The general settings file cannot be converted to another format than JSON\nThis file is used to determine the policy location and format. Please specify another path.");
            return Ok(false);
        }
        settings.storage.method = convertion.to_type;
        let mut remote = settings.storage.settings.clone().unwrap_or_default();
        remote.path = Some(convertion.to);
        settings.storage.settings = Some(remote);
        Ok(true)
    } else {
        error!("You are overwriting the current configuration file but you not specified the reconfigure (-r) option, this would break the current configuration");
        Ok(false)
    }
}

fn write_config_file(
    convertion: &Convertion,
    config: Rc<RefCell<rar_common::database::structs::SConfig>>,
) -> Result<bool, Box<dyn Error>> {
    match convertion.to_type {
        StorageMethod::JSON => {
            let json = serde_json::to_string_pretty(&config)?;
            let file = File::create(&convertion.to)?;
            let mut writer = BufWriter::new(file);
            writer.write_all(json.as_bytes())?;
        }
        StorageMethod::CBOR => {
            let file = File::create(&convertion.to)?;
            let writer = BufWriter::new(file);
            cbor4ii::serde::to_writer(writer, &config)?;
        }
    }
    Ok(false)
}
