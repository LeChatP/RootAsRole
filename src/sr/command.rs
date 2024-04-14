use std::{
    env::var, error::Error, path::{Path, PathBuf}
};

use shell_words::ParseError;

use crate::common::{api::PluginManager, database::structs::SCommand};


