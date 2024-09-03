use std::{fs, io};

use capctl::Cap;

pub fn cap_clear(state: &mut capctl::CapState) -> Result<(), anyhow::Error> {
    state.effective.clear();
    state.set_current()?;
    Ok(())
}

pub fn cap_effective(state: &mut capctl::CapState, cap: Cap) -> Result<(), anyhow::Error> {
    state.effective.clear();
    state.effective.add(cap);
    state.set_current()?;
    Ok(())
}

pub fn files_are_equal(path1: &str, path2: &str) -> io::Result<bool> {
    let file1_content = fs::read(path1)?;
    let file2_content = fs::read(path2)?;

    Ok(file1_content == file2_content)
}