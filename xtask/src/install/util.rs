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