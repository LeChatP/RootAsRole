// This file is generated by build.rs
// Do not edit this file directly
// Instead edit build.rs and run cargo build
use capctl::Cap;
#[rustfmt::skip]
#[allow(clippy::all)] 
pub fn get_capability_description(cap : &Cap) -> &'static str {
    match *cap {
       _ => "Unknown capability",
    }
}