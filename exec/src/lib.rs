pub mod event;
pub mod monitor;
pub mod orchestrator;
pub mod pipe;
pub mod pty;
pub mod runner;
pub mod signal;
pub mod terminal;
pub mod types;

#[cfg(test)]
pub static MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
