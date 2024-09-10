#[cfg(feature = "finder")]
mod hashchecker;
#[cfg(feature = "finder")]
mod hierarchy;
#[cfg(feature = "finder")]
mod ssd;

pub fn register_plugins() {
    #[cfg(feature = "finder")]
    hashchecker::register();
    #[cfg(feature = "finder")]
    ssd::register();
    #[cfg(feature = "finder")]
    hierarchy::register();
}
