mod hashchecker;
mod ssd;
mod hierarchy;

pub(crate) fn register_plugins() {
    hashchecker::register();
    ssd::register();
    hierarchy::register();
}