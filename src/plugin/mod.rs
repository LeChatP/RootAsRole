mod hashchecker;
mod hierarchy;
mod ssd;

pub(crate) fn register_plugins() {
    hashchecker::register();
    ssd::register();
    hierarchy::register();
}
