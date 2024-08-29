mod hashchecker;
mod hierarchy;
mod ssd;

pub fn register_plugins() {
    hashchecker::register();
    ssd::register();
    hierarchy::register();
}
