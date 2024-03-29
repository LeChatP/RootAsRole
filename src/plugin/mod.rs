mod hashchecker;
mod ssd;

pub fn register_plugins() {
    hashchecker::register();
    ssd::register();
}