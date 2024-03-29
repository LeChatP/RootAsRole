pub mod util;
pub mod version;
pub mod database;
pub mod config;
pub mod api;

mod plugin;

trait With {
    fn with<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut Self) -> &mut Self,
        Self: Sized,
    {
        f(self);
        self
    }
}