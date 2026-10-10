//! Single place for product naming (rename here + Cargo.toml + assets/app.rc).

pub const APP_NAME: &str = "Poof";
pub const APP_DIR: &str = "Poof";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const WINDOW_CLASS: &str = "PoofMainWindow";
pub const MUTEX_NAME: &str = "Local\\Poof.SingleInstance";
