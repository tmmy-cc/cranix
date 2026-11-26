//! The fetcher settings in effect for this process. The command line
//! installs the `fetch` part of its configuration with [`set_settings`];
//! until then the defaults apply.

use std::sync::{Mutex, OnceLock};

pub use cranix_store::settings::FetchSettings as Settings;

fn global() -> &'static Mutex<Settings> {
    static S: OnceLock<Mutex<Settings>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Settings::default()))
}

pub fn settings() -> Settings {
    global().lock().unwrap().clone()
}

pub fn set_settings(f: impl FnOnce(&mut Settings)) {
    f(&mut global().lock().unwrap());
}

/// `$XDG_CONFIG_HOME`, by default `~/.config`.
pub fn config_dir() -> String {
    std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{}/.config", std::env::var("HOME").unwrap_or_default()))
}
