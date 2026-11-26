//! Fetcher settings: `tarball-ttl`, `flake-registry`, `access-tokens` and
//! the dirty-tree policy, read from `nix.conf` and `NIX_CONFIG` and
//! adjustable by the command line.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Debug)]
pub struct Settings {
    /// Seconds a cached download or ref lookup stays fresh.
    pub tarball_ttl: u64,
    /// URL or path of the global flake registry; empty disables it.
    pub flake_registry: String,
    /// Host to token, sent to GitHub, GitLab and SourceHut.
    pub access_tokens: BTreeMap<String, String>,
    pub allow_dirty: bool,
    pub warn_dirty: bool,
    pub use_registries: bool,
    pub nix_conf_dir: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            tarball_ttl: 3600,
            flake_registry: "https://channels.nixos.org/flake-registry.json".into(),
            access_tokens: BTreeMap::new(),
            allow_dirty: true,
            warn_dirty: true,
            use_registries: true,
            nix_conf_dir: std::env::var("NIX_CONF_DIR").unwrap_or_else(|_| "/etc/nix".into()),
        }
    }
}

fn global() -> &'static Mutex<Settings> {
    static S: OnceLock<Mutex<Settings>> = OnceLock::new();
    S.get_or_init(|| {
        let mut s = Settings::default();
        s.load_config();
        Mutex::new(s)
    })
}

pub fn settings() -> Settings {
    global().lock().unwrap().clone()
}

pub fn set_settings(f: impl FnOnce(&mut Settings)) {
    f(&mut global().lock().unwrap());
}

pub fn config_dir() -> String {
    std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{}/.config", std::env::var("HOME").unwrap_or_default()))
}

impl Settings {
    /// Applies `key = value` lines of the system and user `nix.conf` and
    /// of `NIX_CONFIG`, in that order.
    fn load_config(&mut self) {
        let mut texts = Vec::new();
        for f in [format!("{}/nix.conf", self.nix_conf_dir), format!("{}/nix/nix.conf", config_dir())] {
            if let Ok(t) = std::fs::read_to_string(f) {
                texts.push(t);
            }
        }
        if let Ok(t) = std::env::var("NIX_CONFIG") {
            texts.push(t);
        }
        for t in texts {
            for line in t.lines() {
                let line = line.split('#').next().unwrap_or("");
                if let Some((k, v)) = line.split_once('=') {
                    self.set(k.trim(), v.trim());
                }
            }
        }
    }

    /// Sets one option by its `nix.conf` name; unknown names are ignored.
    pub fn set(&mut self, key: &str, value: &str) {
        let bool_val = || matches!(value, "true" | "1" | "yes");
        match key.strip_prefix("extra-").unwrap_or(key) {
            "tarball-ttl" => {
                if let Ok(n) = value.parse() {
                    self.tarball_ttl = n;
                }
            }
            "flake-registry" => self.flake_registry = value.to_string(),
            "access-tokens" => {
                for tok in value.split_whitespace() {
                    if let Some((h, t)) = tok.split_once('=') {
                        self.access_tokens.insert(h.to_string(), t.to_string());
                    }
                }
            }
            "allow-dirty" => self.allow_dirty = bool_val(),
            "warn-dirty" => self.warn_dirty = bool_val(),
            "use-registries" => self.use_registries = bool_val(),
            _ => {}
        }
    }
}
