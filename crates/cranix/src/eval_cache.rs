//! Evaluation cache for flake installables.
//!
//! Results of `eval`, `build` and `instantiate` on a flake installable are
//! stored in one JSON file per locked flake under
//! `$XDG_CACHE_HOME/cranix/eval-cache-v1` (or `~/.cache/cranix/...`), named
//! by the flake's fingerprint. Within a file, an entry is keyed by the
//! command kind, output mode, system, store directory and attribute
//! fragment. A flake without a fingerprint (a dirty tree or an unlocked
//! input) and impure evaluation get no cache; the `eval-cache` setting
//! (`--no-eval-cache`) turns it off.

use std::path::PathBuf;

use cranix_eval::flake::LockedFlake;
use cranix_eval::Eval;

const FORMAT: &str = "eval-cache-v1";

pub struct EvalCache {
    path: PathBuf,
    key: String,
}

impl EvalCache {
    /// The cache entry for `what` (command kind and output mode) and
    /// fragment `frag` of the locked flake, or `None` when the cache does
    /// not apply.
    pub fn open(cli: &crate::Cli, ev: &Eval, impure: bool, locked: &LockedFlake, what: &str, frag: &str) -> Option<EvalCache> {
        if impure || !ev.opts.pure || !cli.settings.eval_cache || locked.flake.force_dirty {
            return None;
        }
        let fp = locked.fingerprint(&ev.store)?;
        let base = match std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
            Some(d) => PathBuf::from(d),
            None => PathBuf::from(std::env::var_os("HOME").filter(|v| !v.is_empty())?).join(".cache"),
        };
        let key = format!("{what}\u{0}{}\u{0}{}\u{0}{frag}", cli.system(), ev.store.dir.as_str());
        Some(EvalCache { path: base.join("cranix").join(FORMAT).join(format!("{fp}.json")), key })
    }

    fn read(&self) -> serde_json::Map<String, serde_json::Value> {
        std::fs::read(&self.path)
            .ok()
            .and_then(|d| serde_json::from_slice::<serde_json::Value>(&d).ok())
            .and_then(|v| match v {
                serde_json::Value::Object(m) => Some(m),
                _ => None,
            })
            .unwrap_or_default()
    }

    pub fn get(&self) -> Option<serde_json::Value> {
        self.read().remove(&self.key)
    }

    /// Adds the entry to the file; failures leave the cache without it.
    pub fn put(&self, value: serde_json::Value) {
        let Some(dir) = self.path.parent() else { return };
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
        let mut m = self.read();
        m.insert(self.key.clone(), value);
        let tmp = self.path.with_extension(format!("json.{}", std::process::id()));
        let data = serde_json::Value::Object(m).to_string();
        if std::fs::write(&tmp, data).is_ok() && std::fs::rename(&tmp, &self.path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// Whether every `.drv` store path mentioned in `s` is valid in the store,
/// so a cached result never names a derivation the store lacks.
pub fn drvs_valid(ev: &Eval, s: &str) -> bool {
    let dir = format!("{}/", ev.store.dir.as_str());
    let mut rest = s;
    while let Some(i) = rest.find(&dir) {
        let tail = &rest[i..];
        let end = tail[dir.len()..].find(|c: char| !(c.is_ascii_alphanumeric() || "+-._?=".contains(c))).map_or(tail.len(), |e| e + dir.len());
        let p = &tail[..end];
        if p.ends_with(".drv") {
            match ev.store.dir.parse(p) {
                Ok(sp) if ev.store.is_valid(&sp) => {}
                _ => return false,
            }
        }
        rest = &tail[end..];
    }
    true
}
