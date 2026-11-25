//! Settings in `nix.conf` syntax: `name = value` lines, `#` comments,
//! `include`/`!include` of further files, and `extra-<name>` to append to
//! a list setting.

use std::fs;
use std::path::{Path, PathBuf};

use crate::Result;

pub const DEFAULT_CACHE: &str = "https://cache.nixos.org";
pub const DEFAULT_CACHE_KEY: &str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub substituters: Vec<String>,
    pub trusted_public_keys: Vec<String>,
    pub require_sigs: bool,
    /// Whether `realise` and `storePath` may use substituters at all.
    pub substitute: bool,
    pub secret_key_files: Vec<String>,
    pub max_substitution_jobs: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            substituters: vec![DEFAULT_CACHE.into()],
            trusted_public_keys: vec![DEFAULT_CACHE_KEY.into()],
            require_sigs: true,
            substitute: true,
            secret_key_files: Vec::new(),
            max_substitution_jobs: 16,
        }
    }
}

fn parse_bool(name: &str, v: &str) -> Result<bool> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("invalid Boolean value '{v}' for setting '{name}'")),
    }
}

fn words(v: &str) -> Vec<String> {
    v.split_whitespace().map(str::to_string).collect()
}

impl Settings {
    /// Whether `name` (without an `extra-` prefix) is a setting with a
    /// Boolean value, so that `--name`/`--no-name` flags apply to it.
    pub fn is_bool(name: &str) -> bool {
        matches!(name, "require-sigs" | "substitute")
    }

    pub fn is_known(name: &str) -> bool {
        let base = name.strip_prefix("extra-").unwrap_or(name);
        matches!(
            base,
            "substituters" | "trusted-public-keys" | "require-sigs" | "substitute" | "secret-key-files" | "max-substitution-jobs"
        )
    }

    /// Applies one setting; unknown names produce a warning, like Nix.
    pub fn set(&mut self, name: &str, value: &str) -> Result<()> {
        let (base, extra) = match name.strip_prefix("extra-") {
            Some(b) => (b, true),
            None => (name, false),
        };
        let list = match base {
            "substituters" => &mut self.substituters,
            "trusted-public-keys" => &mut self.trusted_public_keys,
            "secret-key-files" => &mut self.secret_key_files,
            "require-sigs" if !extra => {
                self.require_sigs = parse_bool(name, value)?;
                return Ok(());
            }
            "substitute" if !extra => {
                self.substitute = parse_bool(name, value)?;
                return Ok(());
            }
            "max-substitution-jobs" if !extra => {
                self.max_substitution_jobs =
                    value.parse().map_err(|_| format!("invalid integer '{value}' for setting '{name}'"))?;
                return Ok(());
            }
            _ => {
                eprintln!("warning: unknown setting '{name}'");
                return Ok(());
            }
        };
        if extra {
            list.extend(words(value));
        } else {
            *list = words(value);
        }
        Ok(())
    }

    /// Applies the settings in `text`; `base` resolves relative includes.
    pub fn apply_text(&mut self, text: &str, base: &Path) -> Result<()> {
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut toks = line.split_whitespace();
            match toks.next() {
                Some(kw @ ("include" | "!include")) => {
                    let f = toks.next().ok_or_else(|| format!("syntax error in configuration line '{raw}'"))?;
                    let p = base.join(f);
                    match fs::read_to_string(&p) {
                        Ok(t) => self.apply_text(&t, p.parent().unwrap_or(base))?,
                        Err(_) if kw == "!include" => {}
                        Err(e) => return Err(format!("reading '{}': {e}", p.display())),
                    }
                    continue;
                }
                _ => {}
            }
            let (k, v) = line.split_once('=').ok_or_else(|| format!("illegal configuration line '{raw}'"))?;
            self.set(k.trim(), v.trim())?;
        }
        Ok(())
    }

    /// The defaults, overridden by `$XDG_CONFIG_HOME/oxnix/oxnix.conf`
    /// (default `~/.config/oxnix/oxnix.conf`) and then by the settings in
    /// `$OXNIX_CONFIG`.
    pub fn load() -> Result<Settings> {
        let mut s = Settings::default();
        let path = config_file();
        if let Ok(t) = fs::read_to_string(&path) {
            s.apply_text(&t, path.parent().unwrap_or(Path::new("/")))?;
        }
        if let Ok(t) = std::env::var("OXNIX_CONFIG") {
            s.apply_text(&t, Path::new("/"))?;
        }
        Ok(s)
    }
}

pub fn config_file() -> PathBuf {
    let dir = match std::env::var("XDG_CONFIG_HOME") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into())).join(".config"),
    };
    dir.join("oxnix/oxnix.conf")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nix_conf_syntax() {
        let dir = std::env::temp_dir().join(format!("oxnix-conf-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("more.conf"), "extra-trusted-public-keys = k:AAAA\n").unwrap();
        let mut s = Settings::default();
        s.apply_text(
            "# comment\nsubstituters = file:///a  https://b # trailing\nrequire-sigs = false\n\
             include more.conf\n!include missing.conf\nextra-substituters = file:///c\n",
            &dir,
        )
        .unwrap();
        assert_eq!(s.substituters, ["file:///a", "https://b", "file:///c"]);
        assert_eq!(s.trusted_public_keys, [DEFAULT_CACHE_KEY, "k:AAAA"]);
        assert!(!s.require_sigs);
        assert!(s.apply_text("require-sigs = maybe", &dir).is_err());
        assert!(s.apply_text("include missing.conf", &dir).is_err());
        assert!(s.apply_text("no equals sign", &dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
