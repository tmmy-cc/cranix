//! The configuration: Nix's settings in `nix.conf` syntax (`name = value`
//! lines, `#` comments, `include`/`!include` of further files, and
//! `extra-<name>` to append to a list setting), read from the same places
//! as Nix and in the same order, followed by cranix's own files:
//!
//! 1. `$NIX_CONF_DIR/nix.conf` (default `/etc/nix/nix.conf`)
//! 2. the user files: `$NIX_USER_CONF_FILES`, or else `nix/nix.conf` in
//!    `$XDG_CONFIG_DIRS` and `$XDG_CONFIG_HOME` (default `~/.config`)
//! 3. `$XDG_CONFIG_HOME/cranix/cranix.conf`
//! 4. the text of `$CRANIX_CONFIG`
//! 5. the text of `$NIX_CONFIG`
//!
//! The command line (`--option`, `--NAME VALUE`, `--[no-]NAME`,
//! `--extra-NAME VALUE`) applies on top through [`Settings::set`]. Builds,
//! substitution, fetchers, experimental features and the daemon all take
//! their configuration from one [`Settings`] value.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::binary_cache::redact_url;
use crate::build::BuildOptions;
use crate::Result;

pub const DEFAULT_CACHE: &str = "https://cache.nixos.org";
pub const DEFAULT_CACHE_KEY: &str = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";

/// The shape of a setting's value, which decides the command line flags
/// it gets: `--NAME`/`--no-NAME` for Booleans, `--NAME VALUE` for the
/// others and `--extra-NAME VALUE` for lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bool,
    List,
    Value,
}

/// Every setting of Nix 2.24, with its deprecated aliases. Settings in this
/// table that cranix does not use are accepted silently, so that the
/// system's `nix.conf` loads without warnings.
const NIX_SETTINGS: &[(&str, Kind)] = {
    use Kind::*;
    &[
        ("accept-flake-config", Bool),
        ("access-tokens", List),
        ("allow-dirty", Bool),
        ("allow-import-from-derivation", Bool),
        ("allow-new-privileges", Bool),
        ("allow-symlinked-store", Bool),
        ("allow-unsafe-native-code-during-evaluation", Bool),
        ("allowed-impure-host-deps", List),
        ("allowed-uris", List),
        ("allowed-users", List),
        ("always-allow-substitutes", Bool),
        ("auto-allocate-uids", Bool),
        ("auto-optimise-store", Bool),
        ("bash-prompt", Value),
        ("bash-prompt-prefix", Value),
        ("bash-prompt-suffix", Value),
        ("binary-cache-public-keys", List),
        ("binary-caches", List),
        ("build-chroot-dirs", List),
        ("build-cores", Value),
        ("build-dir", Value),
        ("build-extra-platforms", List),
        ("build-fallback", Bool),
        ("build-hook", List),
        ("build-max-jobs", Value),
        ("build-max-log-size", Value),
        ("build-max-silent-time", Value),
        ("build-poll-interval", Value),
        ("build-sandbox-paths", List),
        ("build-timeout", Value),
        ("build-use-chroot", Bool),
        ("build-use-sandbox", Bool),
        ("build-use-substitutes", Bool),
        ("build-users-group", Value),
        ("builders", Value),
        ("builders-use-substitutes", Bool),
        ("commit-lock-file-summary", Value),
        ("compress-build-log", Bool),
        ("connect-timeout", Value),
        ("cores", Value),
        ("darwin-log-sandbox-violations", Bool),
        ("debugger-on-trace", Bool),
        ("diff-hook", Value),
        ("download-attempts", Value),
        ("download-buffer-size", Value),
        ("download-speed", Value),
        ("env-keep-derivations", Bool),
        ("eval-cache", Bool),
        ("eval-system", Value),
        ("experimental-features", List),
        ("extra-platforms", List),
        ("fallback", Bool),
        ("filter-syscalls", Bool),
        ("flake-registry", Value),
        ("fsync-metadata", Bool),
        ("gc-keep-derivations", Bool),
        ("gc-keep-outputs", Bool),
        ("gc-reserved-space", Value),
        ("hashed-mirrors", List),
        ("http-connections", Value),
        ("http2", Bool),
        ("id-count", Value),
        ("ignore-try", Bool),
        ("ignored-acls", List),
        ("impersonate-linux-26", Bool),
        ("impure-env", List),
        ("keep-build-log", Bool),
        ("keep-derivations", Bool),
        ("keep-env-derivations", Bool),
        ("keep-failed", Bool),
        ("keep-going", Bool),
        ("keep-outputs", Bool),
        ("log-lines", Value),
        ("max-build-log-size", Value),
        ("max-call-depth", Value),
        ("max-free", Value),
        ("max-jobs", Value),
        ("max-silent-time", Value),
        ("max-substitution-jobs", Value),
        ("min-free", Value),
        ("min-free-check-interval", Value),
        ("nar-buffer-size", Value),
        ("narinfo-cache-negative-ttl", Value),
        ("narinfo-cache-positive-ttl", Value),
        ("netrc-file", Value),
        ("nix-path", List),
        ("plugin-files", List),
        ("post-build-hook", Value),
        ("pre-build-hook", Value),
        ("preallocate-contents", Bool),
        ("print-missing", Bool),
        ("pure-eval", Bool),
        ("require-drop-supplementary-groups", Bool),
        ("require-sigs", Bool),
        ("restrict-eval", Bool),
        ("run-diff-hook", Bool),
        ("sandbox", Bool),
        ("sandbox-build-dir", Value),
        ("sandbox-dev-shm-size", Value),
        ("sandbox-fallback", Bool),
        ("sandbox-paths", List),
        ("secret-key-files", List),
        ("show-trace", Bool),
        ("ssl-cert-file", Value),
        ("stalled-download-timeout", Value),
        ("start-id", Value),
        ("store", Value),
        ("substitute", Bool),
        ("substituters", List),
        ("sync-before-registering", Bool),
        ("system", Value),
        ("system-features", List),
        ("tarball-ttl", Value),
        ("timeout", Value),
        ("trace-function-calls", Bool),
        ("trace-verbose", Bool),
        ("trusted-binary-caches", List),
        ("trusted-public-keys", List),
        ("trusted-substituters", List),
        ("trusted-users", List),
        ("upgrade-nix-store-path-url", Value),
        ("upload-jobs", Value),
        ("upload-required", Bool),
        ("upload-to", Value),
        ("use-case-hack", Bool),
        ("use-cgroups", Bool),
        ("use-registries", Bool),
        ("use-sqlite-wal", Bool),
        ("use-xdg-base-directories", Bool),
        ("user-agent-suffix", Value),
        ("warn-dirty", Bool),
    ]
};

/// Settings of the fetchers and the flake registry.
#[derive(Clone, Debug)]
pub struct FetchSettings {
    /// Seconds a cached download or ref lookup stays fresh.
    pub tarball_ttl: u64,
    /// URL or path of the global flake registry; empty disables it.
    pub flake_registry: String,
    /// Host to token, sent to GitHub, GitLab and SourceHut.
    pub access_tokens: BTreeMap<String, String>,
    pub allow_dirty: bool,
    pub warn_dirty: bool,
    pub use_registries: bool,
    /// The directory of the system `nix.conf` and `registry.json`.
    pub nix_conf_dir: String,
}

impl Default for FetchSettings {
    fn default() -> Self {
        FetchSettings {
            tarball_ttl: 3600,
            flake_registry: "https://channels.nixos.org/flake-registry.json".into(),
            access_tokens: BTreeMap::new(),
            allow_dirty: true,
            warn_dirty: true,
            use_registries: true,
            nix_conf_dir: nix_conf_dir().to_string_lossy().into_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub substituters: Vec<String>,
    pub trusted_public_keys: Vec<String>,
    pub require_sigs: bool,
    /// Whether `realise` and `storePath` may use substituters at all.
    pub substitute: bool,
    pub secret_key_files: Vec<String>,
    pub max_substitution_jobs: usize,
    /// Seconds for which a cache's answer that it has a path, or that it
    /// does not, is remembered.
    pub narinfo_cache_positive_ttl: u64,
    pub narinfo_cache_negative_ttl: u64,
    /// Credentials for HTTP caches, used when the file exists.
    pub netrc_file: String,
    /// How many times an HTTP request is tried before giving up.
    pub download_attempts: u32,
    pub experimental_features: BTreeSet<String>,
    /// Remote builders in the machines format, or `@FILE`.
    pub builders: String,
    /// Users (or `@group`s, or `*`) the daemon trusts.
    pub trusted_users: Vec<String>,
    /// Users allowed to connect to the daemon.
    pub allowed_users: Vec<String>,
    /// The build settings; `system` is also `builtins.currentSystem`.
    pub build: BuildOptions,
    pub fetch: FetchSettings,
    /// The cache builds upload each output to; empty for none.
    pub upload_to: String,
    /// How many uploads run at once.
    pub upload_jobs: usize,
    /// Whether a failed upload fails the build.
    pub upload_required: bool,
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
            narinfo_cache_positive_ttl: crate::narinfo_cache::DEFAULT_POSITIVE_TTL,
            narinfo_cache_negative_ttl: crate::narinfo_cache::DEFAULT_NEGATIVE_TTL,
            netrc_file: config_dir().join("netrc").to_string_lossy().into_owned(),
            download_attempts: 5,
            experimental_features: BTreeSet::new(),
            builders: format!("@{}", nix_conf_dir().join("machines").display()),
            trusted_users: vec!["root".into()],
            allowed_users: vec!["*".into()],
            build: BuildOptions::default(),
            fetch: FetchSettings::default(),
            upload_to: String::new(),
            upload_jobs: 4,
            upload_required: false,
        }
    }
}

/// Parses a Boolean the way Nix does.
pub fn parse_bool(name: &str, v: &str) -> Result<bool> {
    match v {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(format!("Boolean setting '{name}' has invalid value '{v}'")),
    }
}

fn parse_int<T: std::str::FromStr>(name: &str, v: &str) -> Result<T> {
    v.parse().map_err(|_| format!("setting '{name}' has invalid value '{v}'"))
}

fn words(v: &str) -> Vec<String> {
    v.split_whitespace().map(str::to_string).collect()
}

fn set_list(list: &mut Vec<String>, extra: bool, value: &str) {
    if !extra {
        list.clear();
    }
    list.extend(words(value));
}

/// Keeps the first of URLs that differ only in a trailing slash.
fn dedup_urls(urls: &mut Vec<String>) {
    let key = |u: &str| {
        let (base, query) = u.split_once('?').map_or((u, None), |(b, q)| (b, Some(q)));
        (base.trim_end_matches('/').to_string(), query.map(str::to_string))
    };
    let mut seen = BTreeSet::new();
    urls.retain(|u| seen.insert(key(u)));
}

/// Prints `warning: unknown setting 'NAME'` once per name and process.
fn warn_unknown(name: &str) {
    static WARNED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    if WARNED.lock().unwrap().insert(name.to_string()) {
        eprintln!("warning: unknown setting '{name}'");
    }
}

impl Settings {
    /// The kind of the setting `name` (without an `extra-` prefix), if Nix
    /// or cranix knows it.
    pub fn kind(name: &str) -> Option<Kind> {
        NIX_SETTINGS.iter().find(|(n, _)| *n == name).map(|(_, k)| *k)
    }

    /// Applies one setting. Unknown names produce a warning, like Nix.
    pub fn set(&mut self, name: &str, value: &str) -> Result<()> {
        if !self.apply(name, value)? {
            let base = name.strip_prefix("extra-").unwrap_or(name);
            let known = match Settings::kind(base) {
                Some(Kind::List) => true,
                Some(_) => base == name,
                None => false,
            };
            if !known {
                warn_unknown(name);
            }
        }
        Ok(())
    }

    /// Applies a setting cranix uses; `Ok(false)` for any other name.
    fn apply(&mut self, name: &str, value: &str) -> Result<bool> {
        let (base, extra) = match name.strip_prefix("extra-") {
            Some(b) => (b, true),
            None => (name, false),
        };
        match base {
            "substituters" | "binary-caches" => {
                set_list(&mut self.substituters, extra, value);
                dedup_urls(&mut self.substituters);
            }
            "trusted-public-keys" | "binary-cache-public-keys" => set_list(&mut self.trusted_public_keys, extra, value),
            "secret-key-files" => set_list(&mut self.secret_key_files, extra, value),
            "trusted-users" => set_list(&mut self.trusted_users, extra, value),
            "allowed-users" => set_list(&mut self.allowed_users, extra, value),
            "experimental-features" => {
                if !extra {
                    self.experimental_features.clear();
                }
                self.experimental_features.extend(words(value));
                self.sync_features();
            }
            "access-tokens" => {
                if !extra {
                    self.fetch.access_tokens.clear();
                }
                for tok in value.split_whitespace() {
                    if let Some((h, t)) = tok.split_once('=') {
                        self.fetch.access_tokens.insert(h.to_string(), t.to_string());
                    }
                }
            }
            _ if extra => return self.build.set(name, value),
            "require-sigs" => self.require_sigs = parse_bool(name, value)?,
            "substitute" | "build-use-substitutes" => {
                self.substitute = parse_bool(name, value)?;
                self.build.substitute = self.substitute;
            }
            "max-substitution-jobs" => self.max_substitution_jobs = parse_int(name, value)?,
            "narinfo-cache-positive-ttl" => self.narinfo_cache_positive_ttl = parse_int(name, value)?,
            "narinfo-cache-negative-ttl" => self.narinfo_cache_negative_ttl = parse_int(name, value)?,
            "netrc-file" => self.netrc_file = value.to_string(),
            "upload-to" => self.upload_to = value.to_string(),
            "upload-jobs" => self.upload_jobs = parse_int(name, value)?,
            "upload-required" => self.upload_required = parse_bool(name, value)?,
            "download-attempts" => self.download_attempts = parse_int(name, value)?,
            "builders" => self.builders = value.to_string(),
            "system" => self.build.system = value.to_string(),
            "tarball-ttl" => self.fetch.tarball_ttl = parse_int(name, value)?,
            "flake-registry" => self.fetch.flake_registry = value.to_string(),
            "allow-dirty" => self.fetch.allow_dirty = parse_bool(name, value)?,
            "warn-dirty" => self.fetch.warn_dirty = parse_bool(name, value)?,
            "use-registries" => self.fetch.use_registries = parse_bool(name, value)?,
            _ => return self.build.set(name, value),
        }
        Ok(true)
    }

    /// Copies the experimental features the builder acts on into it.
    fn sync_features(&mut self) {
        self.build.ca_derivations = self.experimental_features.contains("ca-derivations");
        self.build.impure_derivations = self.experimental_features.contains("impure-derivations");
    }

    /// The value of a setting cranix uses, as `nix.conf` would spell it.
    pub fn get(&self, name: &str) -> Option<String> {
        let list = |l: &[String]| l.join(" ");
        let b = &self.build;
        Some(match name {
            "substituters" => list(&self.substituters),
            "trusted-public-keys" => list(&self.trusted_public_keys),
            "secret-key-files" => list(&self.secret_key_files),
            "trusted-users" => list(&self.trusted_users),
            "allowed-users" => list(&self.allowed_users),
            "experimental-features" => self.experimental_features.iter().cloned().collect::<Vec<_>>().join(" "),
            "require-sigs" => self.require_sigs.to_string(),
            "substitute" => self.substitute.to_string(),
            "max-substitution-jobs" => self.max_substitution_jobs.to_string(),
            "narinfo-cache-positive-ttl" => self.narinfo_cache_positive_ttl.to_string(),
            "narinfo-cache-negative-ttl" => self.narinfo_cache_negative_ttl.to_string(),
            "netrc-file" => self.netrc_file.clone(),
            "upload-to" => self.upload_to.clone(),
            "upload-jobs" => self.upload_jobs.to_string(),
            "upload-required" => self.upload_required.to_string(),
            "download-attempts" => self.download_attempts.to_string(),
            "builders" => self.builders.clone(),
            "system" => b.system.clone(),
            "tarball-ttl" => self.fetch.tarball_ttl.to_string(),
            "flake-registry" => self.fetch.flake_registry.clone(),
            "allow-dirty" => self.fetch.allow_dirty.to_string(),
            "warn-dirty" => self.fetch.warn_dirty.to_string(),
            "use-registries" => self.fetch.use_registries.to_string(),
            "access-tokens" => self.fetch.access_tokens.iter().map(|(h, t)| format!("{h}={t}")).collect::<Vec<_>>().join(" "),
            "sandbox" => b.sandbox.name().to_string(),
            "sandbox-paths" => list(&b.sandbox_paths),
            "sandbox-fallback" => b.sandbox_fallback.to_string(),
            "sandbox-build-dir" => b.sandbox_build_dir.clone(),
            "sandbox-dev-shm-size" => b.sandbox_dev_shm_size.clone(),
            "allowed-impure-host-deps" => list(&b.allowed_impure_host_deps),
            "darwin-log-sandbox-violations" => b.darwin_log_sandbox_violations.to_string(),
            "system-features" => list(&b.system_features),
            "timeout" => b.timeout.to_string(),
            "max-silent-time" => b.max_silent_time.to_string(),
            "keep-failed" => b.keep_failed.to_string(),
            "max-jobs" => b.jobs.to_string(),
            "cores" => b.cores.to_string(),
            _ => return None,
        })
    }

    /// [`Settings::get`] with secrets hidden: substituter URLs through
    /// [`redact_url`] and the tokens of `access-tokens`.
    pub fn get_shown(&self, name: &str) -> Option<String> {
        match name {
            "substituters" => Some(self.substituters.iter().map(|u| redact_url(u)).collect::<Vec<_>>().join(" ")),
            "upload-to" => Some(redact_url(&self.upload_to)),
            "access-tokens" => Some(self.fetch.access_tokens.keys().map(|h| format!("{h}=<redacted>")).collect::<Vec<_>>().join(" ")),
            _ => self.get(name),
        }
    }

    /// The names [`Settings::get`] knows, sorted.
    pub fn names() -> impl Iterator<Item = &'static str> {
        let s = Settings::default();
        NIX_SETTINGS.iter().map(|(n, _)| *n).filter(move |n| s.get(n).is_some())
    }

    /// Applies the settings in `text`; `base` resolves relative includes.
    pub fn apply_text(&mut self, text: &str, base: &Path) -> Result<()> {
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut toks = line.split_whitespace();
            if let Some(kw @ ("include" | "!include")) = toks.next() {
                let f = toks.next().ok_or_else(|| format!("syntax error in configuration line '{raw}'"))?;
                let p = base.join(f);
                match fs::read_to_string(&p) {
                    Ok(t) => self.apply_text(&t, p.parent().unwrap_or(base))?,
                    Err(_) if kw == "!include" => {}
                    Err(e) => return Err(format!("reading '{}': {e}", p.display())),
                }
                continue;
            }
            let (k, v) = line.split_once('=').ok_or_else(|| format!("illegal configuration line '{raw}'"))?;
            self.set(k.trim(), v.trim())?;
        }
        Ok(())
    }

    /// Applies the file at `path` if it exists.
    pub fn apply_file(&mut self, path: &Path) -> Result<()> {
        match fs::read_to_string(path) {
            Ok(t) => self.apply_text(&t, path.parent().unwrap_or(Path::new("/"))),
            Err(_) => Ok(()),
        }
    }

    /// The defaults, overridden by `files` in order and then by `texts`.
    pub fn load_from(files: &[PathBuf], texts: &[String]) -> Result<Settings> {
        let mut s = Settings::default();
        for f in files {
            s.apply_file(f)?;
        }
        for t in texts {
            s.apply_text(t, Path::new("/"))?;
        }
        Ok(s)
    }

    /// The settings from the configuration files and the environment, in
    /// the order the module documentation lists.
    pub fn load() -> Result<Settings> {
        let texts: Vec<String> = ["CRANIX_CONFIG", "NIX_CONFIG"].iter().filter_map(|v| std::env::var(v).ok()).collect();
        Settings::load_from(&config_files(), &texts)
    }

    /// The build options these settings describe.
    pub fn build_options(&self) -> BuildOptions {
        let mut b = self.build.clone();
        b.upload = crate::upload::UploadTarget::from_settings(self);
        b
    }
}

/// `$NIX_CONF_DIR`, by default `/etc/nix`.
pub fn nix_conf_dir() -> PathBuf {
    PathBuf::from(std::env::var("NIX_CONF_DIR").unwrap_or_else(|_| "/etc/nix".into()))
}

fn config_home() -> PathBuf {
    match std::env::var("XDG_CONFIG_HOME") {
        Ok(d) if !d.is_empty() => PathBuf::from(d),
        _ => PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/".into())).join(".config"),
    }
}

/// The configuration files, lowest precedence first.
pub fn config_files() -> Vec<PathBuf> {
    let mut files = vec![nix_conf_dir().join("nix.conf")];
    // Nix applies the user files in reverse, so the first one wins.
    let user: Vec<PathBuf> = match std::env::var("NIX_USER_CONF_FILES") {
        Ok(v) => v.split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect(),
        Err(_) => {
            let dirs = std::env::var("XDG_CONFIG_DIRS").unwrap_or_else(|_| "/etc/xdg".into());
            std::iter::once(config_home())
                .chain(dirs.split(':').filter(|s| !s.is_empty()).map(PathBuf::from))
                .map(|d| d.join("nix/nix.conf"))
                .collect()
        }
    };
    files.extend(user.into_iter().rev());
    files.push(config_file());
    files
}

/// `$XDG_CONFIG_HOME/cranix`, by default `~/.config/cranix`.
pub fn config_dir() -> PathBuf {
    config_home().join("cranix")
}

pub fn config_file() -> PathBuf {
    config_dir().join("cranix.conf")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxMode;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cranix-conf-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_nix_conf_syntax() {
        let dir = scratch("syntax");
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
        s.apply_text("narinfo-cache-negative-ttl = 0\ndownload-attempts = 2\nnetrc-file = /n\n", &dir).unwrap();
        assert_eq!((s.narinfo_cache_negative_ttl, s.download_attempts, s.netrc_file.as_str()), (0, 2, "/n"));
        assert!(s.apply_text("narinfo-cache-positive-ttl = soon", &dir).is_err());
        assert!(s.apply_text("require-sigs = maybe", &dir).is_err());
        assert!(s.apply_text("include missing.conf", &dir).is_err());
        assert!(s.apply_text("no equals sign", &dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_value_feeds_every_subsystem() {
        let mut s = Settings::default();
        s.apply_text(
            "sandbox = relaxed\nextra-sandbox-paths = /x\ntimeout = 7\ntarball-ttl = 9\n\
             experimental-features = nix-command\nextra-experimental-features = ca-derivations\n\
             trusted-users = alice\nextra-trusted-users = @wheel\nbuilders = @/m\nsystem = x86_64-linux\n\
             auto-optimise-store = true\nbuild-users-group = nixbld\n",
            Path::new("/"),
        )
        .unwrap();
        let b = s.build_options();
        assert_eq!(b.sandbox, SandboxMode::Relaxed);
        assert!(b.sandbox_paths.ends_with(&["/x".to_string()]));
        assert_eq!((b.timeout, b.system.as_str()), (7, "x86_64-linux"));
        assert!(b.ca_derivations && !b.impure_derivations);
        assert_eq!(s.fetch.tarball_ttl, 9);
        assert_eq!(s.trusted_users, ["alice", "@wheel"]);
        assert_eq!(s.builders, "@/m");
        assert_eq!(s.get("experimental-features").unwrap(), "ca-derivations nix-command");
        assert_eq!(Settings::kind("sandbox"), Some(Kind::Bool));
        assert_eq!(Settings::kind("substituters"), Some(Kind::List));
        assert_eq!(Settings::kind("no-such-setting"), None);
    }

    #[test]
    fn substituters_are_listed_once() {
        let mut s = Settings::default();
        s.apply_text(
            "substituters = https://a.example/?priority=10 https://cache.nixos.org/ https://cache.nixos.org/
             extra-substituters = https://cache.nixos.org https://b.example https://b.example/
",
            Path::new("/"),
        )
        .unwrap();
        assert_eq!(s.substituters, ["https://a.example/?priority=10", "https://cache.nixos.org/", "https://b.example"]);
    }

    #[test]
    fn later_sources_win() {
        let dir = scratch("order");
        fs::write(dir.join("system.conf"), "timeout = 1\nmax-silent-time = 1\ntarball-ttl = 1\nsubstituters = file:///sys\n").unwrap();
        fs::write(dir.join("user.conf"), "max-silent-time = 2\ntarball-ttl = 2\nextra-substituters = file:///user\n").unwrap();
        fs::write(dir.join("cranix.conf"), "tarball-ttl = 3\ncores = 3\n").unwrap();
        let files = [dir.join("system.conf"), dir.join("user.conf"), dir.join("missing.conf"), dir.join("cranix.conf")];
        let texts = ["cores = 4\nkeep-failed = true".to_string(), "keep-failed = false".to_string()];
        let s = Settings::load_from(&files, &texts).unwrap();
        assert_eq!((s.build.timeout, s.build.max_silent_time, s.fetch.tarball_ttl, s.build.cores), (1, 2, 3, 4));
        assert!(!s.build.keep_failed);
        assert_eq!(s.substituters, ["file:///sys", "file:///user"]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
